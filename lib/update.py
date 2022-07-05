import os
import json
import requests

from re import match
from bs4 import BeautifulSoup

from utils.output import *


# suppress requests insecure warning
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# dictionary for retrieving every moodle plugin path from its type
plugin_paths = {
	'assignsubmission' : '/mod/assign/submission/',
	'calendartype' : '/calendar/type/',
	'gradereport' : '/grade/report/',
	'assignfeedback' : '/assign/feedback/',
	'booktool' : '/mod/book/tool/',
	'workshopallocation' : '/mod/workshop/allocation/',
	'portfolio' : '/portfolio/',
	'message' : '/message/output/',
	'qtype' : '/question/type/',
	'availability' : '/availability/condition/',
	'contenttype' : '/contentbank/contenttype/',
	'media' : '/media/player/',
	'tinymce' : '/lib/editor/tinymce/plugins/',
	'quiz' : '/mod/quiz/report/',
	'profilefield' : '/user/profile/field/',
	'theme' : '/theme/',
	'ltisource' : '/mod/lti/source/',
	'editor' : '/lib/editor/',
	'quizaccess' : '/mod/quiz/accessrule/',
	'local' : '/local/',
	'cachestore' : '/cache/stores/',
	'repository' : '/repository/',
	'format' : '/course/format/',
	'qbehaviour' : '/question/behaviour/',
	'tool' : '/admin/tool/',
	'workshopeval' : '/mod/workshop/eval/',
	'antivirus' : '/lib/antivirus/',
	'dataformat' : '/dataformat/',
	'auth' : '/auth/',
	'report' : '/report/',
	'enrol' : '/enrol/',
	'mod' : '/mod/',
	'search' : '/search/engine/',
	'plagiarism' : '/plagiarism/',
	'webservice' : '/webservice/',
	'gradingform' : '/grade/grading/form/',
	'scormreport' : '/mod/scorm/report/',
	'gradeexport' : '/grade/export/',
	'fileconverter' : '/files/converter/',
	'filter' : '/filter/',
	'qformat' : '/question/format/',
	'datafield' : '/mod/data/field/',
	'logstore' : '/admin/tool/log/store/',
	'atto' : '/lib/editor/atto/plugins/',
	'paygw' : '/payment/gateway/',
	'customfield' : '/customfield/field/',
	'block' : '/blocks/'
}

# get an element's text from a table in a Moodle security advisory article
def get_element_table(trs, elem):
	return [tr.find_all('td')[1].get_text() for tr in trs if elem in tr.find_all('td')[0].get_text().lower()][0]


# parse CVEs from a table in a Moodle security advisory article
def parse_cves(trs):
	try:
		cvelist = [x for x in get_element_table(trs, 'cve identifier').split() if match('CVE-[0-9]{4}-[0-9]{0,8}', x)]
	except IndexError:
		try:
			cvelist = [x for x in get_element_table(trs, 'issue no').split() if match('CVE-[0-9]{4}-[0-9]{0,8}', x)]
		except IndexError:
			cvelist = ['N/A']
	
	if not cvelist:
		return ['N/A']
	
	return cvelist


# parse affected versions from a Moodle security advisory article
def parse_versions(unparsed):
	res = []
	
	unparsed = ' '.join(unparsed.split())
	elmts = [x.split(', ') for x in unparsed.split('and')]
	elmts = [y.replace('+','').replace(' only','').split('(')[0].strip() for x in elmts for y in x]
	
	if (len(elmts) == 1 and elmts[0].lower().startswith('all')) or (len(elmts) == 2 and elmts[0] == 'all past' and elmts[1] == 'future versions'):
		return [{'from':'0.0.0', 'to':'1.10.0'}]
		
	elmts += [x[2] for x in elmts if len(x.split('to')) > 2]
	
	for i, el in enumerate(elmts):
		if ')' in el:
			continue
		
		if 'unsupported versions' in el:
			res.append({'from':'0.0.0', 'to':res[-1]['from']})
		
		elif 'to' in el:
			if len(el.split('to')) > 2:
				continue
			res.append({'from':el.split(' to ')[0].replace('x','0'), 'to':el.split(' to ')[1].replace('x','99')})
		
		elif '-' in el:
			if len(el.split('-')) > 2:
				continue
			res.append({'from':el.split('-')[0].replace('x','0'), 'to':el.split('-')[1].replace('x','99')})
		
		elif '<' in el:
			if '=' in el:
				res.append({'from':'0.0.0', 'to':el.split('<=')[1].lstrip().replace('x','99')})
			else:
				res.append({'from':'0.0.0', 'to':el.split('<')[1].lstrip().replace('x','99')})
		else:
			res.append({'from':el.replace('x','0'), 'to':el.replace('x','99')})
	
	return res


# function to check and update a JSON file
def update_json(name, data, filename):
	# check if JSON file is up to date
	if os.path.isfile(filename):
		before = json.load(open(filename))
		if before == data:
			print_success(name + ' is up to date')
			return 0

		# backup previous JSON file
		os.rename(filename, filename + '.old')
	else:
		before = []
	
	# write data to JSON file
	with open(filename, 'w') as jsonfile:
		json.dump(data, jsonfile, indent = 4)
	
	# return number of new entries on the updated JSON file
	return len(data) - len(before)


# update badmoodle official vulnerability database
def update_vulnerability_database(verbosity):
	print_status('Updating vulnerability database by scraping Moodle official security advisory blog')
	
	# getting pages and preparing vars
	url = 'https://moodle.org/security/index.php?o=3&p={}'
	npages = int(requests.get('https://moodle.org/security/').text.split('<li class="page-item disabled" data-page-number="')[1].split('"')[0])
	vulnerability_database = []
	
	if verbosity > 1:
		print_status('Scraping {} pages from Moodle security advisory blog'.format(npages))
	
	# browse Moodle security advisory blog page by page
	for i in range(npages):
		if verbosity > 2:
			print_info('Scraping page {} of Moodle security advisory blog'.format(i + 1))
		
		# retrieve articles from every page
		for advisory in BeautifulSoup(requests.get(url.format(i)).text, 'html.parser').find_all('article'):
			try:
				trs = advisory.find('table').find_all('tr')
			except AttributeError:
				continue
			
			# print(trs)
			# extract all vulnerabilities info from articles
			title = advisory.find('h3', class_='h4').get_text()
			cves = parse_cves(trs)
			try:
				severity = get_element_table(trs, 'severity/risk').strip()
			except IndexError:
				severity = get_element_table(trs, 'severity').strip()
			versions_affected = get_element_table(trs, 'versions affected').strip()
			versions = parse_versions(versions_affected)
			advisory_link = url.format(i) + '#' + advisory['id']
			
			# save vulnerability info into variable
			vulnerability_database.append(
				{
					'title' : title,
					'severity': severity,
					'cves' : cves,
					'versions' : versions,
					'versions_affected' : versions_affected,
					'link' : advisory_link
				}
			)
	
	# update JSON file
	new_entries = update_json('Vulnerability database', vulnerability_database, 'data/vulndb.json')
	
	if new_entries > 0:
		print_success('Vulnerability database successfully updated: {} new vulnerabilities added'.format(new_entries))
	
	if new_entries < 0:
		# something is wrong: maybe some vulnerabilities were removed from blog? or there are some parsing errors...
		raise Exception('JSON_ENTRIES_LESS_THAN_BEFORE')


# update badmoodle community vulnerability modules
def update_modules(verbosity):
	print_status('Retrieving new badmoodle community vulnerability modules from GitHub')
	
	# retrieve modules list using GitHub API
	try:
		modules_list = [x['url'] for x in json.loads(requests.get('https://api.github.com/repos/cyberaz0r/badmoodle/git/trees/main').text)['tree'] if x['path'] == 'vulns'][0]
		modules_list = [x['path'] for x in json.loads(requests.get(modules_list).text)['tree'] if x['path'].endswith('.py')]
	except:
		print_error('Update failed: error while retrieving online modules list\n')
		return False
	
	# check new modules
	already_existing_modules = [x for x in os.listdir('vulns') if x.endswith('.py')]
	new_modules = [x for x in modules_list if x not in already_existing_modules]
	
	if not new_modules:
		print_success('All new badmoodle community vulnerability modules are already installed\n')
		return True
	
	if verbosity > 1:
		print_info('Found {} new community vulnerability modules'.format(len(new_modules)))
	
	# download and install new modules
	for module in new_modules:
		if verbosity > 1:
			print_status('Installing new community vulnerability module "{}"'.format(module[:-3]))
		try:
			new_module_content = requests.get('https://raw.githubusercontent.com/cyberaz0r/badmoodle/master/vulns/{}'.format(module)).text	
			with open('vulns/{}'.format(module), 'w') as new_module:
				new_module.write(new_module_content)
		except:
			print_error('Update failed: error while installing module "{}"\n'.format(module))
			return False
		
		if verbosity > 1:
			print_success('Successfully installed new community vulnerability module "{}"'.format(module[:-3]))
	
	print_success('Update successful: {} new modules added\n'.format(len(new_modules)))
	return True


# update plugin and theme list
def update_plugin_list(verbosity):
	plugins = []
	i = 0
	
	print_status('Updating plugin and themes list by using moodle.org API')

	while True:
		if verbosity > 2:
			print_info('Retrieving plugin/themes list from moodle.org API (page {})'.format(i + 1))

		data = json.loads(
			requests.post(
				'https://moodle.org/lib/ajax/service.php',
				json = [{'index' : 0, 'methodname' : 'local_plugins_get_plugins_batch', 'args' : {'query' : '', 'batch' : i}}]
			).text
		)

		# loop until API results are empty
		if not data[0]['data']['grid']['plugins']:
			break
		
		# append results to list
		for plugin in data[0]['data']['grid']['plugins']:
			# append only plugins with known path
			if plugin['plugintype']['type'] in plugin_paths.keys():
				plugins.append(
					{
						'id' : plugin['id'],
						'type' : plugin['plugintype']['type'],
						'name' : plugin['name'],
						'description' : plugin['shortdescription'],
						'url' : plugin['url'],
						'path' : '{}{}/'.format(plugin_paths[plugin['plugintype']['type']], plugin['url'].replace('https://moodle.org/plugins/' + plugin['plugintype']['type'] + '_', ''))
					}
				)

		i += 1
	
	# update JSON file
	new_entries = update_json('Plugin list', plugins, 'data/plugins.json')
		
	if new_entries > 0:
		print_success('Plugin list successfully updated: {} new plugins added'.format(new_entries))
	
	if new_entries < 0:
		# something is wrong: maybe some plugins were removed? or there are some parsing errors...
		raise Exception('JSON_ENTRIES_LESS_THAN_BEFORE')