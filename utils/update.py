import os
import json
import requests

from re import match
from bs4 import BeautifulSoup


# suppress requests insecure warning
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


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
	
	if len(elmts) == 1 and elmts[0].startswith('all'):
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
		
		elif '<' in el:
			if '=' in el:
				res.append({'from':'0.0.0', 'to':el.split('<=')[1].lstrip().replace('x','99')})
			else:
				res.append({'from':'0.0.0', 'to':el.split('<')[1].lstrip().replace('x','99')})
		else:
			res.append({'from':el.replace('x','0'), 'to':el.replace('x','99')})
	
	return res


# update badmoodle official vulnerability database
def update_vulnerability_database(verbose):
	print('[*] Updating badmoodle vulnerability database by scraping Moodle official security advisory blog')
	
	# getting pages and preparing vars
	url = 'https://moodle.org/security/index.php?o=3&p={}'
	npages = int(requests.get('https://moodle.org/security/').text.split('<li class="page-item disabled" data-page-number="')[1].split('"')[0])
	vulnerability_database = []
	
	if verbose > 1:
		print('[*] Scraping {} pages from Moodle security advisory blog'.format(npages))
	
	# browse Moodle security advisory blog page by page
	for i in range(npages - 1):
		if verbose > 2:
			print('[i] Scraping page {} of Moodle security advisory blog'.format(i + 1))
		
		# retrieve articles from every page
		for advisory in BeautifulSoup(requests.get(url.format(i)).text, 'html.parser').find_all('article'):
			try:
				trs = advisory.find('table').find_all('tr')
			except AttributeError:
				continue
			
			# extract all vulnerabilities info from articles
			title = advisory.find('h3', class_='h4').get_text()
			cves = parse_cves(trs)
			versions_affected = get_element_table(trs, 'versions affected').strip()
			versions = parse_versions(versions_affected)
			advisory_link = url.format(i) + '#' + advisory['id']
			
			# save vulnerability info into variable
			vulnerability_database.append(
				{
					'title' : title,
					'cves' : cves,
					'versions' : versions,
					'versions_affected' : versions_affected,
					'link' : advisory_link
				}
			)
	
	# check if vulnerability database is up to date
	before = len(json.load(open('data/vulndb.json')))
	after = len(vulnerability_database)
	
	if before == after:
		print('[+] Vulnerability database is up to date')
		return
	
	# backup previous vulnerability database
	if os.path.isfile('data/vulndb.json'):
		os.rename('data/vulndb.json', 'data/vulndb.json.old')
	
	# write vulnerabilities info to JSON file
	with open('data/vulndb.json', 'w') as vulndbfile:
		json.dump(vulnerability_database, vulndbfile, indent = 4)
	
	print('[+] Vulnerability database successfully updated: {} new vulnerabilities added'.format(after - before))


# update badmoodle community vulnerability modules
def update_modules(verbose):
	print('[*] Retrieving new badmoodle community vulnerability modules from GitHub')
	
	# retrieve modules list using GitHub API
	try:
		modules_list = [x['url'] for x in json.loads(requests.get('https://api.github.com/repos/cyberaz0r/badmoodle/git/trees/master').text)['tree'] if x['path'] == 'vulns'][0]
		modules_list = [x['path'] for x in json.loads(requests.get(modules_list).text)['tree'] if x['path'].endswith('.py')]
	except:
		print('[X] Update failed: error while retrieving online modules list\n')
		return False
	
	# check new modules
	already_existing_modules = [x for x in os.listdir('vulns') if x.endswith('.py')]
	new_modules = [x for x in modules_list if x not in already_existing_modules]
	
	if len(new_modules) == 0:
		print('[+] All new badmoodle community vulnerability modules are already installed\n')
		return True
	
	if verbose > 1:
		print('[i] Found {} new community vulnerability modules'.format(len(new_modules)))
	
	# download and install new modules
	for module in new_modules:
		if verbose > 1:
			print('[*] Installing new community vulnerability module "{}"'.format(module[:-3]))
		try:
			new_module_content = requests.get('https://raw.githubusercontent.com/cyberaz0r/badmoodle/master/vulns/{}'.format(module)).text	
			with open('vulns/{}'.format(module), 'w') as new_module:
				new_module.write(new_module_content)
		except:
			print('[X] Update failed: error while installing module "{}"\n'.format(module))
			return False
		
		if verbose > 1:
			print('[+] Successfully installed new community vulnerability module "{}"'.format(module[:-3]))
	
	print('[+] Update successful: {} new modules added\n'.format(len(new_modules)))
	return True
