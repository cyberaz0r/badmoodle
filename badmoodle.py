#!/usr/bin/env python3


VERSION = '0.2'


import os
import sys
import json
import requests

from random import choice

# avoid creating __pycache__ directories before importing local files
sys.dont_write_bytecode = True

from utils.output import *
from utils.logging import *
from utils.argparse import *

from lib.update import *
from lib.version import *
from lib.scraper import *

def update(verbosity):
	print_status('Updating badmoodle')

	# vulnerability database
	try:
		update_vulnerability_database(verbosity)
	except Exception as e:
		print_error('Update failed: error encountered while updating vulnerability database')

		if 'JSON_ENTRIES_LESS_THAN_BEFORE' in repr(e):
			print(color.RED + 'The number of entries in current vulnerability database is less than the previous one\n(maybe some vulnerabilities were removed or there were parsing errors...)' + color.END)
		else:
			print_info('Details of the error are reported in "{}"'.format(exception_logfile()))
		
		print_error('Terminating badmoodle due to errors', True)
		exit(1)
	
	# plugin list
	try:
		update_plugin_list(verbosity)
	except Exception as e:
		print_error('Update failed: error encountered while updating plugin list')

		if 'JSON_ENTRIES_LESS_THAN_BEFORE' in repr(e):
			print(color.RED + 'The number of entries in current plugin list is less than the previous one\n(maybe some plugins were removed or there were parsing errors...)' + color.END)
		else:
			print_info('Details of the error are reported in "{}"'.format(exception_logfile(e)))
		
		print_error('Terminating badmoodle due to errors', True)
		exit(1)
	
	# vulnerability modules
	if not update_modules(verbosity):
		print_error('Terminating badmoodle due to errors', True)
		exit(1)
	
	print_success('Successfully updated badmoodle')


def list_modules():
	print_info('Printing list of modules\n')

	modules = [__import__('vulns.{}'.format(x[:-3]), fromlist=['vulns']) for x in os.listdir('vulns') if x.endswith('.py')]
	offset = max([len(x.name) for x in modules]) + 4

	print('{}MODULE NAME{}ENABLED{}'.format(color.BOLD, ' ' * (offset - 11), color.END))
	for module in modules:
		print('{}{}{}'.format(module.name, ' ' * (offset - len(module.name)), module.enabled))
	
	print('\n')

def load_modules(verbosity):
	if verbosity > 1:
		print_status('Loading community vulnerability modules')
	
	modules = [__import__('vulns.{}'.format(x[:-3]), fromlist=['vulns']) for x in os.listdir('vulns') if x.endswith('.py')]
	
	if verbosity > 2:
		for mod in modules:
			print_info('Imported module for vulnerability "{}"'.format(mod.name))
	
	active_modules = [x for x in modules if x.enabled]
	
	if verbosity > 1:
		print_success('Loaded {} modules ({} active)\n'.format(len(modules), len(active_modules)))
	
	return active_modules


def list_loaded_components(nmodules):
	return [
		'{} plugins and themes loaded'.format(len(json.load(open('data/plugins.json')))),
		'{} official vulnerabilities loaded'.format(len(json.load(open('data/vulndb.json')))),
		'{} community vulnerabilities loaded'.format(nmodules)
	]


def authenticate(auth, url, sess):
	username, password = auth.split(':', 1)
	print_status('Authenticating as "{}"'.format(username))
	
	# getting CSRF token and performing authentication request
	token = sess.get(url + '/login/index.php').text.split('<input type="hidden" name="logintoken" value="')[1].split('"')[0]
	auth_res = sess.post(url + '/login/index.php', data={'username':username, 'password':password, 'logintoken':token}, allow_redirects=False)
	
	# check authentication status
	if auth_res.status_code == 303 and auth_res.headers['Location'] == '{}/login/index.php'.format(url):
		return False
	
	print_success('Authentication successful')
	return True


def enumerate_plugins(verbosity, url, sess):
	plugins = json.load(open('data/plugins.json'))
	plugins_found = []

	print_status('Enumerating moodle plugins and themes')

	for plugin in plugins:
		if verbosity > 3:
			print_info('Trying plugin/theme "{}" (path "{}")'.format(plugin['name'], plugin['path']))
		
		for possible_plugin_filename in ['', 'version.php', 'README.md', 'LICENSE.txt']:
			if sess.get('{}{}{}'.format(url, plugin['path'], possible_plugin_filename)).status_code != 404:
				print_success('Found ' + ('theme' if plugin['type'] == 'theme' else 'plugin'), True)
				print('Name: {}'.format(plugin['name']))
				print('Type: {}'.format(plugin['type']))
				print('Description: {}'.format(plugin['description']))
				print('URL: {}'.format(plugin['url']))
				print('Found from: {}'.format(url + plugin['path'] + possible_plugin_filename))
				plugins_found.append(plugin)
				break
	
	if not plugins_found:
		print_warning('No plugins or themes found')
	
	return plugins_found


def check_official_vulnerabilities(version):
	print_status('Checking for official vulnerabilities from vulnerability database', True)
	vulnerabilities_found = list_vulnerabilities(version[1:].split('-')[0])
	
	if not vulnerabilities_found:
		print_warning('No official vulnerabilities have been found in the scanned host')
		return False
	
	for vuln in vulnerabilities_found:
		print_success('Found Vulnerability', True)
		print(
			color.BOLD + vuln['title'] + color.END + '\n' +
			color.UNDERLINE + 'CVEs:' + color.END + ' ' + ', '.join(vuln['cves']) + '\n' +
			color.UNDERLINE + 'Severity:' + color.END + ' ' + vuln['severity'] + '\n' +
			color.UNDERLINE + 'Versions affected:' + color.END + ' ' + vuln['versions_affected'] + '\n' +
			color.UNDERLINE + 'Link to advisory:' + color.END + ' ' + vuln['link'],
		)
	
	return vulnerabilities_found


def check_community_vulnerabilities(modules, args, sess, version):
	print_status('Checking for community vulnerabilities from vulnerability modules', True)
	vulnerabilities_found = []
	
	for module in modules:
		print_success('Executing module for vulnerability "{}"{}'.format(module.name, ('' if args.verbosity > 1 else '\n')), True)
		
		# checking vulnerability
		if args.verbosity > 1:
			print_status('Checking if host is vulnerable to "{}" vulnerability\n'.format(module.name))
		vulnerable = module.check(args, sess, version)
		
		if vulnerable:
			print_success('Host vulnerable to "{}" vulnerablity!{}'.format(module.name, ('' if args.verbosity > 1 else '\n')), True)
			vulnerabilities_found.append(module.name)
			
			# exploiting vulnerability
			if args.exploit:
				if args.verbosity > 1:
					print_success('Exploiting vulnerability "{}"\n'.format(module.name))
				module.exploit(args, sess, version)
		
		else:
			print_warning('Host not vulnerable to "{}" vulnerability'.format(module.name), True)
	
	print_success('Scan completed\n', True)
	
	# print and return results
	if not vulnerabilities_found:
		print_warning('No community vulnerabilities have been found in the scanned host')
		return False
	
	print_success('The scanned host is vulnerable to:')
	for vuln in vulnerabilities_found:
		print(color.BOLD + vuln + color.END)
	
	return vulnerabilities_found


def save_outfile(url, version, plugins, official_vulnerabilities, community_vulnerabilities, filename):
	results = {
		'url' : url,
		'version' : version,
		'plugins' : plugins,
		'official_vulnerabilities' : official_vulnerabilities,
		'community_vulnerabilities' : community_vulnerabilities
	}
	
	with open(filename, 'w') as resfile:
		json.dump(results, resfile, indent=4)


def main():
	# preliminary operations
	print_logo(VERSION)
	args = parse_args()
	
	os.chdir(sys.path[0])
	requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
	
	# disclaimer
	print_disclaimer()
	
	# update
	if args.update:
		update(args.verbosity)
	
	# list modules
	if args.list_modules:
		try:
			list_modules()
		except Exception as e:
			print_error('An error occurred while retrieving modules')
			print_info('Details of the error are reported in "{}"'.format(exception_logfile(e)))
			print_error('Terminating badmoodle due to errors', True)
			exit(1)
	
	# check if provided url
	if not args.url:
		if args.update or args.list_modules:
			exit(0)
		else:
			print_error('Error: you must specify URL to scan\n')
			usage()
			exit(1)
	
	# loading modules
	try:
		modules = load_modules(args.verbosity)
	except Exception as e:
		print_error('An error occurred while loading modules')
		print_info('Details of the error are reported in "{}"'.format(exception_logfile(e)))
		print_error('Terminating badmoodle due to errors', True)
		exit(1)

	if args.verbosity > 1:
		print_success('badmoodle is ready:')
		print('\n'.join(['{}{}{}'.format(color.BOLD, x, color.END) for x in list_loaded_components(len(modules))]) + '\n')
	
	# initializing session
	sess = requests.Session()
	sess.verify = False
	
	# configuring user agent
	if args.random_agent:
		random_agent = choice(open('data/user-agents.txt').read().splitlines())
		if args.verbosity > 1:
			print_status('Setting User Agent to "{}"'.format(random_agent))
		sess.headers.update({'User-Agent':random_agent})
	else:
		sess.headers.update({'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36'})
	
	# configuring headers
	if args.headers is not None:
		try:
			sess.headers.update({x.split(': ')[0]:x.split(': ')[1] for x in args.headers})
		except IndexError:
			print_error('Error: an invalid header has been provided')
			print_error('Terminating badmoodle due to errors', True)
			exit(1)
	
	# configuring proxy
	if args.proxy is not None:
		if args.verbosity > 1:
			print_status('Setting proxy to "{}"'.format(args.proxy))
		sess.proxies.update({'http':args.proxy, 'https':args.proxy})
	
	# fixing url
	if not args.url.startswith('http'):
		args.url = 'http://' + args.url
	
	print_status('Starting scan in URL "{}"'.format(args.url))
	
	# checking url and retrieving version
	if args.verbosity > 1:
		print_status('Checking Moodle on URL "{}"'.format(args.url))
	
	version = check_moodle(args.url, sess)
	if not version:
		exit(1)
	
	print_success('Moodle version: {}'.format(version))
	
	# retrieving specific version
	if args.level > 1:
		if args.verbosity > 1:
			print_status('Getting Moodle specific version')
		specific_version = get_moodle_specific_version(args.url, sess, args.verbosity)
	
		if not specific_version:
			if args.verbosity > 1:
				print_warning('Couldn\'t determine Moodle specific version')
		else:
			version = specific_version
			print_success('Moodle specific version: {}'.format(version))
	
	# authentication
	if args.auth is not None:
		if not authenticate(args.auth, args.url, sess):
			print_error('Error: authentication failed')
			print_error('Terminating badmoodle due to errors', True)
			exit(1)
	
	# plugins and themes enumeration
	if args.level > 2:
		plugins = enumerate_plugins(args.verbosity, args.url, sess)
	else:
		plugins = []

	# scraping mode
	if args.scrape:
		scrape_moodle(args, sess)
	
	# scanning for vulnerabilities
	official_vulnerabilities = check_official_vulnerabilities(version)
	community_vulnerabilities = check_community_vulnerabilities(modules, args, sess, version)

	# save scan results to output file (if provided)
	if args.outfile is not None:
		save_outfile(args.url, version, plugins, official_vulnerabilities, community_vulnerabilities, args.outfile)
		print_success('Saved scan results to "{}"'.format(args.outfile), True)
	
	print_success('Exiting from badmoodle', True)


if __name__ == '__main__':
	main()
