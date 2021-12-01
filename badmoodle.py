#!/usr/bin/env python3


VERSION = '0.1'


import os
import sys
import requests

from random import choice
from argparse import ArgumentParser

from utils.update import *
from utils.version import *
from utils.scraper import *


def print_logo():
	print(
		'''
 ▄▄                  ╗▄                                ╗╗  ╗m         
 ██                  ▓█                                ╣╫ ▐╫Ñ         
 ██▄▄▄▄  ,▄▄▄▄▄  ╓▄▄▄██  ╔╗╗╗╗╗╗╗,  ╔@Φ╗╗  ,╗ΦΦ╗,  ╔╗Φ╗╣╫ ▐╫Ñ ,╗ΦK╗,  
 ██  ╙█▌▐█▌  ║█M║█▌  ██ ▐╫H ╟╫` ╬╫ ╣╫  ▐╫N ╫M  ╟╫H╟╫M  ╬╫ ▐╫Ñ ╬Ñ╗╗╬╫H 
 ██▄▄▄█Ñ ██▄▄██M╙██▄▄██ ▐╫H ╟╫  ╬╫ ╙╬N╗╬╣` ╝╬╗╗╬M ╙╬N╗╗╣╫ ▐╫Ñ ╚╬╗╓╗K^ 
 `` ``    `└ ``   `└ ``  `   `  ``    ,╓╗╗╗╗╗µ       `          ``    
                                     ╝╜"`   `╙╜M               [v{}]
    Moodle community-based vulnerability scanner
             by cyberaz0r
		'''.format(VERSION)
	)
	

def parse_args():
	parser = ArgumentParser(description='badmoodle - Moodle community-based vulnerability scanner')
	
	parser.add_argument('-u', '--url', help='Moodle target URL', required=True)
	parser.add_argument('-a', '--auth', help='Moodle username and password (separated by ":")')
	parser.add_argument('-p', '--proxy', help='Proxy used for connecting to moodle (ex: https://127.0.0.1:8080)')
	parser.add_argument('-H', '--header', help='Headers used for HTTP connections', action='append', nargs='?', dest='headers')
	parser.add_argument('-l', '--level', help='Level of tests to perform (default: 1)', type=int, default=1)
	parser.add_argument('-v', '--verbose', help='Verbosity level (default: 1)', type=int, default=1)
	parser.add_argument('-r', '--random-agent', help='Random User Agent (default: Chrome Win10)', action='store_const', const=True, dest='random_agent')
	parser.add_argument('-e', '--exploit', help='Enable exploit mode (default: check mode)', action='store_const', const=True)
	parser.add_argument('-s', '--scrape', help='Scraping mode: scrape all the pages from moodle and save the result in a JSON file (default: disabled)', action='store_const', const=True)
	parser.add_argument('-U', '--update', help='Update badmoodle vulnerability database', action='store_const', const=True)
	
	return parser.parse_args()


def load_modules(verbose):
	if verbose > 1:
		print('[*] Loading community vulnerability modules')
	
	modules = [__import__('vulns.{}'.format(x[:-3]), fromlist=['vulns']) for x in os.listdir('vulns') if x.endswith('.py')]
	
	if verbose > 2:
		print('\n'.join(['[i] Imported module for vulnerability "{}"'.format(x.name) for x in modules]))
	
	active_modules = [x for x in modules if x.enabled]
	
	if verbose > 1:
		print('[+] Loaded {} modules ({} active)\n'.format(len(modules), len(active_modules)))
	
	return active_modules


def authenticate(auth, url, sess):
	username, password = auth.split(':', 1)
	print('[*] Authenticating as "{}"'.format(username))
	
	# getting CSRF token and performing authentication request
	token = sess.get(url + '/login/index.php').text.split('<input type="hidden" name="logintoken" value="')[1].split('"')[0]
	auth_res = sess.post(url + '/login/index.php', data={'username':username, 'password':password, 'logintoken':token}, allow_redirects=False)
	
	# check authentication status
	if auth_res.status_code == 303 and auth_res.headers['Location'] == '{}/login/index.php'.format(url):
		return False
	
	return True


def check_official_vulnerabilities(version):
	print('\n[*] Checking for official vulnerabilities from vulnerability database')
	vulnerabilities_found = list_vulnerabilities(version[1:].split('-')[0])
	
	if not vulnerabilities_found:
		print('[-] No official vulnerabilities have been found in the scanned host')
		return
	
	for vuln in vulnerabilities_found:
		print('\n[+] Found Vulnerability')
		print(vuln['title'])
		print('CVEs: {}'.format(', '.join(vuln['cves'])))
		print('Versions affected: {}'.format(vuln['versions_affected']))
		print('Link to advisory: {}'.format(vuln['link']))


def check_community_vulnerabilities(modules, args, sess, version):
	print('\n[*] Checking for community vulnerabilities from vulnerability modules')
	vulnerabilities_found = []
	
	for module in modules:
		print('\n[+] Executing module for vulnerability "{}"{}'.format(module.name, ('' if args.verbose > 1 else '\n')))
		
		# checking vulnerability
		if args.verbose > 1:
			print('[*] Checking if host is vulnerable to "{}" vulnerability\n'.format(module.name))
		vulnerable = module.check(args, sess, version)
		
		if vulnerable:
			print('\n[+] Host vulnerable to "{}" vulnerablity!{}'.format(module.name, ('' if args.verbose > 1 else '\n')))
			vulnerabilities_found.append(module.name)
			
			# exploiting vulnerability
			if args.exploit:
				if args.verbose > 1:
					print('[+] Exploiting vulnerability "{}"\n'.format(module.name))
				module.exploit(args, sess, version)
		
		else:
			print('\n[-] Host not vulnerable to "{}" vulnerability'.format(module.name))
	
	print('\n[+] Scan completed\n')
	
	# print results
	if len(vulnerabilities_found) == 0:
		print('[-] No community vulnerabilities have been found in the scanned host')
	else:
		print('[+] The scanned host is vulnerable to:\n{}'.format('\n'.join(vulnerabilities_found)))


def main():
	# preliminary operations
	print_logo()
	args = parse_args()
	
	os.chdir(sys.path[0])
	sys.dont_write_bytecode = True
	requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
	
	# disclaimer
	print('Legal disclaimer:\nUsage of badmoodle for attacking targets without prior mutual consent is illegal. It is the end user\'s responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.\n')
	
	# update
	if args.update:
		try:
			update_vulnerability_database(args.verbose)
		except:
			print('[X] Update failed: error encountered while updating vulnerability database\n\n[X] Terminating badmoodle due to errors')
			exit(1)
		
		if not update_modules(args.verbose):
			print('\n[X] Terminating badmoodle due to errors')
			exit(1)
	
	# loading modules
	modules = load_modules(args.verbose)
	
	# initializing session
	sess = requests.Session()
	sess.verify = False
	
	# configuring user agent
	if args.random_agent:
		random_agent = choice(open('data/user-agents.txt').read().splitlines())
		if args.verbose > 1:
			print('[*] Setting User Agent to "{}"'.format(random_agent))
		sess.headers.update({'User-Agent':random_agent})
	else:
		sess.headers.update({'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36'})
	
	# configuring headers
	if args.headers is not None:
		try:
			sess.headers.update({x.split(': ')[0]:x.split(': ')[1] for x in args.headers})
		except IndexError:
			print('[X] Error: an invalid header has been provided\n\n[X] Terminating badmoodle due to errors')
			exit(1)
	
	# configuring proxy
	if args.proxy is not None:
		if args.verbose > 1:
			print('[*] Setting proxy to "{}"'.format(args.proxy))
		sess.proxies.update({'http':args.proxy, 'https':args.proxy})
	
	# fixing url
	if not args.url.startswith('http'):
		args.url = 'http://' + args.url
	
	print('[*] Starting scan in URL "{}"'.format(args.url))
	
	# checking url and retrieving version
	if args.verbose > 1:
		print('[*] Checking Moodle on URL "{}"'.format(args.url))
	
	version = check_moodle(args.url, sess)
	if not version:
		exit(1)
	
	print('[+] Moodle version: {}'.format(version))
	
	# retrieving specific version
	if args.level > 1:
		if args.verbose > 1:
			print('[*] Getting Moodle specific version')
		specific_version = get_moodle_specific_version(args.url, sess, args.verbose)
	
		if not specific_version:
			if args.verbose > 1:
				print('[-] Couldn\'t determine Moodle specific version')
		else:
			version = specific_version
			print('[+] Moodle specific version: {}'.format(version))
	
	# authentication
	if args.auth is not None:
		if not authenticate(args.auth, args.url, sess):
			print('[X] Error: authentication failed\n\n[X] Terminating badmoodle due to errors')
			exit(1)
	
	# scraping mode
	if args.scrape:
		scrape_moodle(args, sess)
	
	# scanning for vulnerabilities
	check_official_vulnerabilities(version)
	check_community_vulnerabilities(modules, args, sess, version)
	
	print('\n[+] Exiting from badmoodle')


if __name__ == '__main__':
	main()
