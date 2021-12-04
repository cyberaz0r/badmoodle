#!/usr/bin/env python3

'''
@Title:
Open Redirect via Host Header in Bitnami Moodle's Apache

@Author:
Pierfrancesco Conti (https://github.com/PierfrancescoConti)

@Description:
In Moodle Bitnami instances, by default there's an Open Redirect via Host Header Vulnerability.
Sometimes Bitnami Moodle instances are deployed in production, and unless the system administrator manually fix this vulnerability, by default the host is vulnerable.
This module can also run indipendently by badmoodle, you can launch this script with just the target URL as argument and it will check for this vulnerability.
'''

import requests
import sys

name = "Open Redirect via Host Header in Bitnami Moodle's Apache"
enabled = True

def print_usage():
	s='''
Usage:
\t''' + sys.argv[0] + ''' <URL/Domain/IP>  
Examples:
\t->  ''' + sys.argv[0] + ''' 192.168.161.178
\t->  ''' + sys.argv[0] + ''' mymoodle.domain.com
\t->  ''' + sys.argv[0] + ''' http://mymoodle.domain.com/
'''
	print(s)
	exit()

def argparser():
	if '-h' in sys.argv or '--help' in sys.argv:
		print_usage()
	if len(sys.argv) != 2:
		print_usage()

def openred(url, independent):
	if 'http' not in url:
		url = 'http://' + url
	url += '/my/'
	
	try:
		r = requests.get(url, headers={'Host':'google.com'}, allow_redirects=False, verify=False)
		if independent:
			print('\nHTTP ' + str(r.status_code))
			for h in r.headers:
				if h == 'Location':
					print("\033[33;1m" + h + ': ' + r.headers[h] + '\033[0m')
				else:
					print(h + ': ' + r.headers[h])
		
		if r.status_code == 403:
			if independent:
				msg = '\n\033[31;1m-> Error while checking vulnerability: WAF Detected\033[0m\n'
			else:
				msg = '[-] Error while checking vulnerability "{}", WAF detected...'.format(name)
			print(msg)
			return False
		
		if 'google.com' in r.headers["Location"]:	# if it's google.com, then it is vulnerable!
			if independent:
				print("\n\033[32;1m-> Vulnerable!\033[0m\n")
			else:
				return True
		else:
			if independent:
				print("\n\033[31;1m-> Not Vulnerable...\033[0m\n")
			else:
				return False
	except:
		if independent:
			msg = '\n\033[31;1m-> Some error occurred... check connection or argument\033[0m\n'
		else:
			msg = '[-] An exception has been encountered while checking for the vulnerability "{}"'.format(name)
		print(msg)
		return False

def main(url):
	openred(url, True)

def check(args, sess, version):
	return openred(args.url, False)

def exploit(args, sess, version):
	print("[-] An Open Redirect via Host Header Vulnerability is exploitable only by conducting MITM attacks, skipping...")
	return

if __name__ == '__main__':
	argparser()
	url = sys.argv[1]
	main(url)
