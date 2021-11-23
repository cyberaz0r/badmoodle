import os
import json
import requests

from json import load
from hashlib import md5


# suppress requests insecure warning
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def check_moodle(url, sess):
	# checking if valid url
	try:
		urlcheck = sess.get(url)
		urlcheck.raise_for_status()
	except requests.exceptions.RequestException:
		print('[X] Error: invalid URL\n\n[X] Terminating badmoodle due to errors')
		return False
	
	# checking if valid moodle instance and return version or False otherwise
	moodlecheck1 = sess.get(url + '/lib/editor/atto/lib.php')
	moodlecheck2 = sess.get(url + '/course/view.php')
	
	if moodlecheck1.status_code == 200 and not moodlecheck1.text and '/error/moodle/unspecifycourseid' in moodlecheck2.text:
		moodle_ver = moodlecheck2.text.split('/error/moodle/unspecifycourseid')[0].split('docs.moodle.org/')[-1].split('/')[0]
		return 'v{}.{}'.format(moodle_ver[0], moodle_ver[1:])
	
	print('[X] Error: the URL specified does not refer to a moodle instance\n\n[X] Terminating badmoodle due to errors')
	return False


# retrieve more granular moodle version by confronting file hashes of specific versions
def get_moodle_specific_version(url, sess, verbose):
	files = [
		'/admin/environment.xml', '/composer.lock', '/lib/upgrade.txt', '/privacy/export_files/general.js',
		'/composer.json', '/question/upgrade.txt', '/admin/tool/lp/tests/behat/course_competencies.feature'
	]
	
	try:
		versions = [{'ver':x.split(';')[0], 'hash':x.split(';')[1], 'file':x.split(';')[2]} for x in requests.get('https://raw.githubusercontent.com/inc0d3/moodlescan/master/data/version.txt').text.splitlines()]
	except:
		return False
	
	for f in files:
		filehash = md5(sess.get(url+f).text.encode('utf8')).hexdigest()
		version = [x for x in versions if filehash == x['hash']]
		
		if len(version) == 1:
			if verbose > 1:
				print('[+] Determined Moodle version through file "{}"'.format(version[0]['file']))
			return version[0]['ver']
	
	return False


# check if a version is in a range by confronting the concatenation of major, minor and patch (forcing 2 ciphers each) converted to integer
def check_in_range(ver, vuln_ver):
	ver = int(''.join([str(x).zfill(2) for x in ver.split('.')]))
	ver_from = int(''.join([str(x).zfill(2) for x in vuln_ver['from'].split('.')]))
	ver_to = int(''.join([str(x).zfill(2) for x in vuln_ver['to'].split('.')]))
	return (ver >= ver_from and ver <= ver_to)


# retrieve all the vulnerabilities that affect a specific version
def list_vulnerabilities(ver):
	if len(ver.split('.')) < 3:
		ver += '.0'
	
	vulnerabilities_found = []
	vulnerability_database = load(open('data/vulndb.json'))
	
	for vuln in vulnerability_database:
		for vuln_ver in vuln['versions']:
			if check_in_range(ver, vuln_ver):
				vulnerabilities_found.append(vuln)
				break
	
	return vulnerabilities_found
