import requests

from json import dump
from time import sleep
from gc import collect
from threading import Thread
from bs4 import BeautifulSoup


# global vars
pages = []
base_url = ''
verbose = None
sess = None

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


# HTTP GET requests with exception handling
def get_req(url, attempts=0):
	if attempts == 3:
		print('[X] Request for "{}" failed three times in a row, skipping...'.format(url))
		return ''
	
	try:
		r = sess.get(url)
	except requests.exceptions.RequestException:
		print('[-] Request for "{}" failed, retrying in 5 secs...'.format(url))
		sleep(5)
		return get_req(url, attempts + 1)
	
	return r.text


# parse Moodle links from an HTML page
def scrape(parent_url):
	global pages, sess
	
	# avoid scraping off-scope/non-php links or accidentally logging out
	filename = parent_url.split('?', 1)[0]
	if filename.endswith('logout.php') or (filename != base_url and not filename.endswith('/') and not filename.endswith('.php')): return []
	
	if verbose > 1:
		print('[i] Scraper: scraping links from "{}"'.format(parent_url))
	
	# get page content
	content = get_req(parent_url)
	links = []
	
	# insert page url and content to dictionary
	pages.append({'url':parent_url, 'content':content})
	
	if not content:
		return links
	
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


# multi-threaded scraping of a Moodle website by following every link
def scraper(nthreads):
	global sess
	
	print('[*] Scraping Moodle on "{}"'.format(base_url))
	links = scrape(base_url)
	
	# extract links from pages content until there are none left
	while True:
		spool = []
		spool2 = []
		
		# using a spool variable to save scraping result from every thread and another one for feeding multithreaded functions
		for link in links:
			if len(spool2) < nthreads and len(links) != len(spool2) + 1:
				spool2.append(link)
				continue
			
			threads = [ThreadReturn(target = scrape, args = (x,)) for x in spool2]
			for thread in threads: thread.start()
			for thread in threads: spool += thread.join()
			
			spool2 = []
		
		# sorting links and removing duplicates
		spool = [x for x in spool]
		spool = list(dict.fromkeys(spool))
		spool = [x for x in spool if x not in [x['url'] for x in pages]]
		
		if not spool:
			break
		
		links = spool
		
		# clean memory
		del spool
		del spool2
		
		collect()
	print('[+] Moodle scraping complete')


# main function called by badmoodle
def scrape_moodle(args, session):
	global base_url, verbose, sess
	
	base_url = args.url
	verbose = args.verbose
	sess = session
	
	nthreads = input('[?] Insert number of threads or press Enter for default value (10): ')
	nthreads = (10 if not nthreads else int(nthreads))
	
	jsonfile = input('[?] Insert JSON file name in which scrape results will be saved: ')
	
	scraper(nthreads)
	
	with open(jsonfile, 'w') as outfile:
		dump(pages, outfile, indent = 4)
	print('[+] Saved scraping result to file "{}"'.format(jsonfile))
