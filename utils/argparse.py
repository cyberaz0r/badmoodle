import sys
import argparse

from utils.output import color


class CustomArgumentParser(argparse.ArgumentParser):
	def format_usage(self):
		custom_usage = super().format_usage()
		custom_usage = custom_usage.replace('usage: ', color.BOLD + 'Usage: ' + color.END)
		custom_usage = custom_usage.replace('optional arguments:', color.BOLD + 'Arguments:' + color.END)
		return custom_usage
	
	def format_help(self):
		custom_help = super().format_help()
		custom_help = custom_help.replace('usage: ', color.BOLD + 'Usage: ' + color.END)
		custom_help = custom_help.replace('optional arguments:', color.BOLD + 'Arguments:' + color.END)
		custom_help = custom_help.replace('show this help message and exit', 'Show this help message and exit')
		return custom_help
	
	def print_usage(self, file=sys.stdout):
		file.write(self.format_usage() + 'Use -h or --help for more details\n\n')


def get_parser():
	formatter = lambda prog: argparse.HelpFormatter(prog, max_help_position=40, width=100)
	parser = CustomArgumentParser(formatter_class=formatter, usage='\n{} [ARGUMENTS]\n'.format(sys.argv[0]))
	
	parser.add_argument('-u', '--url', help='Moodle target URL')
	parser.add_argument('-a', '--auth', help='Moodle username and password (separated by ":")')
	parser.add_argument('-p', '--proxy', help='Proxy used for connecting to moodle (ex: https://127.0.0.1:8080)')
	parser.add_argument('-H', '--header', help='Headers used for HTTP connections', action='append', nargs='?', dest='headers')
	parser.add_argument('-l', '--level', help='Level of tests to perform (default: 1)', type=int, default=1)
	parser.add_argument('-v', '--verbose', help='Verbosity level (default: 1)', type=int, default=1, dest='verbosity')
	parser.add_argument('-r', '--random-agent', help='Random User Agent (default: Chrome Win10)', action='store_const', const=True, dest='random_agent')
	parser.add_argument('-e', '--exploit', help='Enable exploit mode (default: check mode)', action='store_const', const=True)
	parser.add_argument('-s', '--scrape', help='Scraping mode: scrape all the pages from moodle and save the result in a JSON file (default: disabled)', action='store_const', const=True)
	parser.add_argument('-o', '--outfile', help='Output file to save scan results (in JSON format)')
	parser.add_argument('-m', '--list-modules', help='List all the community vulnerability modules', action='store_const', const=True, dest='list_modules')
	parser.add_argument('-U', '--update', help='Update badmoodle vulnerability database', action='store_const', const=True)
	
	return parser


def parse_args():
	return get_parser().parse_args()


def help():
	return get_parser().print_help()


def usage():
	return get_parser().print_usage()