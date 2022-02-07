class color:
	GREEN = '\033[92m'
	BLUE = '\033[94m'
	ORANGE = '\033[38:5:130m'
	YELLOW = '\033[93m'
	RED = '\033[91m'
	CYAN = '\033[96m'
	MAGENTA = '\033[95m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	END = '\033[0m'


def print_logo(version):
	print(
		'''{BOLD}
 {RED}▄▄                  ╗▄ {ORANGE}                               ╗╗  ╗m         
 {RED}██                  ▓█ {ORANGE}                               ╣╫ ▐╫Ñ         
 {RED}██▄▄▄▄  ,▄▄▄▄▄  ╓▄▄▄██ {ORANGE} ╔╗╗╗╗╗╗╗,  ╔@Φ╗╗  ,╗ΦΦ╗,  ╔╗Φ╗╣╫ ▐╫Ñ ,╗ΦK╗,  
 {RED}██  ╙█▌▐█▌  ║█M║█▌  ██ {ORANGE}▐╫H ╟╫` ╬╫ ╣╫  ▐╫N ╫M  ╟╫H╟╫M  ╬╫ ▐╫Ñ ╬Ñ╗╗╬╫H 
 {RED}██▄▄▄█Ñ ██▄▄██M╙██▄▄██ {ORANGE}▐╫H ╟╫  ╬╫ ╙╬N╗╬╣` ╝╬╗╗╬M ╙╬N╗╗╣╫ ▐╫Ñ ╚╬╗╓╗K^ 
 {RED}`` ``    `└ ``   `└ `` {ORANGE} `   `  ``    ,╓╗╗╗╗╗µ       `          ``    
 {RED}                       {ORANGE}             ╝╜"`   `╙╜M              {MAGENTA} [v{VERSION}] {END}{BOLD}
    Moodle community-based vulnerability scanner
             by cyberaz0r
		{END}'''.format(VERSION=version, RED=color.RED, ORANGE=color.ORANGE, MAGENTA=color.MAGENTA, BOLD=color.BOLD, END=color.END)
	)

def print_disclaimer():
	print(color.BOLD + color.UNDERLINE + 'Legal disclaimer' + color.END)
	print('Usage of badmoodle for attacking targets without prior mutual consent is illegal.')
	print('It is the end user\'s responsibility to obey all applicable local, state and federal laws.')
	print('Developers assume no liability and are not responsible for any misuse or damage caused by this program.\n')

def print_success(text, newline=False):
	print(('\n' if newline else '') + color.BOLD + color.GREEN + '[+] ' + color.END + color.GREEN + text + color.END)


def print_status(text, newline=False):
	print(('\n' if newline else '') + color.BOLD + color.BLUE + '[*] ' + color.END + color.BLUE + text + color.END)


def print_info(text, newline=False):
	print(('\n' if newline else '') + color.BOLD + color.CYAN + '[i] ' + color.END + color.CYAN + text + color.END)


def print_warning(text, newline=False):
	print(('\n' if newline else '') + color.BOLD + color.YELLOW + '[-] ' + color.END + color.YELLOW + text + color.END)


def print_error(text, newline=False):
	print(('\n' if newline else '') + color.BOLD + color.RED + '[X] ' + color.END + color.RED + text + color.END)