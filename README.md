![badmoodle](https://user-images.githubusercontent.com/35109470/143145731-090d4f81-4a3e-4175-b2fc-95e9c4916906.png)
# badmoodle
Moodle community-based vulnerability scanner

## Description
badmoodle is an unofficial community-based vulnerability scanner for moodle that scans for canonical and non-canonical Moodle vulnerabilities.

badmoodle's purpose is to help penetration testers, bug hunters and security researchers find more vulnerabilities on moodle instances.

Since badmoodle is community-based, it will scan for two different kind of vulnerabilities:

* Official vulnerabilities: The canonical ones published in Moodle security advisory blog;

* Community vulnerabilities: The non-canonical ones that are not present in Moodle security advisory blog.

The community vulnerability scan can run in two modes:

* Check mode: Only checks if the host is vulnerable or not;

* Exploit mode: If the host is vulnerable, exploit the vulnerabilities.

If not specified, the scan will run in check mode.

## Installation
Installing badmoodle is very simple, it can be performed in just a few steps:

* Clone the repository:
  ```bash
  git clone https://github.com/cyberaz0r/badmoodle
  ```

* Dive into "badmoodle" directory:
  ```bash
  cd badmoodle
  ```

* Install requirements for Python:
  ```bash
  pip3 install -r requirements.txt
  ```

* Give execution permissions to "badmoodle.py":
  ```bash
  chmod +x badmoodle.py
  ```

* Run "badmoodle.py":
  ```bash
  ./badmoodle.py
  ```

If you see the badmoodle logo and help with no errors you are good to go :)

## Usage

Using badmoodle is also very simple. Once installed you can run it with the following options:

* `-h`, `--help`

  Show logo and help with options and their descriptions, then exit

* `-u TARGET_URL`, `--url TARGET_URL`

  Moodle target URL (required)

* `-a USERNAME:PASSWORD`, `--auth USERNAME:PASSWORD`

  Moodle username and password separated by ":" (default: none)

* `-p PROXY_ADDRESS:PORT`, `--proxy PROXY_ADDRESS:PORT`

  Proxy used for connecting to moodle (default: none)

* `-H HEADER`, `--header HEADER`

  Headers used for HTTP connections

* `-l LEVEL`, `--level LEVEL`

  Level of tests to perform (default: 1):

  * Level 1: simple version check by parsing 404 page (MAJOR.MINOR)

  * Level 2: simple and specific version check by parsing 404 page and confronting pages hash (MAJOR.MINOR.PATCH)

  * Level 3: all of the above and plugin/themes enumeration

* `-v VERBOSITY`, `--verbose VERBOSITY`

  Verbosity level (default: 1)

* `-r`, `--random-agent`

  Use a random User Agent for HTTP requests (default: Chrome Win10)

* `-e`, `--exploit`

  Enable exploit mode (default: check mode)

* `-s`, `--scrape`

  Scraping mode: scrape all the pages from moodle and save the result in a JSON file (default: disabled)

* `-U`, `--update`

  Update badmoodle vulnerability database by scraping Moodle security advisory blog and retrieving new modules from GitHub repository


## Community Vulnerability Modules

Since Moodle is so strict about their vulnerability disclosure program, a lot of vulnerabilities that security researchers discover and share with Moodle end up rejected or put on hold forever.

All these vulnerabilities will never see the light, they will be left unfixed and forgotten by Moodle... but not by badmoodle ;)

You can just add a community vulnerability module with your exploit code and badmoodle will execute it for you :)

badmoodle is modular, which means that you can add a community vulnerability module that will be executed by badmoodle without interfering with the rest of the code.

Adding a community vulnerability module is very simple: just create a .py file inside the "vulns" directory and badmoodle will execute it alongside the other modules.

badmoodle needs only 2 requirements to make your module work:

* It must have a boolean variable `enabled` and a string variable `name`.

  The `enabled` boolean variable is used to determine wether badmoodle should run the module or not. This allows to enable or disable modules by simply editing this variable without removing it from the "vulns" folder.
  
  The `name` string variable is just the vulnerability name, that will be printed in the core.

* It must have the functions `check(args, sess, version)` and `exploit(args, sess, version)`
  
  These are the main functions of the module, the ones badmoodle will call in the core. Through these functions badmoodle will pass to the module the script arguments, the request session object of the script (useful for authenticated sessions) and moodle version. 
  
  The `check` function is a boolean function that only checks whether the host is vulnerable or not, the `exploit` function instead will exploit that vulnerability.
  
  If in check mode badmoodle will call only the `check` function to only determine whether the host is vulnerable or not, if in exploit mode badmoodle will also call the `exploit` function for exploiting the vulnerability.

You are also free to include all the logging and output functions you need by using `from utils.output import *`  for colored output functions and `from utils.logging import *` for logging functions.

There follows a template for a badmoodle community vulnerability module:

```python
'''
@Title:
MODULE_TITLE

@Author:
MODULE_AUTHOR

@Description:
MODULE_DESCRIPTION
'''

from utils.output import *
from utils.logging import *


name = 'VULNERABILITY_NAME'
enabled = True


def check(args, sess, version):
	#YOUR_CHECK_CODE_HERE
	#return True if the host is vulnerable, False otherwise


def exploit(args, sess, version):
	#YOUR_EXPLOIT_CODE_HERE


```

badmoodle comes with 2 community vulnerability modules built-in:

* A module for a Dashboard Stored XSS vulnerability

* A module for an Atto Editor Stored XSS vulnerability

## Contribute
If you wrote a community vulnerability module for badmoodle and want to share it with the community, you can contribute to the badmoodle project.

Pull requests with new community vulnerability modules are very welcome :)

Also, if you want to report a bug, feel free to open an issue or contact me via mail at cyberaz0r@protonmail.com

## To do
Currently these are the features that are planned to be implemented in badmoodle:
- [ ] Event logging
- [ ] More granular version check
- [ ] Multithreading mode (for instance for plugin/themes enumeration)
- [ ] Getting vulnerabilities from snyk.io
- [ ] Packaging (Makefile, PKGBUILD)
- [ ] Releases for debian-based and arch-based distribution (.deb and .tar.xz packages)

## Credits
badmoodle is coded by Michele 'cyberaz0r' Di Bonaventura.

A special thanks to Panfilo Salutari for the idea of the concept of the tool.

Thanks to moodlescan (https://github.com/inc0d3/moodlescan) for the specific version check technique and its version database.

## Changelog
Changelog is available [here](CHANGELOG.md)