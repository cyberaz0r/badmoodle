#!/usr/bin/env python3

from requests import *
import sys
import json


name = "Open Redirect in Bitnami Moodle's Apache"
enabled = True

found = False

def print_usage():
    s='''
Usage:
\t'''+sys.argv[0]+''' <URL/Domain/IP>  
Examples:
\t->  '''+sys.argv[0]+''' 192.168.161.178
\t->  '''+sys.argv[0]+''' mymoodle.domain.com
\t->  '''+sys.argv[0]+''' http://mymoodle.domain.com/
'''
    print(s)
    exit()

def argparser():
    if '-h' in sys.argv or '--help' in sys.argv:
        print_usage()
        exit()
    if len(sys.argv)!=2:
        print_usage()
        exit()

def exec(url,verbose):
    if 'http' not in url:
        url='http://'+url
    url+='/my/'
    try:
        headers = {'Host': 'google.com'}
        s=Session()
        r=s.get(url,headers=headers,allow_redirects=False)
        if verbose:
            print("\nHTTP "+str(r.status_code))
            for e in r.headers:
                if e=="Location":
                    print("\033[33;1m"+e+": "+r.headers[e]+"\033[0m")
                else:
                    print(e+": "+r.headers[e])
    
        if  'google.com' in r.headers["Location"]:    # if it's google.com, then it is vulnerable!
            if verbose:
                print("\n\033[32;1m-> Vulnerable!\033[0m\n")
            else:
                return True
        else:
            if verbose:
                print("\n\033[31;1m-> Not Vulnerable...\033[0m\n")
            else:
                return False
    except:
        print("\n\033[31;1m-> Some error occurred... check connection or argument\033[0m\n")
        exit()

def main(url):
    return exec(url,True)

def check(args, sess, version):
    return exec(args.url,False)

def exploit(args, sess, version):
    print("[-] An Host Header Open Redirect Vulnerability is exploitable only by conducting MITM attacks, skipping...")
    return exec(args.url,False)

if __name__ == '__main__':
    argparser()
    url = sys.argv[1]
    main(url)