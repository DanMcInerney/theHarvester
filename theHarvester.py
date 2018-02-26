#!/usr/bin/env python

import string
import httplib
import sys
import os
from socket import *
import re
import getopt

try:
    import requests
except:
    print "Request library not found, please install it before proceeding\n"
    sys.exit()

from discovery import *
from lib import htmlExport
from lib import hostchecker

def usage():

    comm = os.path.basename(sys.argv[0])

    if os.path.dirname(sys.argv[0]) == os.getcwd():
        comm = "./" + comm

    print "Usage: theharvester options \n"
    print "       -d: Domain to search or company name"
    print """       -b: data source: baidu, bing, bingapi, dogpile,google, googleCSE,
                        googleplus, google-profiles, linkedin, pgp, twitter, vhost, 
                        yahoo, all\n"""
    print "       -s: Start in result number X (default: 0)"
    print "       -v: Verify host name via dns resolution and search for virtual hosts"
    print "       -f: Save the results into an HTML and XML file (both)"
    print "       -n: Perform a DNS reverse query on all ranges discovered"
    print "       -c: Perform a DNS brute force for the domain name"
    print "       -t: Perform a DNS TLD expansion discovery"
    print "       -e: Use this DNS server"
    print "       -l: Limit the number of results to work with(bing goes from 50 to 50 results,"
    print "            google 100 to 100, and pgp doesn't use this option)"
    print "       -h: use SHODAN database to query discovered hosts"
    print "\nExamples:"
    print "        " + comm + " -d microsoft.com -l 500 -b google -h myresults.html"
    print "        " + comm + " -d microsoft.com -b pgp"
    print "        " + comm + " -d microsoft -l 200 -b linkedin"
    print "        " + comm + " -d apple.com -b googleCSE -l 500 -s 300\n"


def start(argv):
    if len(sys.argv) < 4:
        usage()
        sys.exit()
    try:
        opts, args = getopt.getopt(argv, "l:d:b:s:vf:nhcte:")
    except getopt.GetoptError:
        usage()
        sys.exit()
    start = 0
    host_ip = []
    filename = ""
    bingapi = "yes"
    dnslookup = False
    dnsbrute = False
    dnstld = False
    shodan = False
    vhost = []
    virtual = False
    limit = 100
    dnsserver = ""
    for opt, arg in opts:
        if opt == '-l':
            limit = int(arg)
        elif opt == '-d':
            word = arg
        elif opt == '-s':
            start = int(arg)
        elif opt == '-v':
            virtual = "basic"
        elif opt == '-f':
            filename = arg
        elif opt == '-n':
            dnslookup = True
        elif opt == '-c':
            dnsbrute = True
        elif opt == '-h':
            shodan = True
        elif opt == '-e':
            dnsserver = arg
        elif opt == '-t':
            dnstld = True
        elif opt == '-b':
            engine = arg
            if engine not in ("baidu", "bing", "crtsh","bingapi","dogpile", "google", "googleCSE","virustotal", "googleplus", "google-profiles","linkedin", "pgp", "twitter", "vhost", "yahoo","netcraft","all"):
                usage()
                print "Invalid search engine, try with: baidu, bing, bingapi,crtsh, dogpile, google, googleCSE, virustotal, netcraft, googleplus, google-profiles, linkedin, pgp, twitter, vhost, yahoo, all"
                sys.exit()
            else:
                pass
    if engine == "google":
        print "[-] Searching in Google:"
        search = googlesearch.search_google(word, limit, start)
        search.process()
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()
    
    if engine == "netcraft":
        print "[-] Searching in Netcraft:"
        search = netcraft.search_netcraft(word)
        search.process()
        all_hosts = search.get_hostnames()
        print "\n[+] Subdomains found:\n"
        for x in all_hosts:
                print x
        sys.exit()
        
    if engine == "virustotal":
        print "[-] Searching in Virustotal:"
        search = virustotal.search_virustotal(word)
        search.process()
        all_hosts = search.get_hostnames()
        print "\n[+] Subdomains found:\n"
        for x in all_hosts:
                print x
        sys.exit()

    if engine == "crtsh":
        print "[-] Searching in CRT.sh:"
        search = crtsh.search_crtsh(word)
        search.process()
        all_hosts = search.get_hostnames()
        print "\n[+] Subdomains found:\n" 
        for x in all_hosts:
                print x
        sys.exit()

    if engine == "googleCSE":
        print "[-] Searching in Google Custom Search:"
        search = googleCSE.search_googleCSE(word, limit, start)
        search.process()
        search.store_results()
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    elif engine == "bing" or engine == "bingapi":
        print "[-] Searching in Bing:"
        search = bingsearch.search_bing(word, limit, start)
        if engine == "bingapi":
            bingapi = "yes"
        else:
            bingapi = "no"
        search.process(bingapi)
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    elif engine == "dogpile":
        print "[-] Searching in Dogpilesearch.."
        search = dogpilesearch.search_dogpile(word, limit)
        search.process()
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    elif engine == "pgp":
        print "[-] Searching in PGP key server.."
        search = pgpsearch.search_pgp(word)
        search.process()
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    elif engine == "yahoo":
        print "[-] Searching in Yahoo.."
        search = yahoosearch.search_yahoo(word, limit)
        search.process()
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    elif engine == "baidu":
        print "[-] Searching in Baidu.."
        search = baidusearch.search_baidu(word, limit)
        search.process()
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    elif engine == "googleplus":
        print "[-] Searching in Google+ .."
        search = googleplussearch.search_googleplus(word, limit)
        search.process()
        people = search.get_people()
        print "Users from Google+:"
       	print "===================="
       	for user in people:
            print user
        sys.exit()

    elif engine == "twitter":
        print "[-] Searching in Twitter .."
        search = twittersearch.search_twitter(word, limit)
        search.process()
        people = search.get_people()
        print "Users from Twitter:"
       	print "-------------------"
       	for user in people:
            print user
        sys.exit()

    elif engine == "linkedin":
        print "[-] Searching in Linkedin.."
        search = linkedinsearch.search_linkedin(word, limit)
        search.process()
        people = search.get_people()
        print "Users from Linkedin:"
       	print "-------------------"
       	for user in people:
            print user
        sys.exit()
    elif engine == "google-profiles":
        print "[-] Searching in Google profiles.."
        search = googlesearch.search_google(word, limit, start)
        search.process_profiles()
        people = search.get_profiles()
        print "Users from Google profiles:"
        print "---------------------------"
        for users in people:
            print users
        sys.exit()
    elif engine == "all":
        print "Full harvest.."
        all_emails = []
        all_hosts = []
        virtual = "basic"
        
        print "[-] Searching in Google.."
        search = googlesearch.search_google(word, limit, start)
        search.process()
        emails = search.get_emails()
        hosts = search.get_hostnames()
        all_emails.extend(emails)
        all_hosts.extend(hosts)
        
        print "[-] Searching in PGP Key server.."
        search = pgpsearch.search_pgp(word)
        search.process()
        emails = search.get_emails()
        hosts = search.get_hostnames()
        all_hosts.extend(hosts)
        all_emails.extend(emails)
        
        print "[-] Searching in Netcraft server.."
        search = netcraft.search_netcraft(word)
        search.process()
        hosts = search.get_hostnames()
        all_hosts.extend(hosts)
       
        print "[-] Searching in CRTSH server.."
        search = crtsh.search_crtsh(word)
        search.process()
        hosts = search.get_hostnames()
        all_hosts.extend(hosts)

        print "[-] Searching in Virustotal server.."
        search = virustotal.search_virustotal(word)
        search.process()
        hosts = search.get_hostnames()
        all_hosts.extend(hosts)
        
        print "[-] Searching in Bing.."
        bingapi = "no"
        search = bingsearch.search_bing(word, limit, start)
        search.process(bingapi)
        emails = search.get_emails()
        hosts = search.get_hostnames()
        all_hosts.extend(hosts)
        all_emails.extend(emails)
       
        print "[-] Searching in Exalead.."
        search = exaleadsearch.search_exalead(word, limit, start)
        search.process()
        emails = search.get_emails()
        hosts = search.get_hostnames()
        all_hosts.extend(hosts)
        all_emails.extend(emails)

        #Clean up email list, sort and uniq
        all_emails=sorted(set(all_emails))
    #Results############################################################
    print "\n\n[+] Emails found:"
    print "------------------"
    if all_emails == []:
        print "No emails found"
    else:
        print "\n".join(all_emails)

if __name__ == "__main__":
    try:
        start(sys.argv[1:])
    except KeyboardInterrupt:
        print "Search interrupted by user.."
    except:
        sys.exit()
