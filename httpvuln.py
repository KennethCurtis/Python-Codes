#Results from the scans will indicate just host up if it returns negative, but will state Vulnerable if targetable.
#This will create a directory in linux for the particular IP, and then create a total output file and vulnerability summary .txts
#Version 1
#Scripts validated to run and get outputs, have not tested against one that gives a positive on VULNERABLE yet.

import argparse
import os
import subprocess
from subprocess import run

def startup():
    port_check = input('Enter the port to check, 80 or 443: ')
    http_vuln_list = ['http-vuln-wnr1000-creds.nse',
                 'http-vuln-cve2017-5638.nse',
                 'http-vuln-cve2015-1635.nse',
                 'http-vuln-cve2013-7091.nse',
                 'http-vuln-cve2013-6786.nse',
                 'http-vuln-cve2013-0156.nse',
                 'http-vuln-cve2012-1823.nse',
                 'http-vuln-cve2011-3368.nse',
                 'http-vuln-cve2010-2861.nse',
                 'http-huawei-hg5xx-vuln.nse']

    http_arg_list = ['http-vuln-cve2017-8917',
                 'http-vuln-cve2017-1001000',
                 'http-vuln-cve2011-3192.nse',
                 'http-vuln-cve2010-0738',
                 'http-vuln-cve2009-3960',
                 'http-vuln-cve2006-3392',
                 'http-vuln-cve2015-1427',
                 'http-vuln-cve2014-8877',
                 'http-vuln-cve2014-3704']
    
    dict = {'http-vuln-cve2017-8917': 'http-vuln-cve2017-8917.uri=joomla/',
            'http-vuln-cve2017-1001000': 'http-vuln-cve2017-1001000="uri"',
            'http-vuln-cve2011-3192.nse':  'http-vuln-cve2011-3192.hostname=nmap.scanme.org',
            'http-vuln-cve2010-0738': 'http-vuln-cve2010-0738.paths={/path1/,/path2/}',
            'http-vuln-cve2009-3960': 'http-http-vuln-cve2009-3960.root="/root/"',
            'http-vuln-cve2006-3392': 'http-vuln-cve2006-3392.file=/etc/shadow ',
            'http-vuln-cve2015-1427': "command= 'ls'",
            'http-vuln-cve2014-8877': 'http-vuln-cve2014-8877.cmd="whoami",http-vuln-cve2014-8877.uri="/wordpress" ',
            'http-vuln-cve2014-3704': 'http-vuln-cve2014-3704.cmd="uname -a",http-vuln-cve2014-3704.uri="/drupal"'}

    
    https_vuln_list = ['http-vuln-cve2014-2129',
                     'http-vuln-cve2014-2128',
                     'http-vuln-cve2014-2127',
                     'http-vuln-cve2014-2126']                     

    default_vuln_list = ['http-vuln-misfortune-cookie.nse',
                         'http-vuln-cve2017-5689.nse',
                         'http-vmware-path-vuln.nse',
                         'http-iis-webdav-vuln.nse']

    def_dict = {'http-vuln-misfortune-cookie.nse': '-p 7547',
                'http-vuln-cve2017-5689.nse': '-p 16992',
                'http-vmware-path-vuln.nse': '-p 80,443,8222,8333',
                'http-iis-webdav-vuln.nse': '-p 80,8080'}
                         
    parser = argparse.ArgumentParser()
    parser.add_argument('IP', type=str, help="Enter the value of the IP of the target.")
    args = parser.parse_args()
    os.system('mkdir ' + args.IP)
    doc_hold = ''
    active_list = []
    doc = open('/home/kali/Desktop/python/scanners/http/' + args.IP + '/httpvuln.txt', 'a+')
    if '80' in str(port_check):
        active_list = http_vuln_list
    elif '443' in str(port_check):
        active_list = https_vuln_list
    port_check = '-p ' + str(port_check)
    for i in active_list:
        output = subprocess.Popen(['nmap', args.IP, '--script', i, port_check], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout= output.communicate()
        print (i + '\n')
        print(stdout)
        print ('\n\n')
        doc_hold = check_vuln(stdout, doc, doc_hold, i)
    if '80' in str(port_check):
        for i in http_arg_list:
            output = subprocess.Popen(['nmap', args.IP, '--script', i, '-p 80', '--script-args', dict[i]], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            stdout= output.communicate()
        print (i + '\n')
        print(stdout)
        print ('\n\n')
        doc_hold = check_vuln(stdout, doc, doc_hold, i)
    for i in default_vuln_list:
        output = subprocess.Popen(['nmap', '--script', i, args.IP, def_dict[i]], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout= output.communicate()
        print (i + '\n')
        print(stdout)
        print ('\n\n')
        doc_hold = check_vuln(stdout, doc, doc_hold, i)
    prettify(args, doc_hold)

    
def prettify(args, doc_hold):
    doc1 = open('/home/kali/Desktop/python/scanners/http/' + args.IP + '/httpnmap.txt', 'w+')
    double_remove = doc_hold.replace('\\n\\n','\n')
    csv_replace = double_remove.replace('\\n',',')
    csv_list = csv_replace.split (',')
    for i in csv_list:
        doc1.write (i + '\n')
    doc1.close()


def check_vuln(stdout, doc, doc_hold, i):
    if 'VULNERABLE' in str(stdout):
        doc.write (i + ': VULERNABLE\n')
    else:
        doc.write (i + ': did not return a VULNERABLE\n')
    return doc_hold + str(stdout) + '\n'

startup()
