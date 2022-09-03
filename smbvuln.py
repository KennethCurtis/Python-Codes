#Results from the scans will indicate just host up if it returns negative, but will state Vulnerable if targetable.
#This will create a directory in linux for the particular IP, and then create a total output file and vulnerability summary .txts
#version 1.0

import argparse
import os
import subprocess
from subprocess import run

def startup():
    vuln_list = ['smb-vuln-cve2009-3103.nse',
                 'smb-vuln-ms08-067.nse',
                 'smb-vuln-regsvc-dos.nse',
                 'smb-vuln-cve-2017-7494.nse',
                 'smb-vuln-ms10-054.nse',
                 'smb-vuln-webexec.nse',
                 'smb-vuln-ms06-025.nse',
                 'smb-vuln-ms10-061.nse',
                 'smb2-vuln-uptime.nse',
                 'smb-vuln-conficker.nse',
                 'smb-vuln-ms07-029.nse',
                 'smb-vuln-ms17-010.nse']
    parser = argparse.ArgumentParser()
    parser.add_argument('IP', type=str, help="Enter the value of the IP of the target.")
    args = parser.parse_args()
    os.system('mkdir ' + args.IP)
    doc = open('/home//python/scanners/' + args.IP + '/smbvuln.txt', 'a+')
    doc1 = open('/home/python/scanners/' + args.IP + '/smbnmap.txt', 'a+')
    for i in vuln_list:
        payload = 'nmap ' +args.IP + ' --script ' + i + ' -p 445'
        output = subprocess.Popen(['nmap', args.IP, '--script', i, '-p 445'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout= output.communicate()
        print(stdout)
        check_vuln(stdout, doc, doc1, i)


def check_vuln(stdout, doc, doc1, i):
    if 'VULNERABLE' in str(stdout):
        doc.write (i + ': VULERNABLE\n')
    else:
        doc.write (i + ': not a valid exploit\n')
    doc1.write (str(stdout))
    doc1.write('\n')

startup()
