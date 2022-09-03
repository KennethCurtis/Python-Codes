#This will create a directory in linux for the particular IP, and then create a raw and pretty format of the output of the nmap scans
#version 1.0

import argparse
import os
import subprocess
from subprocess import run

def startup():
    vuln_list = ['smb-protocols',
                 'smb-security-mode',
                 'smb-enum-sessions',
                 'smb-enum-shares',
                 'smb-enum-domains',
                 'smb-enum-groups',
                 'smb-enum-shares,smb-ls',
                 'smb-server-stats',
                 'smb-os-discovery']
    parser = argparse.ArgumentParser()
    parser.add_argument('IP', type=str, help="Enter the value of the IP of the target.")
    args = parser.parse_args()
    os.system('mkdir ' + args.IP)
    doc = open('/home/kali/Desktop/python/scanners/' + args.IP + '/smbenumnmap.txt', 'a+')
    for i in vuln_list:
        payload = 'nmap ' +args.IP + ' --script ' + i + ' -p 445'
        output = subprocess.Popen(['nmap', args.IP, '--script', i, '-p 445'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout= output.communicate()
        print(stdout)
        check_vuln(stdout, doc, i)
    doc.close()
    prettify(args)
    doc.close()
    

def check_vuln(stdout, doc, i):
    doc.write (str(stdout))
    doc.write('\n')

def prettify(args):
    doc = open('/home/python/scanners/' + args.IP + '/smbenumnmap.txt', 'r')
    doc1=open('/home/python/scanners/' + args.IP + '/pretty_smb_nmap.txt', 'w+')
    read_output = doc.read()
    double_remove = read_output.replace('\\n\\n','\n')
    csv_replace = double_remove.replace('\\n',',')
    csv_list = csv_replace.split (',')
    for i in csv_list:
        doc1.write (i + '\n')
    doc1.close()

startup()
