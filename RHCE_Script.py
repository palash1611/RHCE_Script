#!/usr/bin/env python3
#
#!/bin/bash
# Script to check sample RHCE Practice exam (EX200)
# NOTE - This is not the official Red Hat Certified Engineer Exam (EX200) Script.
# This script is written to improve students' effeciency in the sample RHCE practice exam by
# Institute of Technical Education, Bhopal (M.P.)
#
#	Author		: Palash Chaturvedi
#	Date		: 6/06/2018

import os
import sys
import socket
import subprocess
import selinux
import time

command = "ifconfig wlp2s0| awk '{print $2;}' | grep 192 | head -n1 | cut -d : -f2"
hname  = socket.gethostname()
ipaddr = subprocess.run(command, stdout=subprocess.PIPE, stderr=None, shell=True)
ipaddr = ipaddr.stdout.decode().split('\n')[0]

def checkEnvironment() :

    strr="""
                                                        -------------------------------------------------------------------------------------
                                                                         Script to check EX300 | Author - Palash Chaturvedi
                                                        -------------------------------------------------------------------------------------
    """

    print(strr)
    time.sleep(1)

    print ("Checking Environment . . .".center(1000))
    time.sleep(1)
    print()
    print()
    print("Your Hostname : ", hname)
    time.sleep(1)
    print()
    print()
    print("your IP address :", ipaddr)

    if os.getuid() !=0 :
        print("Script should be run by Root user  [ ERROR ]")
        sys.exit(1)

def check_selinux() :
    print()
    print()
    print("Checking SELINUX ..........".center(1000))
    print()
    print()
    str = subprocess.run("getenforce",stdout=subprocess.PIPE)
    str = str.stdout.decode().split('\n')[0]
    if str == 'Enforcing' :
        print("Selinux is Running in Enforcing mode	[ OK ]\n")
    else :
        print("Selinux is Running in ",str," mode	[ Mistake ]\n")


def check_script():
    print()
    print()
    print("Checking SCRIPT question..........".center(1000))
    print()
    print()
    """ The name of the script will be script.sh . When you pass "redhat" as the first argument to the script then it should print "bar".
    When you pass "bar" as the first argument to the script then it should print "redhat" and when you dont pass or you write something else,
    then it should print this error "/bin/bash script.sh redhat|bar " and redirect its output to standard error(stderr).
    Place the script in /root/bin directory.
    """
    dir='/root/bin'
    name='script.sh'
    arg1='redhat'
    arg2='bar'
    script=dir+'/'+name
    #print(script)
    error='/bin/bash %s %s|%s' %(name,arg1,arg2)
    if os.path.isfile(script):
        stat = subprocess.run(script, shell=True, stderr=subprocess.PIPE, stdout=open('/dev/null','w'))
        stat = stat.stderr.decode().split('\n')[0]
        if stat == '/bin/sh: /root/bin/script.sh: Permission denied':
            print("Unable to execute script | check permissions		[ Mistake ]\n")
            return
        else:
            print("Permissions are correct....Checking Script content")
            print()
    else:
        print("File not found	[ Mistake ]\n")
        return
    check1 = subprocess.run(script + ' ' + arg1, shell=True,stdout=subprocess.PIPE, stderr=open('/dev/null','w'))
    check1 = check1.stdout.decode().split('\n')[0]
    check2 = subprocess.run(script + ' ' + arg2, shell=True, stdout=subprocess.PIPE, stderr=open('/dev/null','w'))
    check2 = check2.stdout.decode().split('\n')[0]
    check3 = subprocess.run(script + ' ' + 'xyz', shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    check3 = check3.stderr.decode().split('\n')[0]
    check4 = subprocess.run(script, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    check4 = check4.stderr.decode().split('\n')[0]

    if ((check1 == 'bar') and (check2 == 'redhat') ) and ( (check3 and check4) == '/bin/bash script.sh redhat|bar' ):
        print("Script is correct	[ OK ]\n")
    else :
        print("Output is not correct | check possible combinations	[ Mistake ]\n")


def ssh():
    print()
    print()
    print("Checking Firewall Rich Rule for SSH..........".center(1000))
    print()
    print()
    accept = subprocess.run("firewall-cmd --list-all | grep \'\"ssh\" accept\'",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    accept_err = accept.stderr.decode()
    accept_op = accept.stdout.decode()

    reject = subprocess.run("firewall-cmd --list-all | grep \'\"ssh\" reject\'",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    reject_err = reject.stderr.decode()
    reject_op = reject.stdout.decode()


    if accept_op != '':
        if reject_op != '':
            accept = accept.stdout.decode().split('\n')[0].split('\t')[1]
            reject = reject.stdout.decode().split('\n')[0].split('\t')[1]
            if accept == 'rule family="ipv4" source address="10.1.1.1" service name="ssh" accept' :
                if reject == 'rule family="ipv4" source address="10.1.1.5" service name="ssh" reject' :
                    print("Rich Rules for SSH are correctly set	[ OK ]\n")
                else :
                    print("host 10.1.1.5 can SSH in your system [ Mistake ]\n")
                    return
            else:
                print("host 10.1.1.1 can not SSH in your system [ Mistake ]\n")
                return
        else :
            print("Rich Rules for SSH are not correct [ Mistake ]\n")
            return
    else :
        print("Rich Rules for SSH are not correct [ Mistake ]\n")
        return

def port_fwd():
    print()
    print()
    print("Checking Firewall Rich Rule for Port Forwarding..........".center(1000))
    print()
    print()

    rule = subprocess.run("firewall-cmd --list-all | grep \'forward-port port=\"5423\"\'",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    rule_op = rule.stdout.decode()

    if rule_op != '' :
        rule = rule.stdout.decode().split('\n')[0].split('\t')[1]
        if rule == 'rule family="ipv4" source address="172.25.1.0/24" forward-port port="5423" protocol="tcp" to-port="80"' :
            print ("Rich Rules for Port Forwarding are correctly set	[ OK ]\n")
        else :
            print ("Rich Rules for Port Forwarding are not correct	[ Mistake ]\n")
            return
    else:
        print ("Rich Rules for Port Forwarding are not correct	[ Mistake ]\n")
        return



checkEnvironment()
check_selinux()
check_script()
ssh()
port_fwd()
