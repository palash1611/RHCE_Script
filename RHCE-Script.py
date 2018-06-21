#!/usr/bin/env python

#!/bin/bash
# Script to check sample RHCE Practice exam (EX200)
# NOTE - This is not the official Red Hat Certified Engineer Exam (EX200) Script.
# This script is written to improve students' effeciency in the sample RHCE practice exam by
# Institute of Technical Education, Bhopal (M.P.)
#
#   Author      : Palash Chaturvedi
#   Date        : 6/06/2018

import os
import sys
import socket
import subprocess
import time

command = "ifconfig wlp2s0| awk '{print $2;}' | grep 192 | head -n1 | cut -d : -f2" #Need to Change device
hname  = socket.gethostname()
ipaddr = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE)
ipaddr = ipaddr.communicate()[0].split("\n")[0]


def checkEnvironment() :

    strr="""
                                                        -------------------------------------------------------------------------------------
                                                                      			   Script to check EX300
                                                        -------------------------------------------------------------------------------------
    """

    print(strr)
    time.sleep(1)

    print "Checking Environment . . .".center(100)
    time.sleep(1)
    print
    print
    print "Your Hostname : ", hname
    time.sleep(1)
    print
    print
    print"your IP address :", ipaddr

    if os.getuid() !=0 :
        print "Script should be run by Root user  [ ERROR ]"
        sys.exit(1)

def check_service(service_name):
	status = subprocess.Popen('systemctl status %s | grep running | awk \'{print $3;}\''%(service_name),shell=True,stdout=subprocess.PIPE)
	status_op = status.communicate()[0].split('\n')[0]

	if status_op == '(running)' :

		return True 
	else :
		return False


def check_selinux() :
    print
    print
    print "Checking SELINUX ..........".center(100)
    print
    print
    str = subprocess.Popen("getenforce",stdout=subprocess.PIPE)
    str = str.communicate()[0].split("\n")[0]
    if str == 'Enforcing' :
        print "Selinux is Running in Enforcing mode	[ OK ]\n"
    else :
        print "Selinux is Running in ",str," mode	[ Mistake ]\n"

def check_script():
    print
    print
    print "Checking SCRIPT question..........".center(100)
    print
    print
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
    if os.path.isfile(script):
        stat = subprocess.Popen(script, shell=True, stderr=subprocess.PIPE, stdout=open('/dev/null','w'))
        stat = stat.communicate()[-1].split('\n')[0]
        if stat == '/bin/sh: /root/bin/script.sh: Permission denied':
            print "Unable to execute script | check permissions		[ Mistake ]"
            return
        else:
            print "Permissions are correct....Checking Script content"
            print
    else:
        print "File not found	[ Mistake ]"
        return
    check1=subprocess.Popen(script + ' ' + arg1, shell=True, stdout=subprocess.PIPE, stderr=open('/dev/null','w'))
    check1 = check1.communicate()[0].split('\n')[0]

    check2 = subprocess.Popen(script + ' ' + arg2, shell=True,stdout=subprocess.PIPE, stderr=open('/dev/null','w'))
    check2 = check2.communicate()[0].split('\n')[0]

    check3=subprocess.Popen(script + ' ' + 'xyz', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    check3 = check3.communicate()[1].split('\n')[0]

    check4 = subprocess.Popen(script, shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    check4 = check4.communicate()[1].split('\n')[0]


    if ((check1 == 'bar') and (check2 == 'redhat') ) and ( (check3 and check4) == '/bin/bash script.sh redhat|bar' ):
        print "Script is correct	[ OK ]"
    else :
        print "Output is not correct | check possible combinations	[ Mistake ]"




def ssh():
    print
    print
    print "Checking Firewall Rich Rule..........".center(100)
    print
    print
    accept = subprocess.Popen("firewall-cmd --list-all | grep \'\"ssh\" accept\'",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    accept_err = accept.communicate()[1].split('\n')[0]
    

    reject = subprocess.Popen("firewall-cmd --list-all | grep \'\"ssh\" reject\'",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    reject_err = reject.communicate()[1].split('\n')[0]
    accept = subprocess.Popen("firewall-cmd --list-all | grep \'\"ssh\" accept\'",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    accept_op = accept.communicate()[0].split('\n')[0]
    reject = subprocess.Popen("firewall-cmd --list-all | grep \'\"ssh\" reject\'",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    reject_op = reject.communicate()[0].split('\n')[0]
    

    if accept_err == '' and accept_op!= '':
    	if reject_err== '' and reject_op!='':
    		accept = subprocess.Popen("firewall-cmd --list-all | grep \'\"ssh\" accept\'",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    		accept_op = accept.communicate()[0].split('\n')[0].split('\t')[1]
    		reject = subprocess.Popen("firewall-cmd --list-all | grep \'\"ssh\" reject\'",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    		reject_op = reject.communicate()[0].split('\n')[0].split('\t')[1]
    		#print accept_op
    		#print reject_op
    		if accept_op == 'rule family="ipv4" source address="10.1.1.1" service name="ssh" accept' : #change IP address
    			if reject_op == 'rule family="ipv4" source address="10.1.1.5" service name="ssh" reject' : #change IP address
    				print "Rich Rules are correctly set	[ OK ]"
    			else :
    				print "host 10.1.1.5 can SSH in your system [ Mistake ]" #change IP address
    				return
    		else :
    			print "host 10.1.1.1 can not SSH in your system [ Mistake ]" #change IP address
    			return
    	else :
    		print "Rich Rules are not correct | REJECT Rule not found [ Mistake ]"
    		return
    else :
    	print "Rich Rules are not correct | ACCEPT Rule not found [ Mistake ]"
    	return



def port_fwd():
    print
    print
    print "Checking Firewall Rich Rule for Port Forwarding..........".center(100)
    print
    print

    rule = subprocess.Popen("firewall-cmd --list-all | grep \'forward-port port=\"5423\"\'",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    rule_err = rule.communicate()[1].split('\n')[0]
    rule = subprocess.Popen("firewall-cmd --list-all | grep \'forward-port port=\"5423\"\'",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    rule_op = rule.communicate()[0].split('\n')[0]

    if rule_err == '' and rule_op !='' :
    	rule = subprocess.Popen("firewall-cmd --list-all | grep \'forward-port port=\"5423\"\'",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    	rule_op = rule.communicate()[0].split('\n')[0].split('\t')[1]
    	if rule_op =='rule family="ipv4" source address="172.25.1.0/24" forward-port port="5423" protocol="tcp" to-port="80"' : #change IP address and Ports
    		print  "Rich Rules for Port Forwarding are correctly set	[ OK ]\n"
    	else :
    		print "Rich Rules for Port Forwarding are not correct	[ Mistake ]\n"
    		return
    else :
    	print "Rich Rules for Port Forwarding are not correct	[ Mistake ]\n"
    	return




def check_alias():
	print
	print
	print "Checking question | custom user command......".center(100)
	print
	print

	command = subprocess.Popen("cat /etc/bashrc | tail -n1",shell=True,stdout=subprocess.PIPE)
	command_op = command.communicate()[0].split('\n')[0]

	if command_op=='alias qstat=\"ps -eo pid,tid,class,rtprio,ni,pri,psr,pcpu,stat,comm\"' or command_op =='alias qstat=\'ps -eo pid,tid,class,rtprio,ni,pri,psr,pcpu,stat,comm\'':
		print "Question | Custom User Command correct   [ OK ]"
	else :
		print "Custom Command Incorrect   [ Mistake ]"

'''
def check_samba_public():
    print
    print
    print "Checking Samba Single User (Samba Public)......".center(100)
    print
    print

    dir = '/common'
    if check_service('smb') and check_service('nmb') :
        if os.path.isdir(dir) :
            perm = int(oct(os.stat(dir)[0])[-3:])
            if perm == 777 :
                context = subprocess.Popen("ls -ldZ /common/ | cut -d ':' -f3", shell=True, stdout=subprocess.PIPE)
                context = context.communicate()[0].split('\n')[0]
                if context == 'samba_share_t' :
                    content = subprocess.Popen("echo | testparm --section-name=global", shell=True, stdout=subprocess.PIPE, stderr=open('/dev/null','w'))
                    content = content.communicate()[0]
                    workgroup = re.search('workgroup\s+=\s+ITEGROUP',content)
                    if workgroup!=None :
                        

'''


def check_link_aggregation():
    print 
    print
    print "Checking Link Aggregation......".center(100)
    print
    print

    command = "ifconfig team0| awk '{print $2;}' | grep 192 | head -n1 | cut -d : -f2" #Need to Change device
    
    ipaddr = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE)
    ipaddr = ipaddr.communicate()[0].split("\n")[0]

    if ipaddr== '':
        print "team0 not found or not active    [ Mistake ]"
        return

    team_typ = subprocess.Popen("teamdctl team0 state | grep activebackup",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    team_typ1 = team_typ.communicate()[0]
    if team_typ1 != '' :
        e1 = subprocess.Popen("teamdctl team0 state | grep eno1 | head -n1",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        e1_op = e1.communicate()[0]
        e2 = subprocess.Popen("teamdctl team0 state | grep eno1 | head -n1",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        e2_op = e2.communicate()[0]
        if e1_op != '' and e2_op != '':
            ipaddr = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE)
            ipaddr = ipaddr.communicate()[0].split("\n")[0]
            if ipaddr == '192.168.0.105' :
                print "Link Aggregation Configured correctly    [ OK ]"
            else :
                print "Ip not configured correctly   [ Mistake ]"
        else :
            print "Slaves not configured correctly    [ OK ]"
    else :
        print "Team type is not ActiveBackup    [ Mistake ]"












        




checkEnvironment()
check_selinux()
check_script()
ssh()
port_fwd()
check_alias()
