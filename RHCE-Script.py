#!/usr/bin/env python
# Script to check sample RHCE Practice exam (EX300)
# NOTE - This is not the official Red Hat Certified Engineer Exam (EX300) Script.
# This script is written to improve students' effeciency in the sample RHCE practice exam by
# Institute of Technical Education, Bhopal (M.P.)
#
#   Written by -  Palash Chaturvedi
#
# Please report the mistakes at palashchaturvedi1611@gmail.com

import os
import re
import sys
import socket
import subprocess
import time
import urllib2
import smtplib

CBOLD = '\33[1m'
CRED = '\033[91m'
CEND = '\033[0m'
CGREEN  = '\33[32m'
CYELLOW = '\33[33m'
CBLINK    = '\33[5m'
CBLUE   = '\33[34m'
CVIOLET = '\33[35m'
CBEIGE  = '\33[36m'

command = "ifconfig eth0 | awk '{print $2;}' | grep 172 | head -n1 | cut -d : -f2" #Need to Change device
hname  = socket.gethostname()
ipaddr = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE)
ipaddr = ipaddr.communicate()[0].split("\n")[0]
host_no = input("Enter your machine number : ")

selnx = 0
ssh_rich_rule = 0
team_conf = 0
port_fwd_rule = 0
custom_command = 0
ipv6_conf = 0
nfs_server_conf = 0
nfs_client_conf = 0
samba_pub = 0
samba_priv = 0
smpl_apache = 0
apache_virt = 0
apache_secret = 0
apache_wsgi = 0
iscsi_conf = 0
db_conf = 0
script_ques = 0


def checkEnvironment() :

    strr="""
               -------------------------------------------------------------------------------------
                                        Script to check RHCE Sample Paper
               -------------------------------------------------------------------------------------
    """

    print(CBOLD+CYELLOW+strr+CEND)
    time.sleep(1)


    print CBLINK+CBOLD+CYELLOW+"Checking Environment . . .".center(100)+CEND
    time.sleep(1)
    print
    print
    print "Your Hostname : ", hname
    time.sleep(1)
    print
    print
    print "Your Host number: ", host_no
    time.sleep(1)
    print
    print
    print "your IP address :", ipaddr

    if os.getuid() !=0 :
        print CBOLD+CBLUE+"Script should be run by Root user "+CEND+CRED+CBOLD+CBLINK+"[ ERROR ]"+CEND
        sys.exit(1)




def gen_ssh_key():
    print
    print
    print CBOLD+CYELLOW+"* * * * *Generating SSH keys and copying to Desktop Machine...Please Follow on screen process* * * * *".center(100)+CEND
    print
    print
    time.sleep(2)

    gen_key = subprocess.call('ssh-keygen',shell=True)
    ssh_copy_id = subprocess.call('ssh-copy-id -i root@desktop%d'%host_no,shell=True)


def check_service(service_name):
	status = subprocess.Popen('systemctl status %s | grep running | awk \'{print $3;}\''%(service_name),shell=True,stdout=subprocess.PIPE)
	status_op = status.communicate()[0].split('\n')[0]

	if status_op == '(running)' :

		return True 
	else :
		return False


def check_selinux() :
    print " "
    print " "
    print CBOLD+CYELLOW+"* * * * *Checking SELINUX* * * * *".center(100)+CEND
    print
    print
    global selnx
    str = subprocess.Popen("getenforce",stdout=subprocess.PIPE)
    str = str.communicate()[0].split("\n")[0]
    if str == 'Enforcing' :
        print "Selinux is Running in Enforcing mode	on Server Machine "+CGREEN+CBOLD+" [ PASS ]"+CEND
        selnx = 1
    else :
        print "Selinux is Running in ",str," mode on Server Machine	"+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND

def check_script():
    print
    print
    print CBOLD+CYELLOW+"* * * * *Checking SCRIPT question* * * * *".center(100)+CEND
    print
    print
    global script_ques
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
            print "Unable to execute script | check permissions		"+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
            return
        else:
            print "Permissions are correct....Checking Script content"
            print
    else:
        print "File not found	"+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
        return
    combination1=subprocess.Popen(script + ' ' + arg1, shell=True, stdout=subprocess.PIPE, stderr=open('/dev/null','w'))
    combination1 = combination1.communicate()[0].split('\n')[0]

    combination2 = subprocess.Popen(script + ' ' + arg2, shell=True,stdout=subprocess.PIPE, stderr=open('/dev/null','w'))
    combination2 = combination2.communicate()[0].split('\n')[0]

    combination3=subprocess.Popen(script + ' ' + 'xyz', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    combination3 = combination3.communicate()[1].split('\n')[0]

    combination4 = subprocess.Popen(script, shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    combination4 = combination4.communicate()[1].split('\n')[0]


    if ((combination1 == 'bar') and (combination2 == 'redhat') ) and ( (combination3 and combination4) == '/bin/bash script.sh redhat|bar' ):
        print "Script is correct	"+CGREEN+CBOLD+" [ PASS ]"+CEND
        script_ques = 1
    else :
        print "Output is not correct | check possible combinations	"+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND




def check_link_aggregation():
    print 
    print
    print CBOLD+CYELLOW+"* * * * *Checking Link Aggregation* * * * *".center(100)+CEND
    print
    print
    global team_conf

    command = "ifconfig team0 | awk '{print $2;}' | grep 172 | head -n1 | cut -d : -f2" 
    
    ipaddr = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE)
    ipaddr = ipaddr.communicate()[0].split("\n")[0]

    if ipaddr== '':
        print "team0 not found or not active    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
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
            if ipaddr == '172.16.%d.20'%host_no :
                print "Link Aggregation Configured correctly    "+CGREEN+CBOLD+" [ PASS ]"+CEND
                team_conf = 1
            else :
                print "Ip not configured correctly   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
        else :
            print "Slaves not configured correctly    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
    else :
        print "Team type is not ActiveBackup    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND




def ssh():
    print
    print
    print CBOLD+CYELLOW+"* * * * *Checking Firewall Rich Rule* * * * *".center(100)+CEND
    print
    print
    global ssh_rich_rule
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
    		if accept_op == 'rule family=\"ipv4\" source address=\"172.25.%d.0/24\" service name=\"ssh\" accept'%host_no : #change IP address
    			if reject_op == 'rule family=\"ipv4\" source address=\"10.0.%d.0/24\" service name=\"ssh\" reject'%host_no : #change IP address
    				print "Rich Rules are correctly set	"+CGREEN+CBOLD+" [ PASS ]"+CEND
    				ssh_rich_rule = 1
    			else :
    				print "host within my133t.org can SSH in your system "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND #change IP address
    				return
    		else :
    			print "host within example.com can not SSH in your system "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND #change IP address
    			return
    	else :
    		print "Rich Rules are not correct | REJECT Rule not found "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
    		return
    else :
    	print "Rich Rules are not correct | ACCEPT Rule not found "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
    	return



def port_fwd():
    print
    print
    print CBOLD+CYELLOW+"* * * * *Checking Firewall Rich Rule for Port Forwarding* * * * *".center(100)+CEND
    print
    print
    global port_fwd_rule

    rule = subprocess.Popen("firewall-cmd --list-all | grep \'forward-port port=\"5423\"\'",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    rule_err = rule.communicate()[1].split('\n')[0]
    rule = subprocess.Popen("firewall-cmd --list-all | grep \'forward-port port=\"5423\"\'",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    rule_op = rule.communicate()[0].split('\n')[0]

    if rule_err == '' and rule_op !='' :
    	rule = subprocess.Popen("firewall-cmd --list-all | grep \'forward-port port=\"5423\"\'",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    	rule_op = rule.communicate()[0].split('\n')[0].split('\t')[1]
    	if rule_op =='rule family=\"ipv4\" source address=\"172.25.1.0/24\" forward-port port=\"5423\" protocol=\"tcp\" to-port=\"80\"' : #change IP address and Ports
    		print  "Rich Rules for Port Forwarding are correctly set	"+CGREEN+CBOLD+" [ PASS ]"+CEND
    		port_fwd_rule = 1
    	else :
    		print "Rich Rules for Port Forwarding are not correct	"+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
    		return
    else :
    	print "Rich Rules for Port Forwarding are not correct	"+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
    	return




def check_alias():
	print
	print
	print CBOLD+CYELLOW+"* * * * *Checking question | custom user command* * * * *".center(100)+CEND
	print
	print
	global custom_command

	command = subprocess.Popen("cat /etc/bashrc | grep \"alias qstat\"",shell=True,stdout=subprocess.PIPE)
	command_op = command.communicate()[0].split('\n')[0]

	if command_op=='alias qstat=\"ps -eo pid,tid,class,rtprio,ni,pri,psr,pcpu,stat,comm\"' or command_op =='alias qstat=\'ps -eo pid,tid,class,rtprio,ni,pri,psr,pcpu,stat,comm\'':
		print "Question | Custom User Command correct   "+CGREEN+CBOLD+" [ PASS ]"+CEND
		custom_command = 1
	else :
		print "Custom Command Incorrect   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND

def check_ipv6():
    print
    print
    print CBOLD+CYELLOW+"* * * * *Checking ipv6 Configuration* * * * *".center(100)+CEND
    print
    print
    global ipv6_conf

    sys1_ip = subprocess.Popen("ifconfig eth0 | grep \"inet6 2006\"",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    sys1_ip_op = sys1_ip.communicate()[0]

    sys2_ip = subprocess.Popen("ssh root@desktop%d ifconfig eth0 | grep \"inet6 2006\""%host_no,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    sys2_ip_op = sys2_ip.communicate()[0]

    sys1_ip_content = re.search("2006:ac18::%d05"%host_no,sys1_ip_op)
    sys2_ip_content = re.search("2006:ac18::%d10"%host_no,sys2_ip_op)
    sys11_ip_content = re.search("2006:ac18::5",sys1_ip_op)
    sys22_ip_content = re.search("2006:ac18::10",sys2_ip_op)

    if ( sys1_ip_content != None or sys11_ip_content != None ) and ( sys2_ip_content != None or sys22_ip_content != None ) :
        print " "
        print "ipv6 configured correctly    "+CGREEN+CBOLD+" [ PASS ]"+CEND
        ipv6_conf = 1
    else :
        print " "
        print "ipv6 not configured correctly.... check IP for both client and server    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
'''
    if sys1_ip_content == None or sys2_ip_content == None :
        print " "
        print "ipv6 not configured correctly.... check IP for both client and server    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
    else :
        print " "
        print "ipv6 configured correctly    "+CGREEN+CBOLD+" [ PASS ]"+CEND
'''

def check_mariadb():
    print
    print
    print CBOLD+CYELLOW+"* * * * *Checking MariaDB Configuration* * * * *".center(100)+CEND
    print
    print
    global db_conf

    db = subprocess.Popen("mysql -uroot -predhat -e \"show databases;\" | grep Contacts",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    db_op = db.communicate()[0]

    conf_file = subprocess.Popen("cat /etc/my.cnf | grep skip-networking",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    conf_file_op = conf_file.communicate()[0]
    conf_file_content = re.search("skip-networking=1",conf_file_op) #check Space required or not near 1

    user = subprocess.Popen("mysql -uroot -predhat -e \"select User from mysql.user;\" | grep kevin",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    user_op = user.communicate()[0]

    user_grants = subprocess.Popen("mysql -u root -predhat -e \"SHOW GRANTS FOR kevin@localhost;\" | grep Contacts",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    user_grants_op = user_grants.communicate()[0]

    user_grants_content = re.search("SELECT",user_grants_op)

    if check_service('mariadb'):
        print ""
    else :
        print ""
        print "Check mariadb service status   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
        return

    if db_op != '':
        if conf_file_content != '':
            if user_op != '':
                if user_grants_content != '':
                    print ""
                    print "MariaDB Configured Correctly    "+CGREEN+CBOLD+" [ PASS ]"+CEND
                    db_conf = 1
                else :
                    print ""
                    print "User Kevin does not have read access to database   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
            else:
                print ""
                print "User kevin does not exist  "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
        else :
            print ""
            print "MariaDB server is not configured to listen localhost   [ FAIL "
    else :
        print ""
        print "Database Contacts does not exist  "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND




def check_samba_public():
    print
    print
    print CBOLD+CYELLOW+"* * * * *Checking Samba Single User (Samba Public)* * * * *".center(100)+CEND
    print
    print
    global samba_pub

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
                        content = subprocess.Popen("echo | testparm --section-name=common", shell=True, stdout=subprocess.PIPE, stderr=open('/dev/null','w'))
                        content1 = content.communicate()[0]
                        read_only = re.search('read only\s+=\s+No',content1)
                        if read_only == None :
                            browseable = re.search('browseable\s+=\s+No',content1)
                            if browseable == None :
                                valid_users = re.search('valid users\s+=\s+krishna',content1)
                                if valid_users != None :
                                    Firewall = subprocess.Popen('firewall-cmd --list-all',shell=True,stdout=subprocess.PIPE)
                                    Firewall_op = Firewall.communicate()[0]
                                    Firewall_op = re.search('samba',Firewall_op)
                                    if Firewall_op != None :
                                        hosts_allow = re.search('hosts allow\s+=\s+172.25.%d.0'%host_no,content1)
                                        if hosts_allow != None:
                                            print "Samba Single User has been configured correctly   "+CGREEN+CBOLD+" [ PASS ]"+CEND
                                            samba_pub = 1
                                        else :
                                            print "Check Hosts Allow entry in config file    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                                    else :
                                        print "Check Firewall entry   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                                else :
                                    print "User Krishna does not have required permissions   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                            else :
                                print "The directory is not Browseable   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                        else :
                            print "The directory should be read only   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                    else :
                        print "Workgroup is not ITEGROUP   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                else :
                    print "Directory context not correct   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
            else :
                print "Directory permissions not correct   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
        else :
            print "Directory does not exist   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
    else :
        print "service smb nmb not started   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND


def check_samba_multiuser() :
    print
    print
    print CBOLD+CYELLOW+"* * * * *Checking Samba Multi User (Samba Private)* * * * *".center(100)+CEND
    print
    print
    global samba_priv

    dir_client = '/mnt/releases'
    flag = 1

    client_status = subprocess.Popen('ssh root@desktop%d \'if [ -d /mnt/releases ]; then echo \"exists\"; else echo \"not_exists\"; fi\''%host_no,shell=True,stdout=subprocess.PIPE)
    client_status_op = client_status.communicate()[0].split('\n')[0]
    if client_status_op == 'exists':
        flag = 0
    else :
        print "Directory not mounted in Desktop Machine"
        return


    dir = '/releases'
    if check_service('smb') and check_service('nmb') :
        if os.path.isdir(dir) :
            perm = int(oct(os.stat(dir)[0])[-3:])
            if perm == 777 :
                context = subprocess.Popen("ls -ldZ /common/ | cut -d ':' -f3", shell=True, stdout=subprocess.PIPE)
                context = context.communicate()[0].split('\n')[0]
                if context == 'samba_share_t' :
                    content = subprocess.Popen("echo | testparm --section-name=releases", shell=True, stdout=subprocess.PIPE, stderr=open('/dev/null','w'))
                    content1 = content.communicate()[0]
                    read_only = re.search('read only\s+=\s+No',content1)
                    if read_only != None :
                        browseable = re.search('browseable\s+=\s+No',content1)
                        if browseable == None:
                            path = re.search('path\s+=\s+/releases',content1)
                            if path != None :
                                read_list = re.search('read list\s+=\s+kenji',content1)
                                if read_list!=None:
                                    write_list = re.search('write list\s+=\s+chihihora',content1)
                                    if write_list!=None:
                                        valid_users1 = re.search('valid users\s+=\s+chihihora,\s+\skenji',content1)
                                        valid_users2 = re.search('valid users\s+=\s+kenji,\s+chihihora',content1)
                                        if valid_users1 != None or valid_users2 != None :
                                            hosts = re.search('hosts allow\s+=\s+172.25.%d.0/24'%host_no,content1)   #change IP address
                                            if hosts != None :
                                                kenji = subprocess.Popen("smbclient -N //%s/releases -U kenji%%redhat -c \"mkdir file_temp1\"" % (ipaddr),shell=True,stdout=subprocess.PIPE,stderr=open('/dev/null','w'))
                                                kenji_op = kenji.communicate()[0]
                                                if kenji_op != '' :
                                                    chihihora = subprocess.Popen("smbclient -N //%s/releases -U chihihora%%redhat -c \"mkdir file_temp2\"" % (ipaddr),shell=True,stdout=subprocess.PIPE,stderr=open('/dev/null','w'))
                                                    chihihora_op = chihihora.communicate()[0]
						    chihihora_rm = subprocess.call("rm -rf /releases/file_temp2",shell=True,stdout=subprocess.PIPE)

                                                    if chihihora_op == '' :
                                                        Firewall = subprocess.Popen('firewall-cmd --list-all',shell=True,stdout=subprocess.PIPE)
                                                        Firewall_op = Firewall.communicate()[0]
                                                        Firewall_op = re.search('samba',Firewall_op)

                                                        if Firewall_op != None :
                                                            print "Samba Multi User Configured correctly     "+CGREEN+CBOLD+" [ PASS ]"+CEND
                                                            samba_priv = 1
                                                        else :
                                                            print "Check Firewall entry   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                                                    else :
                                                        print "User chihihora does not have write permissions or its password is incorrect   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                                                else :
                                                    print "Permissions of user kenji or its password is incorrect  "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                                            else :
                                                print "Hosts not in example.com can also access the share   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                                        else :
                                            print "Check valid users entry in config file    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                                    else :
                                        print "Check write list entry in config file    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                                else :
                                    print "Check read list entry in config file    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                            else :
                                print "Check path in config file    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                        else :
                            print "The directory is not Browseable   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                    else :
                        print "The directory is not Writeable   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                else :
                    print "Directory context not correct   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
            else :
                print "Directory permissions not correct   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
        else :
            print "Directory does not exist   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
    else :
        print "service smb nmb not started   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND



def check_apache_1():
    print
    print
    print CBOLD+CYELLOW+"* * * * *Checking Apache default hosting question* * * * *".center(100)+CEND
    print
    print
    global smpl_apache

    original = 'ftp://172.25.254.250/updates/station.html'
    check1 = 'http://' + str(ipaddr)
    check2 = 'http://server%d.example.com'%(int(host_no))

    if check_service('httpd'):
        try :
            original_content = urllib2.urlopen(original)
            original_content = original_content.read()
            content1 = urllib2.urlopen(check1)
            content1 = content1.read()
            content2 = urllib2.urlopen(check2)
            content2 = content2.read()

            if content1 == original_content and content2 == original_content:
                Firewall = subprocess.Popen('firewall-cmd --list-all',shell=True,stdout=subprocess.PIPE)
                Firewall_op = Firewall.communicate()[0]
                Firewall_op = re.search('http',Firewall_op)

                if Firewall_op != None :
                    print "Website is working perfectly    "+CGREEN+CBOLD+" [ PASS ]"+CEND
                    smpl_apache = 1
                else :
                    print "Check Firewall entry    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
            else :
                print "Content of website is not according to question   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
        except urllib2.HTTPError :
            print "Website is not working properly    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
    else :
        print "Check service status   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND


def check_virtual_hosting():
    print
    print
    print CBOLD+CYELLOW+"* * * * *Checking Apache virtul hosting question* * * * *".center(100)+CEND
    print
    print
    global apache_virt

    original = 'ftp://172.25.254.250/updates/www.html'
    check1 = 'http://www%d.example.com'%(int(host_no))

    dir = '/var/www/virtual'

    if os.path.isdir(dir) :
        if check_service('httpd'):
            try :
                original_content = urllib2.urlopen(original)
                original_content = original_content.read()
                content1 = urllib2.urlopen(check1)
                content1 = content1.read()

                if original_content == content1 :
                    Firewall = subprocess.Popen('firewall-cmd --list-all',shell=True,stdout=subprocess.PIPE)
                    Firewall_op = Firewall.communicate()[0]
                    Firewall_op = re.search('http',Firewall_op)
                    if Firewall_op != None :
                        print "Website is working perfectly    "+CGREEN+CBOLD+" [ PASS ]"+CEND
                        apache_virt = 1
                    else :
                        print "Checl Fire entry   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                else :
                    print "Content of website is not according to question   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
            except urllib2.HTTPError :
                print "Website is not working properly    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
        else :
            print "Check service status   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
    else :
        print "Directory does not exist   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND


def check_apache_secret():
    print
    print
    print CBOLD+CYELLOW+"* * * * *Checking Apache Secure Directory question.* * * * *".center(100)+CEND
    print
    print
    global apache_secret

    os.system("ifconfig eth0:0 192.168.0.1")
    dir = '/var/www/html/secret'
    check1 = 'http://server%d.example.com/secret/index.html'%host_no
    check2 = 'http://%s/secret/index.html'%ipaddr
    original_content = 'ftp://172.25.254.250/updates/host.html'
    if os.path.isdir(dir):
        if check_service('httpd'):
            try :
                original_content = urllib2.urlopen(original_content)
                original_content = original_content.read()
                content1 = urllib2.urlopen(check1)
                content1 = content1.read()
                content2 = urllib2.urlopen(check2)
                content2 = content2.read()

                if content1 == original_content and content2 == original_content:
                    os.system("ifconfig eth0:0 192.168.0.1")
                    outside_url = 'http://192.168.0.1/secret/index.html'

                    Firewall = subprocess.Popen('firewall-cmd --list-all',shell=True,stdout=subprocess.PIPE)
                    Firewall_op = Firewall.communicate()[0]
                    Firewall_op = re.search('http',Firewall_op)

                    if Firewall_op != None:
                        try :
                            urllib2.urlopen(outside_url)
                            print "Outer network can access secred directory  "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND 
                            os.system("ifconfig eth0:0 down")
                            return
                        except urllib2.HTTPError :
                            print "Secret is only accessible from System1  "+CGREEN+CBOLD+" [ PASS ]"+CEND
                            apache_secret = 1
                    else :
                        print "Check Filewall entry  "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                else :
                    print "Content of website is not according to question   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
            except urllib2.HTTPError :
                print "Secret directory is not accessible from your System1    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
        else :
            print "Check service status   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
    else :
        print "Directory does not exist   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND



def check_apache_wsgi():
    print
    print
    print CBOLD+CYELLOW+"* * * * *Checking Apache WSGI Script Question* * * * *".center(100)+CEND
    print
    print
    global apache_wsgi

    script_file = '/var/www/cgi-bin/webapp.wsgi'
    url = 'http://webapp%d.example.com:8999'%host_no

    if os.path.isfile(script_file):
        print CYELLOW+"webapp.wsgi exist...Checking other specifications.....".center(100)+CEND
	print " "
    else :
        print CRED+"webapp.wsgi does not exist in /var/www/cgi-bin/   "+CEND+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
	print " "
        return

    lable = subprocess.Popen("semanage port -l | grep 8999",shell=True,stdout=subprocess.PIPE)
    lable_op = lable.communicate()[0]

    lable1 = re.search('http_port_t',lable_op)
    if lable1 != None:
        if check_service('httpd'):
            try :
                content1 = urllib2.urlopen(url)
                content1 = content1.read()
                content = re.search('UNIX EPOCH time is now',content1)
                if content != None:
                    print "Website working correctly    "+CGREEN+CBOLD+" [ PASS ]"+CEND
                    apache_wsgi = 1
                else :
                    print "Website content not correct   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
            except urllib2.HTTPError :
                print "Website is not working properly    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
        else :
            print "Check service status   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
    else :
        print "Semanage context of port 8999 is not correct    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND



def check_nfs_server_config():
    print
    print
    print CBOLD+CYELLOW+"* * * * *Checking NFS Server side Configuration* * * * *".center(100)+CEND
    print
    print
    global nfs_server_conf
    dir1 = '/public'
    dir2 = '/protected'
    config_file = '/etc/exports'
    nfs_version_file = '/etc/sysconfig/nfs'

    key_file = '/etc/krb5.keytab'

    nfs_file_content1 = subprocess.Popen("cat /etc/exports | grep public",shell=True,stdout=subprocess.PIPE)
    nfs_file_content_op1 = nfs_file_content1.communicate()[0]

    nfs_file_content2 = subprocess.Popen("cat /etc/exports | grep protected",shell=True,stdout=subprocess.PIPE)
    nfs_file_content_op2 = nfs_file_content2.communicate()[0]

    public = re.search('ro',nfs_file_content_op1)
    protected = re.search('rw',nfs_file_content_op2)
    protected_sec = re.search('krb5p',nfs_file_content_op2)
    nfs_vers = subprocess.Popen('cat /etc/sysconfig/nfs | grep NFSDARG',shell=True,stdout=subprocess.PIPE)
    nfs_vers_op = nfs_vers.communicate()[0]
    version = re.search('4.2',nfs_vers_op)
    
    stat1 = subprocess.Popen('systemctl status nfs-server | grep active | awk \'{print $2;}\'',shell=True,stdout=subprocess.PIPE)
    status_op1 = stat1.communicate()[0].split('\n')[0]

    stat2 = subprocess.Popen('systemctl status nfs-secure-server | grep active | awk \'{print $2;}\'',shell=True,stdout=subprocess.PIPE)
    status_op2 = stat2.communicate()[0].split('\n')[0]

    if os.path.isdir(dir1) and os.path.isdir(dir2) :
        if status_op1 == "active" and status_op2 == "active" :
            context1 = subprocess.Popen("ls -ldZ /public | cut -d ':' -f3", shell=True, stdout=subprocess.PIPE)
            context1 = context1.communicate()[0].split('\n')[0]
            context2 = subprocess.Popen("ls -ldZ /protected | cut -d ':' -f3", shell=True, stdout=subprocess.PIPE)
            context2 = context2.communicate()[0].split('\n')[0]
            if context1 == 'nfs_t' and context2 == 'nfs_t':
                if public != None :
                    if protected != None :
                        if protected_sec != None :
                            if version != None :
                                Firewall = subprocess.Popen('firewall-cmd --list-all',shell=True,stdout=subprocess.PIPE)
                                Firewall_op = Firewall.communicate()[0]
                                Firewall_op = re.search('nfs',Firewall_op)
                                if Firewall_op!= None:
                                    print"NFS Server Side Configuration is correct    "+CGREEN+CBOLD+" [ PASS ]"+CEND
                                    nfs_server_conf = 1
                                    print
                                    print
                                    print CBOLD+CYELLOW+"* * * * *Checking NFS client side Configuration* * * * *".center(100)+CEND
                                    print " "
                                    print " "
                                    check_nfs_client_config()
                                else :
                                    print"Server Side Configuration not correct (check Firewall)....Skiping checking client side config......   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                            else :
                                print "NFS versionnot specified in /etc//sysconfig/nfs ....Skiping checking client side config......    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                        else :
                            print "check kerberos config entry for protected share in /etc/exports   ....Skiping checking client side config......   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                    else :
                        print "Check permissions of protected share in /etc/exports ....Skiping checking client side config......   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                else :
                    print "Check permissions of public share in /etc/exports  ....Skiping checking client side config......   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
            else :
                print "Context of directories not correct  ....Skiping checking client side config......  "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
        else :
            print "Check service status ....Skiping checking client side config......   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
    else :
        print "Directory does not exist  ....Skiping checking client side config......  "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                            

def check_nfs_client_config():
    print
    print
    global nfs_client_conf
    
    dir1 = '/mnt/public'
    dir2 = '/mnt/protected'

    var1 = subprocess.Popen("echo \"test_NFS\" > /public/test_file",shell=True,stdout=subprocess.PIPE)

    check_dir1 = subprocess.Popen("ssh root@desktop%d \'if [ -d /mnt/public ]; then echo \'true\' ; else echo \'false\';fi\'"%host_no,shell=True,stdout=subprocess.PIPE)
    check_dir1_op = check_dir1.communicate()[0].split('\n')[0]
    check_dir2 = subprocess.Popen("ssh root@desktop%d \'if [ -d /mnt/protected ]; then echo \'true\' ; else echo \'false\';fi\'"%host_no,shell=True,stdout=subprocess.PIPE)
    check_dir2_op = check_dir2.communicate()[0].split('\n')[0]



    fstab_content1 = subprocess.Popen("ssh root@desktop%d cat /etc/fstab | grep public"%host_no,shell=True,stdout=subprocess.PIPE)
    fstab_content_op1 = fstab_content1.communicate()[0]
    
    fstab_content2 = subprocess.Popen("ssh root@desktop%d cat /etc/fstab |grep protected"%host_no,shell=True,stdout=subprocess.PIPE)
    fstab_content_op2 = fstab_content2.communicate()[0]

    public = re.search('/mnt/public',fstab_content_op1)
    public_fs = re.search('nfs',fstab_content_op1)
    protected = re.search('/mnt/protected',fstab_content_op2)
    protected_sec = re.search('krb5p',fstab_content_op2)
    protected_fs = re.search('nfs',fstab_content_op2)
    nfs_vers = re.search('v4.2',fstab_content_op2)

    public_test = subprocess.Popen('ssh root@desktop%d cat /mnt/public/test_file'%host_no,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    public_test_content = public_test.communicate()[0]
    public_test_op = re.search('test_NFS',public_test_content)

    protected_test = subprocess.Popen('ssh root@desktop%d mount | grep /mnt/protected'%host_no,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    protected_test_op = protected_test.communicate()[0] #check output
    protected_test_content = re.search(':/protected',protected_test_op)

    if check_dir1_op == 'true' and check_dir2_op == 'true':
        if check_service('nfs-secure'):
            if public != None:
                if public_fs != None:
                    if protected != None:
                        if protected_sec != None:
                            if protected_fs != None:
                                if nfs_vers != None :
                                    if public_test_op != None:
                                        if protected_test_content != None :
                                            print "NFS client configured correctly"
                                            print
                                            print "NFS Server configured correctly    "+CGREEN+CBOLD+" [ PASS ]"+CEND
                                            nfs_client_conf = 1
                                        else :
                                            print "/mnt/protected is not mounted properly on client machine   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                                    else :
                                        print "You do not have read permissions on /mnt/public or it is not mounted properly on client machine   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                                else :
                                    print "Check NFS version entry in /etc/fstab file for protected share on client machine   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                            else :
                                print "Check file system type entry in /etc/fstab file for protected share on client machine   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                        else :
                            print "Check Kerberos entry in /etc/fstab file for protected share on client machine   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                    else :
                        print "Check protected share mount point entry in /etc/fstab on client machine   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                else :
                    print "Check file stab entry entry in /etc/fstab file for public share on client machine   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
            else :
                print "Check public share mount point entry in /etc/fstab on client machine   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
        else :
            print "Check service status    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
    else :
        print "Directory does not exist on client machine   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND

            




    
def check_iscsi():
    print
    print
    print CBOLD+CYELLOW+"* * * * *Checking ISCSI* * * * *".center(100)+CEND
    print
    print
    global iscsi_conf
    stat = subprocess.Popen('systemctl status target | grep active | awk \'{print $2;}\'',shell=True,stdout=subprocess.PIPE)
    status_op = stat.communicate()[0].split('\n')[0]
    if status_op == "active":
        iscsid = subprocess.Popen('ssh root@desktop%d systemctl status iscsid | grep active'%host_no,shell=True,stdout=subprocess.PIPE)
        iscsid_op = iscsid.communicate()[0]
        iscsid_status = re.search('Active: active',iscsid_op)
        if iscsid_status != None:
            iscsiadm = subprocess.Popen('ssh root@desktop%d iscsiadm -m discovery -t st -p %s'%(host_no,ipaddr),shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            iscsiadm_op = iscsiadm.communicate()[0]
            server_iqn = re.search('iqn.2015-01.com.example:system1',iscsiadm_op)
            if server_iqn != None :
                client_iqn = subprocess.Popen('ssh root@desktop%d cat /etc/iscsi/initiatorname.iscsi'%host_no,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                client_iqn = client_iqn.communicate()[0]
                client_iqn_op = re.search('iqn.2015-01.com.example:system2',client_iqn)
                if client_iqn_op != None :

                    check_dir1 = subprocess.Popen("ssh root@desktop%d \'if [ -d /mnt/storage ]; then echo \'true\' ; else echo \'false\';fi\'"%host_no,shell=True,stdout=subprocess.PIPE)
                    check_dir1_op = check_dir1.communicate()[0].split('\n')[0]
                    if check_dir1_op == 'true' :

                        check_mount = subprocess.Popen("ssh root@desktop%d mount | grep sda"%host_no,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                        check_mount_op = check_mount.communicate()[0]
                        check_mount_op1 = re.search('/dev/sda1 on /mnt/storage type ext4',check_mount_op)
                        if check_mount_op1 != None :
                            print "Iscsi configured correctly    "+CGREEN+CBOLD+" [ PASS ]"+CEND
                            iscsi_conf = 1
                            print " "
                        else :
                            print "Error in mounting    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                            print " "
                    else :
                        print "Directory does not exist    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                        print " "
                else :
                    print "Client iqn not correct    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                    print " "
            else :
                print "Server iqn not correct    "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
                print " "
        else :
            print "Check service status in client system   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
            print " "
    else :
        print "Check service status on System1   "+CRED+CBLINK+CBOLD+" [ FAIL ]"+CEND
        print " "   





def final_result():
	tot = 17
	cq = 0
	iq = 0
	final_op = """
*************************************************************************
*                                                                       *
*                      R E S U L T     S U M M A R Y                    *
*                                                                       *
*************************************************************************
"""
	print " "
	print " "
	print CYELLOW+final_op+CEND
	print " "
	if selnx :
		print CGREEN+CBOLD+"[ OK ]         "+CEND+CYELLOW+"SELINUX configured correctly"+CEND
	else :
		print CRED+CBOLD+"[ Mistake ]    "+CEND+CYELLOW+"SELINUX configured incorrectly"+CEND

	if ssh_rich_rule :
		print CGREEN+CBOLD+"[ OK ]         "+CEND+CYELLOW+"SSH Rich Rules are correctly set"+CEND
	else :
		print CRED+CBOLD+"[ Mistake ]    "+CEND+CYELLOW+"SSH Rich Rules are incorrectly set"+CEND

	if team_conf :
		print CGREEN+CBOLD+"[ OK ]         "+CEND+CYELLOW+"Link Aggregation configured correctly"+CEND
	else :
		print CRED+CBOLD+"[ Mistake ]    "+CEND+CYELLOW+"Link Aggregation configured incorrectly"+CEND

	if port_fwd_rule :
		print CGREEN+CBOLD+"[ OK ]         "+CEND+CYELLOW+"Port Forwarding Rich Rules are correctly"+CEND
	else :
		print CRED+CBOLD+"[ Mistake ]    "+CEND+CYELLOW+"Port Forwarding Rich Rules are incorrectly set"+CEND

	if custom_command :
		print CGREEN+CBOLD+"[ OK ]         "+CEND+CYELLOW+"Customized user command (Alias) is correctly set"+CEND
	else :
		print CRED+CBOLD+"[ Mistake ]    "+CEND+CYELLOW+"Customized user command (Alias) is incorrectly set"+CEND

	if ipv6_conf :
		print CGREEN+CBOLD+"[ OK ]         "+CEND+CYELLOW+"ipv6 configured correctly"+CEND
	else :
		print CRED+CBOLD+"[ Mistake ]    "+CEND+CYELLOW+"ipv6 configured incorrectly"+CEND

	if nfs_server_conf :
		print CGREEN+CBOLD+"[ OK ]         "+CEND+CYELLOW+"NFS Server Configuration is correct"+CEND
	else :
		print CRED+CBOLD+"[ Mistake ]    "+CEND+CYELLOW+"NFS Server Configuration is incorrect"+CEND

	if nfs_client_conf :
		print CGREEN+CBOLD+"[ OK ]         "+CEND+CYELLOW+"NFS Client Configuration is correct"+CEND
	else :
		print CRED+CBOLD+"[ Mistake ]    "+CEND+CYELLOW+"NFS Client Configuration is incorrect"+CEND

	if samba_pub :
		print CGREEN+CBOLD+"[ OK ]         "+CEND+CYELLOW+"Samba Public is configured correctly"+CEND
	else :
		print CRED+CBOLD+"[ Mistake ]    "+CEND+CYELLOW+"Samba Public is configured incorrectly"+CEND

	if samba_priv :
		print CGREEN+CBOLD+"[ OK ]         "+CEND+CYELLOW+"Samba Private is configured correctly"+CEND
	else :
		print CRED+CBOLD+"[ Mistake ]    "+CEND+CYELLOW+"Samba Private is configured incorrectly"+CEND

	if smpl_apache :
		print CGREEN+CBOLD+"[ OK ]         "+CEND+CYELLOW+"Apache simple web hosting solved correctly"+CEND
	else :
		print CRED+CBOLD+"[ Mistake ]    "+CEND+CYELLOW+"Apache simple web hosting solved incorrectly"+CEND

	if apache_virt :
		print CGREEN+CBOLD+"[ OK ]         "+CEND+CYELLOW+"Apache Virtual hosting solved correctly"+CEND
	else :
		print CRED+CBOLD+"[ Mistake ]    "+CEND+CYELLOW+"Apache Virtual hosting solved incorrectly"+CEND

	if apache_secret :
		print CGREEN+CBOLD+"[ OK ]         "+CEND+CYELLOW+"Apache Secret directory question solved correctly"+CEND
	else :
		print CRED+CBOLD+"[ Mistake ]    "+CEND+CYELLOW+"Apache Secret directory question solved incorrectly"+CEND

	if apache_wsgi :
		print CGREEN+CBOLD+"[ OK ]         "+CEND+CYELLOW+"Apache WSGI script hosting question solved correctly"+CEND
	else :
		print CRED+CBOLD+"[ Mistake ]    "+CEND+CYELLOW+"Apache WSGI script hosting question solved correctly"+CEND

	if iscsi_conf :
		print CGREEN+CBOLD+"[ OK ]         "+CEND+CYELLOW+"ISCSI Configuration is correct"+CEND
	else :
		print CRED+CBOLD+"[ Mistake ]    "+CEND+CYELLOW+"ISCSI Configuration is incorrect"+CEND

	if db_conf :
		print CGREEN+CBOLD+"[ OK ]         "+CEND+CYELLOW+"MariaDB  configured correctly"+CEND
	else :
		print CRED+CBOLD+"[ Mistake ]    "+CEND+CYELLOW+"MariaDB  configured incorrectly"+CEND

	if script_ques :
		print CGREEN+CBOLD+"[ OK ]         "+CEND+CYELLOW+"Script is correct"+CEND
	else :
		print CRED+CBOLD+"[ Mistake ]    "+CEND+CYELLOW+"Script is incorrect"+CEND

	print " "
	print " "
	print "NOTE: For detailed analysis view individual results..... "

	endstr = """
****************************************************************
*                                                              *
* Please report the mistakes at palashchaturvedi1611@gmail.com *
*                                                              *
****************************************************************
"""

	print " "
	print " "

	print(CBOLD+CYELLOW+endstr+CEND)
	print " "



def main():
	gen_ssh_key()
	checkEnvironment()
	check_selinux()
	ssh()
	check_link_aggregation()
	port_fwd()
	check_alias()
	check_ipv6()
	check_nfs_server_config()
	check_samba_public()
	check_samba_multiuser()
	check_apache_1()
	check_virtual_hosting()
	check_apache_secret()
	check_apache_wsgi()
	#MAIL_SERVER
	check_iscsi()
	check_mariadb()
	check_script()
	final_result()



if __name__ == '__main__' :
	try :
		main()
	except :
		print CRED+CBLINK+"Error Occured!"+CEND
		print CYELLOW+"Please contact Palash Chaturvedi"+CEND
		print CYELLOW+"palashchaturvedi1611@gmail.com"+CEND



