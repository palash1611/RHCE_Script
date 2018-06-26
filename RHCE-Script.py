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
import re
import sys
import socket
import subprocess
import time
import urllib2


command = "ifconfig wlp2s0| awk '{print $2;}' | grep 192 | head -n1 | cut -d : -f2" #Need to Change device
hname  = socket.gethostname()
ipaddr = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE)
ipaddr = ipaddr.communicate()[0].split("\n")[0]
host_no = input("Enter your machine number : ")


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




def gen_ssh_key():
    print
    print
    print "Generating SSH keys and copying to Desktop Machine...Please Follow on screen process......".center(100)
    print
    print

    gen_key = subprocess.call('ssh-keygen',shell=True)
    ssh_copy_id = subprocess.call('ssh-copy-id -i root@desktop0',shell=True)


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
        print "Selinux is Running in Enforcing mode	on Server Machine [ OK ]\n"
    else :
        print "Selinux is Running in ",str," mode on Server Machine	[ Mistake ]\n"

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
    combination1=subprocess.Popen(script + ' ' + arg1, shell=True, stdout=subprocess.PIPE, stderr=open('/dev/null','w'))
    combination1 = combination1.communicate()[0].split('\n')[0]

    combination2 = subprocess.Popen(script + ' ' + arg2, shell=True,stdout=subprocess.PIPE, stderr=open('/dev/null','w'))
    combination2 = combination2.communicate()[0].split('\n')[0]

    combination3=subprocess.Popen(script + ' ' + 'xyz', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    combination3 = combination3.communicate()[1].split('\n')[0]

    combination4 = subprocess.Popen(script, shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    combination4 = combination4.communicate()[1].split('\n')[0]


    if ((combination1 == 'bar') and (combination2 == 'redhat') ) and ( (combination3 and combination4) == '/bin/bash script.sh redhat|bar' ):
        print "Script is correct	[ OK ]"
    else :
        print "Output is not correct | check possible combinations	[ Mistake ]"




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
                        content = subprocess.Popen("echo | testparm --section-name=common", shell=True, stdout=subprocess.PIPE, stderr=open('/dev/null','w'))
                        content1 = content.communicate()[0]
                        read_only = re.search('read only\s+=\s+No',content1)
                        if read_only == None :
                            browseable = re.search('browseable\s+=\s+No',content1)
                            if browseable == None :
                                valid_users = re.search('valid users\s+=\s+krishna',content1)
                                if valid_users != None :
                                    print "Samba Single User has been configured correctly   [ OK ]"
                                else :
                                    print "User Krishna does not have required permissions   [ Mistake ]"
                            else :
                                print "The directory is not Browseable   [ Mistake ]"
                        else :
                            print "The directory should be read only   [ Mistake ]"
                    else :
                        print "Workgroup is not ITEGROUP   [ Mistake ]"
                else :
                    print "Directory context not correct   [ Mistake ]"
            else :
                print "Directory permissions not correct   [ Mistake ]"
        else :
            print "Directory does not exist   [ Mistake ]"
    else :
        print "service smb nmb not started   [ Mistake ]"


def check_samba_multiuser() :
    print
    print
    print "Checking Samba Single User (Samba Public)......".center(100)
    print
    print

    dir_client = '/mnt/releases'
    flag = 1

    client_status = subprocess.Popen('ssh root@desktop0 if [ -d /mnt/releases ]; then echo \"exists\"; else echo \"not_exists\";',shell=True,stdout=subprocess.PIPE)
    client_status_op = client_status.communicate()[0]
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
                    content1 = content.subprocess.communicate()[0]
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
                                        valid_users1 = re.search('valid users\s+=\s+chihihora\s+\skenji',content1)
                                        valid_users2 = re.search('valid users\s+=\s+kenji\s+\schihihora',content1)
                                        if valid_users1 != None or valid_users2 != None :
                                            hosts = re.search('hosts allow\s+=\s+172.25.0.0/24',content1)   #chenge IP address
                                            if hosts != None :
                                                kenji = subprocess.Popen("smbclient -N //%s/releases -U kenji%%redhat -c \"mkdir file_temp1\"" % (ipaddr),shell=True,stdout=subprocess.PIPE,stderr=open('/dev/null','w'))
                                                kenji_op = kenji.communicate()[0]
                                                if kenji_op != '' :
                                                    chihihora = subprocess.Popen("smbclient -N //%s/releases -U chihihora%%redhat -c \"mkdir file_temp2\"" % (ipaddr),shell=True,stdout=subprocess.PIPE,stderr=open('/dev/null','w'))
                                                    chihihora_op = chihihora.communicate()[0]
                                                    if chihihora_op == '' :
                                                        print "Samba Multi User Configured correctly     [ OK ]"
                                                    else :
                                                        print "User chihihora does not have write permissions or its password is incorrect   [ Mistake ]"
                                                else :
                                                    print "Permissions of user kenji or its password is incorrect  [ Mistake ]"
                                            else :
                                                print "Hosts not in example.com can also access the share   [ Mistake ]"
                                        else :
                                            print "Check valid users entry in config file    [ Mistake ]"
                                    else :
                                        print "Check write list entry in config file    [ Mistake ]"
                                else :
                                    print "Check read list entry in config file    [ Mistake ]"
                            else :
                                print "Check path in config file    [ Mistake ]"
                        else :
                            print "The directory is not Browseable   [ Mistake ]"
                    else :
                        print "The directory is not Writeable   [ Mistake ]"
                else :
                    print "Directory context not correct   [ Mistake ]"
            else :
                print "Directory permissions not correct   [ Mistake ]"
        else :
            print "Directory does not exist   [ Mistake ]"
    else :
        print "service smb nmb not started   [ Mistake ]"



def check_apache_1():
    print
    print
    print "Checking Apache default hosting question......".center(100)
    print
    print

    original = 'ftp://172.25.254.100/updates/station.html'
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
                print "Website is working perfectly    [ OK ]"
            else :
                print "Content of website is not according to question   [ Mistake ]"
        except urllib2.HTTPError :
            print "Website is not working properly    [ Mistake ]"
    else :
        print "Check service status   [ Mistake ]"


def check_virtual_hosting():
    print
    print
    print "Checking Apache virtul hosting question.....".center(100)
    print
    print

    original = 'ftp://172.25.254.100/updates/www.html'
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
                    print "Website is working perfectly    [ OK ]"
                else :
                    print "Content of website is not according to question   [ Mistake ]"
            except urllib2.HTTPError :
                print "Website is not working properly    [ Mistake ]"
        else :
            print "Check service status   [ Mistake ]"
    else :
        print "Directory does not exist   [ Mistake ]"


def check_apache_secret():
    print
    print
    print "Checking Apache Secure Directory question......".center(100)
    print
    print

    os.system("ifconfig eth0:0 192.168.0.1")
    dir = '/var/www/html/secret'
    check1 = 'http://server%d.example.com/secret/index.html'%host_no
    check2 = 'http://%s/secret/index.html'%ipaddr
    original_content = 'ftp://172.25.254.100/updates/host.html'
    if os.path.isdir(dir):
        if check_service('httpd'):
            try :
                original_content = urllib2.urlopen(original)
                original_content = original_content.read()
                content1 = urllib2.urlopen(check1)
                content1 = content1.read()
                content2 = urllib2.urlopen(check2)
                content2 = content2.read()

                if content1 == original_content and content2 == original_content:
                    os.system("ifconfig eth0:0 192.168.0.1")
                    outside_url = 'http://192.168.0.1/secret/index.html'

                    try :
                        urllib2.urlopen(outside_url)
                        print "Outer network can access secred directory  [ Mistake ]" 
                        os.system("ifconfig eth0:0 down")
                        return
                    except urllib2.HTTPError :
                        print "Secret is only accessible from System1  [ OK ]"
                else :
                    print "Content of website is not according to question   [ Mistake ]"
            except urllib2.HTTPError :
                print "Secret directory is not accessible from your System1    [ Mistake ]"
        else :
            print "Check service status   [ Mistake ]"
    else :
        print "Directory does not exist   [ Mistake ]"



def check_apache_wsgi():
    print
    print
    print "Checking Apache WSGI Script Question....".center(100)
    print
    print

    script_file = '/var/www/cgi-bin/webapp.wsgi'
    url = 'http://webapp%d.example.com:8999'%host_no

    if os.path.isfile(script_file):
        print "webapp.wsgi exist...Checking other specifications.....".center(100)
    else :
        print"webapp.wsgi does not exist in /var/www/cgi-bin/   [ Mistake ]"
        return

    lable = subprocess.Popen("semanage port -l | grep 8999",shell=True,stdout=subprocess.PIPE)
    lable_op = lable.communicate()[0]

    lable1 = re.search('http_port_t',lable_op)
    if lable != None:
        if check_service('httpd'):
            try :
                content1 = urllib2.urlopen(url)
                content1 = content1.read()
                content = re.search('#######',content)
                if content != None:
                    print "Website working correctly    [ OK ]"
                else :
                    print "Website content not correct   [ Mistake ]"
            except urllib2.HTTPError :
                print "Website is not working properly    [ Mistake ]"
        else :
            print "Check service status   [ Mistake ]"
    else :
        print "Semanage context of port 8999 is not correct    [ Mistake ]"



def check_nfs_server_config():
    print
    print
    print "Checking NFS Server side Configuration......".center(100)
    print
    print
    dir1 = '/public'
    dir2 = '/protected'
    config_file = '/etc/exports'
    nfs_version_file = '/etc/sysconfig/nfs'

    key_file = '/etc/krb5.keytab'

    nfs_file_content = subprocess.Popen("cat /etc/exports",shell=True,stdout=subprocess.PIPE)
    nfs_file_content_op = nfs_file_content.communicate()[0]

    public = re.search('/public\s+ro',nfs_file_content_op)
    protected = re.search('/protected\s+rw',nfs_file_content_op)
    protected_sec = re.search('/protected\s+krb5p',nfs_file_content_op)
    nfs_vers = subprocess.Popen('cat /etc/sysconfig/nfs | grep NFSDARG',shell=True,stdout=subprocess.PIPE)
    nfs_vers_op = nfs_vers.communicate()[0]
    version = re.search('4.2',nfs_vers_op)

    if os.path.isdir(dir1) and os.path.isdir(dir2) :
        if check_service('nfs_secure_server') and check_service('nfe_server') :
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
                                    print"NFS Server Side Configuration is correct    [ OK ]"
                                    print
                                    print
                                    print "Checking NFS client side Configuration........."
                                    check_nfs_client_config()
                                else :
                                    print"Server Side Configuration not correct (check Firewall)....Skiping checking client side config......   [ Mistake ] "
                            else :
                                print "NFS versionnot specified in /etc//sysconfig/nfs ....Skiping checking client side config......    [ Mistake ]"
                        else :
                            print "check kerberos config entry for protected share in /etc/exports   ....Skiping checking client side config......   [ Mistake ]"
                    else :
                        print "Check permissions of protected share in /etc/exports ....Skiping checking client side config......   [ Mistake ]"
                else :
                    print "Check permissions of public share in /etc/exports  ....Skiping checking client side config......   [ Mistake ]"
            else :
                print "Context of directories not correct  ....Skiping checking client side config......  [ Mistake ]"
        else :
            print "Check service status ....Skiping checking client side config......   [ Mistake ]"
    else :
        print "Directory does not exist  ....Skiping checking client side config......  [ Mistake ]"
                            
'''
def check_nfs_client_config():
    print
    print
    
    dir1 = '/mnt/public'
    dir2 = '/mnt/protected'

  '''  










#gen_ssh_key()
#checkEnvironment()
#check_selinux()
#check_script()
#ssh()
#port_fwd()
#check_alias()
#check_link_aggregation()
#check_samba_public()
#check_samba_multiuser()
