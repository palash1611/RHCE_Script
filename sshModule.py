import sys
import paramiko

try:
    hostname, username, password, targetpath = sys.argv[1:5]
except ValueError:
    print("Failed, call with hostname username password targetpath")

command = "cd {};pwd".format(targetpath)
print("Command to send: {}".format(command))

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(hostname=hostname, username=username, password=password)
stdin, stdout, stderr = ssh.exec_command("cd {};pwd".format(targetpath))
print(stdout.read())
ssh.close()
