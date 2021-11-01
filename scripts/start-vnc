#! /usr/bin/python3
import sys
import os
import subprocess

# first chdir to my home dir
homedir = os.path.expanduser('~')
os.chdir(homedir)

vncdir = os.path.expanduser('~/.vnc/')
if not os.path.exists(vncdir):
    try:
        os.makedirs(vncdir)
    except:
        pass
passwdfn = os.path.expanduser('~/.vnc/passwd-guac')
#print('Checking for', passwdfn)
#if not os.path.exists(passwdfn):
passwd = 'GUAC' #'SuperSecret'
passwd = passwd.encode()
cmd = '/usr/bin/tigervncpasswd -f > %s' % passwdfn
#p = subprocess.run(cmd, capture_output=True, input=passwd, shell=True)
p = subprocess.run(cmd, input=passwd, shell=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
print('Return code from tigervncpasswd:', p.returncode, 'stdout', p.stdout, 'stderr', p.stderr)

cmd = ['/usr/bin/tigervncserver', '-passwd', passwdfn]
#p = subprocess.run(cmd, capture_output=True)
p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
print('Result of tigervncserver:', p.stdout, 'return value', p.returncode)
