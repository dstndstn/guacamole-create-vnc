#! /usr/bin/python3
import sys
import os
import subprocess

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
p = subprocess.run(cmd, capture_output=True, input=passwd, shell=True)
print('Return code from tigervncpasswd:', p.returncode, 'stdout', p.stdout, 'stderr', p.stderr)

cmd = ['/usr/bin/tigervncserver', '-passwd', passwdfn]
p = subprocess.run(cmd, capture_output=True)
print('Result of tigervncserver:', p.stdout, 'return value', p.returncode)
