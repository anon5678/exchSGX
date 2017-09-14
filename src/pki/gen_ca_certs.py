#!/bin/python

from subprocess import call

CMD = r'openssl req -nodes -newkey rsa:4096 -keyout %s -out %s -subj /C=US/ST=AB/O=exch/CN=%s'

for i in range(5):
    cmd = CMD % ('key%d.pem' % i, 'cert%d.pem' % i, 'CA%d' % i) 
    call(cmd.split())
