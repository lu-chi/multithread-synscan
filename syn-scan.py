#!/usr/bin/env python

import argparse
from threading import *
from scapy.all import *


screenLock = Semaphore(value=1)
count = []

def SYN_SCAN(SYN_dst, SYN_sport, SYN_dport):
	
	try:
		ip = IP(dst = SYN_dst)
		
		if SYN_sport == 0:
			SYN_sport = RandNum(1024,65535)
		
		tcp = TCP(sport = SYN_sport, dport = SYN_dport, flags = "S")	
		mypacket = ip/tcp
		ans,unans = sr(mypacket, retry=-2, timeout=1)
		screenLock.acquire()
		print("[!] Scanning %s, port %d") % (SYN_dst, SYN_dport)
		print "[+] Answered:", ans.show()
		#print resp.show()
		#print "[-] Unanswered: ", unans.summary() 
		#for snd,rcv in ans:
    		#	snd.summary()
		#	rcv.summary()
	except:
		screenLock.acquire()
		print "[-] tcp %d closed." % SYN_dport
	finally:
		screenLock.release()


def shut_app():
	exit(0)


def main():
	# parsing cmdline args
	parser = argparse.ArgumentParser("<options>", version="version 1.0 by Lukas\'2013")
	parser.add_argument("-H", "--host", dest="hostname", default="127.0.0.1",  help="use specified ip address")
	parser.add_argument("-p","--port", dest="portnum", default=80, nargs='+', type=int, action="store", help="use specified port or ports separated by space")
	
	args = parser.parse_args()
	#if len(args) != 2:
	#	parser.error("[-]Incorrect number of arguments!")
	ip_add = args.hostname
	count = args.portnum

	try:
		for i in count:
			print("[+] Scanning %s, port %d") % (ip_add, i)
			t = Thread(target=SYN_SCAN, args=(ip_add,0,i))
			t.start()
	except KeyboardInterrupt:
		 exit(0)

if __name__ == "__main__":
	main()


