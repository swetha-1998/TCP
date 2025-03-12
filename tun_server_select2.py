#!/usr/bin/env python3

import fcntl
import struct
import os
from scapy.all import *

IP_A = "0.0.0.0"
PORT = 9090


TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create a tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)
ifname  = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

# Set up the tun interface and routing
os.system("ip addr add 192.168.53.1/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

# Set up routing
os.system("ip route add 192.168.50.0/24 dev {}".format(ifname))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))

fds = [sock, tun]
ip = '10.9.0.5'
port = 10000

while True:
  # this will block until at least one socket is ready
  ready, _, _ = select.select(fds, [], []) 

  for fd in ready:
    if fd is sock:
       print("sock ....")
       data, (ip, port) = sock.recvfrom(2048) 
       pkt = IP(data)
       print("{}:{} --> {}:{}".format(ip, port, IP_A, PORT))
       print("   Inside Tunnel: {} --> {}".format(pkt.src, pkt.dst))
       os.write(tun, data)

    if fd is tun:
       print("tun ....")
       packet = os.read(tun, 2048)
       pkt = IP(packet)
       print("Return: {} --> {}".format(pkt.src, pkt.dst))
       sock.sendto(packet, (ip, port))

