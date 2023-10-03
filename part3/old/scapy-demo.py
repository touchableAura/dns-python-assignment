from scapy import *

# packets are objects 
# the / operator is used to stack packets

packet = IP() / TCP()
Ether() / packet 

# ls() function list packets fields 
print(ls(IP, verbose=True))

# Scapy selects the correct source 
# IPv4 addresses, MAC addresses...

