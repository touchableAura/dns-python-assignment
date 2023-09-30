from scapy.all import *

# create internet protocol packet 
print("\ncreate internet protocol packet\n")
# ip_hdr = IP()
# print(ip_hdr.show())
ip_hdr = IP(dst="192.168.2.0/24")
print(ip_hdr.show())

udp_hdr = UDP() # create a UDP packet
print("\ncreate udp packet\n")
print(udp_hdr.show())
eth_hdr = Ether() # create an ethernet packet
print("\ncreate ethernet packet\n")
print(eth_hdr.show())
pkt = eth_hdr /  ip_hdr / udp_hdr # packet assembled

print("-"*46 + "\n"+"* * * * *  packet assembled * * * * * \n" + "-"*46)


# pkt[IP].src = "192.168.1.45"
print(pkt.show())
print("-"*46 + "\n"+" ^ pkt.show() ^\n" + "-"*46)

# use ICMP and TCP to assemble packets 
# send the packets to 

# create an ip address

pkt = IP(src = "", dst = "") / ICMP()

req_resp = sr(pkt)
req_resp[0].show()




