from scapy.all import *
import socket  
import sys

# ICMP SCANNER
print("\n network scanner running!\n")

# obtain ip address from url
user_url = input("enter a URL:\n")
dns = socket.gethostbyname(user_url)
print("user input:", user_url)
print("ip address:", dns)
print(f"preparing for ICMP Scan of {user_url} / {dns}")


print("*** mode 1: ICMP Scan ***")
# ICMP packet
icmp_pkt = IP(dst=dns)/ICMP()
icmp_pkt.show()
# ICMP ping - using sr 
ans, unans = sr(icmp_pkt, timeout=10)
# view responses
print("\nICMP Scan Summary")
ans.summary(lambda s,r: r.sprintf("%IP.src% is alive\n"))

print("\n\n*** mode 2: TCP Scan  ***")
# TCP packet 
tcp_pckt = IP(dst=dns)/TCP(dport=80,flags="S")
tcp_pckt.show()
# TCP ping
ans, unans = sr(tcp_pckt, timeout=10)
print("\nTCP Scan Summary")
ans.summary( lambda s,r : r.sprintf("%IP.src% is alive") )

print("\nport scanning\n")
res, unans = sr( IP(dst="192.168.1.1") /TCP(flags="S", dport=(1,1024)), timeout=10)
print("\nsummary of port scan")
res.nsummary( lfilter=lambda s,r: (r.haslayer(TCP) and (r.getlayer(TCP).flags & 2)) )



# print("test 1")
# ans, unans = sr(IP(dst="192.168.1.1",proto=(0,255))/"SCAPY",retry=2)
print("program ended")
# icmp_pkt = IP(dst="192.168.0.1")/ICMP()
# Sent 1 packet

print("\n\ntraceroute test:\n")
ans, unans = traceroute("4.2.2.1",l4=UDP(sport=RandShort())/DNS(qd=DNSQR(qname="dns")))




# sendp(Ether()/IP(dst="1.2.3.4",ttl=(1,4)), iface="eth1")
# sr(IP(dst="192.168.0.1")/ICMP())
