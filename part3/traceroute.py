from scapy.all import *
import socket  


# packet crafting

# [print("\n*** start ***\n\n")]
# ip_hdr = IP()
# print("ip_hdr.show()\n")
# print(ip_hdr.show())
# udp_hdr = UDP()
# eth_hdr = Ether()
# pkt = eth_hdr / ip_hdr /udp_hdr
# print("\n\nshow 1\n")
# print("pkt.show()", pkt.show())
# print("\n\nshow 2\n")
# pkt[IP].src = "192.168.0.14"
# print(pkt.show())

print("\n\n")

# ICMP packet crafting 
icmp_ip_hdr = IP()
eth_hdr = Ether()
icmp_pkt = eth_hdr / icmp_ip_hdr 
print("ICMP packet")
print(icmp_pkt.show(),"\n") 
# send ICMP packets using sr() function
i_ans, i_unans = sr(icmp_pkt, timeout=10, retry=2)
# summarize answered packets with source port flags
i_ans.summary(lambda s,r:r.sprintf("%ICMP.sport% - %ICMP.flags%"), lfilter=lambda s,r:True if (r.sprintf("%ICMP.flags%")) == "SA" else False)

# TCP packet crafting
tcp_pkt = IP(dst="192.168.0.1") / TCP(sport=RandShort(), dport=(1,1024), flags="S")
print("TCP packet")
print(tcp_pkt.show(),"\n")
# send TCP packets using sr() function
t_ans, t_unans = sr(tcp_pkt, timeout=10, retry=2)
# summarize answered packets with source port flags
t_ans.summary(lambda s,r:r.sprintf("%TCP.sport% - %TCP.flags%"), lfilter=lambda s,r:True if (r.sprintf("%TCP.flags%")) == "SA" else False)


# print("\n\nNetwork Scanning")
# dns = socket.gethostbyname("cbc.ca")
# print("ICMP Scan of cbc.ca")
# print("dns:", dns, "\n") # 23.192.62.36


# traceroute 

# dst_ip = socket.gethostbyname("cbc.ca")
dst_ip = "192.168.0.1"

# ICMP 
print(f"\nICMP Scan - {dst_ip}")
icmp_pkts = IP(dst=dst_ip, id=50000, ttl=(1,45)) / ICMP(type=8)
ans, unans = sr(icmp_pkts, timeout=10)
print(f"IP addresses communicating with {dst_ip}.")
print(ans.summary(lambda s,r : s.sprintf("%IP.ttl%") + "\t" + r.sprintf("%IP.src%")))

# TCP 
print("\n\n")
print(f"TCP Scan - {dst_ip}")
tcp_pkts = IP(dst=dst_ip) / TCP(sport=RandShort(), dport=(1,1024), flags="S")
ans, unans = sr(tcp_pkts, timeout=10)
print(f"IP addresses on the way to {dst_ip}.")
print(ans.summary(lambda s,r : s.sprintf("%IP.ttl%") + "\t" + r.sprintf("%IP.src%")))