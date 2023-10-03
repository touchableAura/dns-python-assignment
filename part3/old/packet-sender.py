from scapy.all import *
import socket 

# info about setup:
# Network info from ipcongfig
# Ethernet adapter Ethernet:
#    Connection-specific DNS Suffix  . :
#    Link-local IPv6 Address . . . . . : fe80::e0c7:5f81:f1cf:b474%15
#    IPv4 Address. . . . . . . . . . . : 192.168.0.14
#    Subnet Mask . . . . . . . . . . . : 255.255.255.0
#    Default Gateway . . . . . . . . . : 192.168.0.1



print("\nICMP Scan\n")

# ICMP mode - echo packet requrests
# create ICMP packet
icmp_packet = IP(src = "192.168.0.14", dst = "192.168.0.1") / ICMP()

# send the ICMP packet using sr() function
req_resp = sr(icmp_packet) #sr to send and receive packet
req_resp[0].show() # show details of the response packet
print("\n")


#ICMP - recording IP addresses communicating with destination IP
# goal: to record unique IPs that responded to the sent packets. 
# each IP printed on its own line 
icmp_dst_ip = "192.168.0.1"
pkts = IP(dst=icmp_dst_ip, id=50000) / ICMP(type=8) 
ans, unans = sr(pkts)

#show the answered packets
print("\nanswered packets from ICMP Scan\n")
ans.show()

print(f"IP Addresses on the way to {icmp_dst_ip}.")
print(ans.summary(lambda s,r : s.sprintf("%IP.ttl%") + "\t" + r.sprintf("%IP.src%")))

print("\n\n TCP Scan\n")


#TCP mode - send TCP SYN packets to a port
# create TCP packet
tcp_packet = IP(dst="192.168.0.14") / TCP(sport=RandShort(), dport=(1,1024), flags="S")
tcp_packet.show()

# send TCP packets using sr() function
ans, unans = sr(tcp_packet, timeout=10, retry=2)

# summarize answered packets with source port flags
ans.summary(lambda s,r:r.sprintf("%TCP.sport% - %TCP.flags%"), lfilter=lambda s,r:True if (r.sprintf("%TCP.flags%")) == "SA" else False)

