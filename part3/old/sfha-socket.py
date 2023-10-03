# import socket

# def tcp_scan(target_ip, port):
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#             s.settimeout(1)  # Adjust the timeout as needed
#             s.connect((target_ip, port))
#         print(f"Port {port} on {target_ip} is open.")
#     except (socket.timeout, ConnectionRefusedError):
#         print(f"Port {port} on {target_ip} is closed.")

# # Example usage:
# target_subnet = "192.168.0.0/24"
# target_port = 80  # Change this to the desired port
# for i in range(1, 255):  # Scan IP addresses from 192.168.0.1 to 192.168.0.254
#     target_ip = f"{target_subnet[:-4]}.{i}"
#     tcp_scan(target_ip, target_port)


import socket
import ipaddress
from scapy.all import *

def scan_network(dst_subnet):
    responding_ips = []

    subnet = ipaddress.IPv4Network(dst_subnet)

    icmp_ip_hdr = IP(src="192.168.0.1")  # Set your machine's source IP

    for ip in subnet.hosts():
        icmp_ip_hdr.dst = str(ip)  # Set the destination IP to the current IP in the loop
        icmp_pkt = icmp_ip_hdr / ICMP()
        response = sr1(icmp_pkt, timeout=1, verbose=False)
        if response:
            responding_ips.append(str(ip))

    return responding_ips

# Usage
dst_subnet = "192.168.0.1/24"  # Example subnet to scan
responding_ips = scan_network(dst_subnet)

if responding_ips:
    print("Responding IP addresses:")
    for ip in responding_ips:
        print(ip)
else:
    print("No IP addresses responded to ICMP requests.")