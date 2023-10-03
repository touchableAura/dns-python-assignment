import socket
import ipaddress
from scapy.all import *

def scan_network(dst_subnet):
    responding_ips = []

    subnet = ipaddress.IPv4Network(dst_subnet)

    icmp_pkt = IP() / ICMP()

    for ip in subnet.hosts():
        icmp_pkt.dst = str(ip)
        response = sr1(icmp_pkt, timeout=1, verbose=False)
        if response:
            responding_ips.append(str(ip))

    return responding_ips

if __name__ == "__main__":
    print("\nNetwork Scanner\n")
    ip_input_choice = input("Choose an option:\n"
                            "a) Use default IP\n"
                            "b) Enter a website URL\n"
                            "c) Enter an IP address or subnet\n"
                            "Select 'a', 'b', or 'c': ")

    dst_subnet = "192.168.0.0/24"  # Default subnet

    if ip_input_choice == "b":
        website_url = input("Please enter a website address: ")
        dst = socket.gethostbyname(website_url)
        print(f'The {website_url} IP Address is {dst}')
    elif ip_input_choice == "c":
        while True:
            dst_subnet = input("Enter an IP address or subnet (e.g., 192.168.0.0/24): ")
            try:
                ipaddress.IPv4Network(dst_subnet)
                break  # Valid input, exit the loop
            except ValueError:
                print("Invalid IP address or subnet format. Please try again.")

    print(f'Using IP Address or Subnet: {dst_subnet}')

    scan_mode = input("Now, choose a scanning mode (ICMP or TCP): ").strip().lower()

    if scan_mode not in ["icmp", "tcp"]:
        print("Invalid scanning mode. Please choose either ICMP or TCP.")
    else:
        if scan_mode == "icmp":
            responding_ips = scan_network(dst_subnet)
            if responding_ips:
                print("Responding IP addresses:")
                for ip in responding_ips:
                    print(ip)
            else:
                print("No IP addresses responded to ICMP requests.")
        elif scan_mode == "tcp":
            tcp_pkt = IP(dst=dst) / TCP(sport=RandShort(), dport=(1,1024), flags="S") / Ether()
            print("\n\nTCP packet generated  ************************  \n")
            print(tcp_pkt.show(),"**************************************\n\n")
            t_ans, t_unans = sr(tcp_pkt, timeout=10, retry=2)
            print(f"\nTCP Traceroute Scan with IP: {dst}")
            print(f"IP addresses communicating with {dst}.")
            print(t_ans.summary(lambda s,r : s.sprintf("%IP.ttl%") + "\t" + r.sprintf("%IP.src%")))
            tcp_pkts = IP(dst=dst, id=50000, ttl=(1,45)) / TCP(sport=RandShort(), dport=(1,1024), flags="S")
            print("\ntcp_pkts:", tcp_pkts,"\n")











# import socket
# import ipaddress
# import sys
# import re
# import os
# from scapy.all import *

# def get_default_gateway_ip():
#     try:
#         # Create a socket object
#         sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
#         # Connect to a known external server
#         sock.connect(("8.8.8.8", 80))
        
#         # Get the local IP address, which should be the default gateway
#         default_gateway = sock.getsockname()[0]
        
#         return default_gateway
#     except Exception as e:
#         print(f"Error while getting default gateway IP: {str(e)}")
    
#     return None

# def scan_network(dst_subnet):
#     results = []

#     ip_list = []

#     ip_list.append("192.168.0.1")

#     subnet = ipaddress.IPv4Network("192.168.0.0/24")
#     ip_list.extend([str(ip) for ip in subnet])

#     # ICMP packet crafting
#     icmp_pkt = IP() / ICMP()

#     for ip in ip_list:
#         icmp_pkt.dst = ip
#         response = sr1(icmp_pkt, timeout=1, verbose=False)
#         if response:
#             results.append((ip, response.summary()))

#     return results

# # Get the computer's IP address
# default_gateway = get_default_gateway_ip()

# if default_gateway is not None:
#     print(f'\nUsing default IP address: {default_gateway}')
#     dst_subnet = ".".join(default_gateway.split(".")[:3])  # Get the subnet from the default gateway IP
# else:
#     print("Unable to determine the default gateway's IP address. Please provide a specific IP address.")
#     dst_subnet = input("Enter an IP address or subnet to scan: ")

# print("\nNetwork Scanner\n")

# ip_input_choice = input("Choose an option:\n"
#                         "a) Use default IP\n"
#                         "b) Enter a website URL\n"
#                         "c) Enter an IP address\n"
#                         "Select 'a', 'b', or 'c': ")

# dst = ""

# if ip_input_choice == "a":
#     dst = default_gateway
#     print(f'\nUsing default IP address: {dst}')
# elif ip_input_choice == "b":
#     website_url = input("Please enter a website address: ")
#     dst = socket.gethostbyname(website_url)
#     print(f'The {website_url} IP Address is {dst}')
# elif ip_input_choice == "c":
#     dst = input("Enter an IP address: ")
#     print(f'The IP Address is {dst}')

# scan_mode = input("Now, choose a scanning mode (ICMP or TCP): ").strip().lower()

# if scan_mode not in ["icmp", "tcp"]:
#     print("Invalid scanning mode. Please choose either ICMP or TCP.")
# else:
#     if scan_mode == "icmp":
#         dst_subnet = ".".join(dst.split(".")[:3])
#         results = scan_network(dst_subnet)
#         for ip, summary in results:
#             print(f"IP Address: {ip}, Response: {summary}")
#     elif scan_mode == "tcp":
#         tcp_pkt = IP(dst=dst) / TCP(sport=RandShort(), dport=(1,1024), flags="S") / Ether()
#         print("\n\nTCP packet generated  ************************  \n")
#         print(tcp_pkt.show(),"**************************************\n\n")
#         t_ans, t_unans = sr(tcp_pkt, timeout=10, retry=2)
#         print(f"\nTCP Traceroute Scan with IP: {dst}")
#         print(f"IP addresses communicating with {dst}.")
#         print(t_ans.summary(lambda s,r : s.sprintf("%IP.ttl%") + "\t" + r.sprintf("%IP.src%")))
#         tcp_pkts = IP(dst=dst, id=50000, ttl=(1,45)) / TCP(sport=RandShort(), dport=(1,1024), flags="S")
#         print("\ntcp_pkts:", tcp_pkts,"\n")
