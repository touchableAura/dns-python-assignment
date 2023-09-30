import argparse
import ipaddress
from scapy.all import *

dns = socket.gethostbyname("nmap.scanme.org")
print(dns) #

ip_address = "24.89.237.110"


# Function to perform ICMP scan
def icmp_scan(network):
    live_hosts = []
    for ip in ipaddress.IPv4Network(network, strict=False):
        icmp = IP(dst=str(ip)) / ICMP()
        response = sr1(icmp, timeout=1, verbose=False)
        if response:
            live_hosts.append(ip)
    return live_hosts

# Function to perform TCP scan
def tcp_scan(network, port):
    live_hosts = []
    for ip in ipaddress.IPv4Network(network, strict=False):
        syn_packet = IP(dst=str(ip)) / TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=1, verbose=False)
        if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
            live_hosts.append(ip)
    return live_hosts

def main():
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("network", help="Network address to scan (e.g., 192.168.2.0/24)")
    parser.add_argument("mode", choices=["ICMP", "TCP"], help="Scan mode: ICMP or TCP")
    parser.add_argument("--port", type=int, help="Port to scan (required for TCP mode)")

    args = parser.parse_args()

    if args.mode == "ICMP":
        live_hosts = icmp_scan(args.network)
    elif args.mode == "TCP" and args.port is not None:
        live_hosts = tcp_scan(args.network, args.port)
    else:
        print("Invalid arguments.")
        return

    for host in live_hosts:
        print(host)

if __name__ == "__main__":
    main()


icmp_scan(ip_address)




# import socket
# from scapy.all import *

# dns = socket.gethostbyname("nmap.scanme.org")
# print(dns)

# pkts = IP(dst="45.33.32.156") / TCP(sport=RandShort(), dport=(1,1024), flags="S")

# ans, unans = sr(pkts, timeout=10, retry=2)