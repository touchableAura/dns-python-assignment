from scapy.all import *
import socket  
import sys 

# dst_ip = "192.168.0.1"
print("\nNetwork Scanner\n")

ip_input_choice = input("Choose an option:\n"
                        "a) Use default IP\n"
                        "b) Enter a website URL\n"
                        "c) Enter an IP address\n"
                        "Select 'a', 'b', or 'c': ")

# Initialize the destination IP address variable
dst = ""

if ip_input_choice == "a":
    # Get the computer's IP address
    hostname = socket.gethostname()
    dst = socket.gethostbyname(hostname)
    print(dst)
    # dst = "192.168.0.1"   # <<<<<<<<< comment out for b and c ########
    print(f'\nUsing default IP address: {dst}')
elif ip_input_choice == "b":
    # Enter a website URL and resolve it to an IP address
    website_url = input("Please enter a website address: ")
    dst = socket.gethostbyname(website_url)
    print(f'The {website_url} IP Address is {dst}')
elif ip_input_choice == "c":
    # Enter an IP address directly
    dst = input("Enter an IP address: ")
    print(f'The IP Address is {dst}')

# Prompt the user for the scanning mode
scan_mode = input("Now, choose a scanning mode (ICMP or TCP): ").strip().lower()

# Check if the user input is valid
if scan_mode not in ["icmp", "tcp"]:
    print("Invalid scanning mode. Please choose either ICMP or TCP.")
else:
    if scan_mode == "icmp":
        "\n*********  ICMP Mode Started *********\n"
        # ICMP packet crafting *******************************************
        # dst = "192.168.0.1"   # <<<<<<<<< comment out for b and c ########
        # icmp_ip_hdr = IP()
        # eth_hdr = Ether()
        # icmp_pkt = IP() / Ether() 
        icmp_pkt = IP(src="192.168.0.1", dst="192.168.256.1") / ICMP()
        print("\n*********  ICMP packet generated *********\n")
        print(icmp_pkt.show(),"************************************\n\n") 

        # ICMP - tranmission ********************************************* # send/ receive responses using sr() function
        i_ans, i_unans = sr(icmp_pkt, timeout=10, retry=2)
          # # ICMP output ************************************************
        icmp_pkts = IP(dst=dst, id=50000, ttl=(1,45)) / ICMP(type=8)
        ans, unans = sr(icmp_pkts, timeout=30)
        print("\nicmp_pkts:", icmp_pkts, "\n icmp_pckts.show:", icmp_pkts.show,"\n")
        # ans, unans = sr(icmp_pkts, timeout=10)
        print(f"\nIP addresses communicating with {dst}.")
        print(ans.summary(lambda s,r : s.sprintf("%IP.ttl%") + "\t" + r.sprintf("%IP.src%")))
        pass
    elif scan_mode == "tcp":
        # TCP packet crafting ********************************************
        dst = "192.168.0.1"   # <<<<<<<<< comment out for b and c ########
        tcp_pkt = IP(dst=dst) / TCP(sport=RandShort(), dport=(1,1024), flags="S") / Ether()
        print("\n\nTCP packet generated  ************************  \n")
        print(tcp_pkt.show(),"**************************************\n\n")
        # TCP tramission  ************************************************
        t_ans, t_unans = sr(tcp_pkt, timeout=10, retry=2)
        # TCP output *****************************************************
        print(f"\nTCP Traceroute Scan with IP: {dst}")
        print(f"IP addresses communicating with {dst}.")
        print(t_ans.summary(lambda s,r : s.sprintf("%IP.ttl%") + "\t" + r.sprintf("%IP.src%")))
        tcp_pkts = IP(dst=dst, id=50000, ttl=(1,45)) / TCP(sport=RandShort(), dport=(1,1024), flags="S")
        print("\ntcp_pkts:", tcp_pkts,"\n")
        pass
