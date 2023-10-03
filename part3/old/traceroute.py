from scapy.all import *
import socket  

print("\n\nNetwork Scanner\n\n")

ip_input_choice = input("what IP address do you want to use?\na) use default\nb) enter URL\nc) enter IP address\nSelect 'a', 'b', or 'c'")


if ip_input_choice not in ["a", "b", "c"]:
    print("Invalid option. Please choose either a, b or c.")
else:
    if ip_input_choice == "a":
        dst = "192.168.0.1"
        print(f'The IP Address is {dst}')
        pass
    elif ip_input_choice == "b":
        dst = input("Please enter website address:\n")
        # IP lookup from hostname
        print(f'The {dst} IP Address is {socket.gethostbyname(dst)}')
        pass
    elif ip_input_choice == "c":
        dst = input("enter an IP address: ")
        print(f'The IP Address is {dst}')
        pass
        
        return dst


# # print("\n\nNetwork Scanning")
# # dns = socket.gethostbyname("cbc.ca")
# # print("ICMP Scan of cbc.ca")
# # print("dns:", dns, "\n") # 23.192.62.36
# # dst_ip = socket.gethostbyname("cbc.ca")


# dst_ip = "192.168.0.1"

# print(f"\n\n network being scanned: {dst_ip}\n\n")

# # ***************************************************
# # ***************************************************
# # ****************** ICMP SCAN **********************
# # ***************************************************
# # ***************************************************

# # ICMP packet crafting ******************************
# icmp_ip_hdr = IP()
# eth_hdr = Ether()
# icmp_pkt = eth_hdr / icmp_ip_hdr 
# print("**********  ICMP packet  **********\n")
# print(icmp_pkt.show(),"**********  ICMP packet  **********\n\n") 
# # ICMP - tranmission ********************************
# # send ICMP packets using sr() function
# i_ans, i_unans = sr(icmp_pkt, timeout=10, retry=2)
# # summarize answered packets with source port flags
# i_ans.summary(lambda s,r:r.sprintf("%ICMP.sport% - %ICMP.flags%"), lfilter=lambda s,r:True if (r.sprintf("%ICMP.flags%")) == "SA" else False)
# print(f"\nICMP Scan - {dst_ip}")
# icmp_pkts = IP(dst=dst_ip, id=50000, ttl=(1,45)) / ICMP(type=8)
# # ICMP output ***************************************
# ans, unans = sr(icmp_pkts, timeout=10)
# print(f"IP addresses communicating with {dst_ip}.")
# print(ans.summary(lambda s,r : s.sprintf("%IP.ttl%") + "\t" + r.sprintf("%IP.src%")))


# # TCP packet crafting *******************************
# tcp_pkt = IP(dst="192.168.0.1") / TCP(sport=RandShort(), dport=(1,1024), flags="S")
# print("\n\n**********  TCP packet  **********\n")
# print(tcp_pkt.show(),"**********  TCP packet  **********\n\n")
# # TCP tramission  ***********************************
# t_ans, t_unans = sr(tcp_pkt, timeout=10, retry=2)
# # TCP output ****************************************
# t_ans.summary(lambda s,r:r.sprintf("%TCP.sport% - %TCP.flags%"), lfilter=lambda s,r:True if (r.sprintf("%TCP.flags%")) == "SA" else False)


# # print("\n\nNetwork Scanning")
# # dns = socket.gethostbyname("cbc.ca")
# # print("ICMP Scan of cbc.ca")
# # print("dns:", dns, "\n") # 23.192.62.36
# # dst_ip = socket.gethostbyname("cbc.ca")

# # ***************************************************
# # ***************************************************
# # ******************** TCP Scan *********************
# # ***************************************************
# # ***************************************************
# # print("\n\n")
# print(f"TCP Scan - {dst_ip}")
# tcp_pkts = IP(dst=dst_ip) / TCP(sport=RandShort(), dport=(1,1024), flags="S")
# ans, unans = sr(tcp_pkts, timeout=10)
# print(f"IP addresses on the way to {dst_ip}.")
# print(ans.summary(lambda s,r : s.sprintf("%IP.ttl%") + "\t" + r.sprintf("%IP.src%")))