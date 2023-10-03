from scapy.all import *
import ipaddress  # Import the ipaddress module

# Get the computer's IP address
hostname = socket.gethostname()
print("hostname:",hostname)


# # Function to send ICMP echo request and print IP addresses on response
# def send_icmp_echo_requests(start_ip, end_ip):
#     responding_ips = []

#     # Create an ICMP echo request packet
#     icmp_pkt = IP() / ICMP()

#     # Loop through the IP range and send ICMP echo requests
#     for ip in ipaddress.IPv4Network(f"{start_ip}/{end_ip}", strict=False):
#         current_ip = str(ip)
#         icmp_pkt.dst = current_ip
#         response = sr1(icmp_pkt, timeout=1, verbose=False)
#         if response:
#             responding_ips.append(current_ip)

#     return responding_ips

# if __name__ == "__main__":
#     start_ip = "192.168.0.1"
#     end_ip = "192.168.0.24" # Corrected end IP address"

#     print("Sending ICMP echo requests to IP addresses between {} and {}...".format(start_ip, end_ip))
    
#     responding_ips = send_icmp_echo_requests(start_ip, end_ip)

#     if responding_ips:
#         print("\nResponding IP addresses:")
#         for ip in responding_ips:
#             print(ip)
#     else:
#         print("\nNo IP addresses responded to ICMP echo requests.")
