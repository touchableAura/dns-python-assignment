from scapy.all import *

# TCP Port Scan

# User Interface
# Choose IP Address
ip_address = input("\nEnter IP Address:\na) demo (45.33.32.156)\nb) default (192.168.0.1)\nc) custom (user input)\nenter: 'a', 'b' or 'c' and hit 'return:'")
ip_input = ""

if ip_address == "a":
    ip_input = "45.33.32.156"
    print(f"\nuser selected: {ip_input}\n")
    # ports to scan
    dport_input = input("Enter port number(s) to scan:\na) default (1,1024)\nb) custom (user input)\nc) more options (popular port suggestions)\nenter: 'a', 'b' or 'c' and hit 'return:'")
    if dport_input == "a":
        port_input = 1,1024
        print(f"\nscanning port(s): {port_input}\n")
    elif dport_input == "b":
        port_input = input("Enter port number(s): \n")
        print(f"\nuser selected: {port_input}\n")
    elif dport_input == "c":
        port_input = "not available right now"
elif ip_address == "b":
    ip_input = "192.168.0.1"
    print(f"\nuser selected: {ip_input}\n")
    # ports to scan
    dport_input =  input("Enter port number(s) to scan:\na) default (1,1024)\nb) custom (user input)\nc) more options (popular port suggestions)\nenter: 'a', 'b' or 'c' and hit 'return:'")
    if dport_input == "a":
        port_input = 1,1024
        print(f"\nscanning port(s): {port_input}\n")
    elif dport_input == "b":
        port_input = input("Enter port number(s)")
        print(f"\nuser selected: {port_input}\n")
    elif dport_input == "c":
        port_input = "not available right now"
elif ip_address == "c":
    ip_input = input("Enter custom IP Adress:\n")
    print(f"\nuser selected: {ip_input}\n")
    # ports to scan
    dport_input =  input("Enter port number(s) to scan:\na) default (1,1024)\nb) custom (user input)\nc) more options (popular port suggestions)\nenter: 'a', 'b' or 'c' and hit 'return:'")
    if dport_input == "a":
        port_input = 1,1024
        print(f"\nscanning port(s): {port_input}\n")
    elif dport_input == "b":
        port_input = input("Enter port number(s)")
        print(f"\nuser selected: {port_input}\n")
    elif dport_input == "c":
        port_input = "not available right now"

print(f"sending TCP SYN packets to port(s): {port_input} at ip address: {ip_input}\n")

# Packet crafting
tcp_pkts = IP(dst=ip_input) / TCP(sport=RandShort(), dport=(1, 1024), flags="S")
# un/comment to see example of TCP packet
print("example TCP packet contents\n")
tcp_pkts.show()
# Transmission
print("\n\n\n * * * ans, unans = sr(tcp_pkts, timeout=20, retry=2) *****sr()** TRANSMISSION ***\n")
ans, unans = sr(tcp_pkts, timeout=20, retry=2)

# Initialize a set to store unique responses
unique_responses = set()

# Loop through the responses and add unique IP addresses and port numbers to the set
for s, r in ans:
    unique_responses.add((r[IP].src, r[TCP].dport))

# Print the unique responses
print("\n\n * * *  IPADDRRESS:PORT * * * RESPONSES * ****\n")
print("OUTPUT ( ipaddresses:port# )\nresponses from TCP SYN packets:\n")
for response in unique_responses:
    print(f"{response[0]}:{response[1]}")
print("\n\n\n * * TCP SCAN * * * * COMPLETE *********\n")

# Print summary
print(f"\nSummary for TCP Scan\nIP Address: {ip_input}\nPort(s) scanned: {port_input}")
print(f"Total Port Responses: {len(unique_responses)}")
print("\n\n\n * * PROGRAM * * * * FINISHED *********\n")
