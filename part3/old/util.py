import psutil
import socket

# def get_network_info():
#     network_info = psutil.net_if_addrs()

#     for interface, addresses in network_info.items():
#         print(f"Interface: {interface}")
#         for addr in addresses:
#             if addr.family == socket.AF_INET:
#                 print(f"  IPv4 Address: {addr.address}")
#                 print(f"  Netmask: {addr.netmask}")
#                 print(f"  Broadcast Address: {addr.broadcast}")
#             elif addr.family == socket.AF_INET6:
#                 print(f"  IPv6 Address: {addr.address}")
#             elif addr.family == psutil.AF_LINK:
#                 print(f"  MAC Address: {addr.address}")
#         print()

# import module
import subprocess
  
# Traverse the ipconfig information
data = subprocess.check_output(['ipconfig','/all']).decode('utf-8').split('\n')
  
# Arrange the bytes data
for item in data:
     print(item.split('\r')[:-1])


