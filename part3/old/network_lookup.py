import socket
import ipaddress

def get_ip_address_and_subnet_mask(interface_name):
    try:
        ip_address = socket.inet_ntoa(socket.inet_aton(socket.gethostbyname(interface_name)))
        subnet_mask = socket.inet_ntoa(socket.inet_aton(socket.if_nameindex(interface_name)[0]))
        return ip_address, subnet_mask
    except (socket.gaierror, OSError):
        return None, None

# Replace 'eth0' with your actual network interface name
interface_name = 'eth0'
ip_address, subnet_mask = get_ip_address_and_subnet_mask(interface_name)

if ip_address and subnet_mask:
    network = ipaddress.IPv4Network(f'{ip_address}/{subnet_mask}', strict=False)
    print(f'Network: {network}')
    if network:
        num_hosts = network.num_addresses - 2  # Subtract 2 for network and broadcast addresses
        print(f'Number of Hosts: {num_hosts}')



    