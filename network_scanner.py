import scapy.all as scapy
import subprocess
import ipaddress
import socket
import netifaces
import netaddr
from vendorsMacs import *
# This program is meant to scan the wifi network the computer is connected to
# Somewhat like fing


def addresses(interface):
    addrs = netifaces.ifaddresses(interface)
    addr = addrs[netifaces.AF_INET][0]['addr']
    mask = addrs[netifaces.AF_INET][0]['netmask']
    return addr,mask

def scan_ip(local_ip):
    #Creates ARP packets and sends them to all addresses in the specifies subnet
    #Returns a list of connected devices in the following format {"ip":IP, "mac":MAC}
    arp_req_frame = scapy.ARP(pdst = local_ip)
    broadcast_ether_frame = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff')
    broadcast_arp_frame = broadcast_ether_frame / arp_req_frame
    devices_on_network = scapy.srp(broadcast_arp_frame, timeout=1, verbose=False)[0]
    print(devices_on_network)
    parsed_devices = []
    print("There are " + str(len(devices_on_network)) + " devices on the network")
    for i in range(0, len(devices_on_network)):
        client_dict = {"ip" : devices_on_network[i][1].psrc, "mac" : devices_on_network[i][1].hwsrc}
        parsed_devices.append(client_dict)
    return parsed_devices

def print_devices(devices, vendorsMacs_dict):
    #Recieves the list of devices from scan_ip (and a dict of vendors),
    #prints the devices on screen (with vendor if found)
    print("--------Devices on Network--------")
    for device_dict in devices:
        try:
            vendor = vendorsMacs_dict[':'.join(device_dict["mac"].split(':', 3)[:3]).upper()]
            print("IP: " + device_dict["ip"] + "        MAC: " + device_dict["mac"] + " (" + vendor + ")")
        except:
            print("IP: " + device_dict["ip"] + "        MAC: " + device_dict["mac"] + " (Unknown)")

def get_hostnames(devices):
    for device in devices:
        ip = device["ip"]
        try:
            nslookup_output = subprocess.check_output(f"nslookup {ip}", shell=True)
            if "** server can't find" not in nslookup_output:
                print(f"{ip}: {nslookup_output}")
        except:
            print("hostname not found")

interface = str(subprocess.check_output("iw dev | awk '$1==\"Interface\"{print $2}'", shell=True))[2:-3]
print(f"Wireless interface: {interface}")
local_ip,subnet = addresses(interface)
print(f"Your machine's local IP: {local_ip}")
print(f"Your network's subnet mask: {subnet}")
cidr = netaddr.IPAddress(subnet).netmask_bits()
network_address = str(ipaddress.IPv4Interface(local_ip + '/' + str(cidr)).network)
print(f"Your network address is: {network_address}")
devices = scan_ip(network_address)
print_devices(devices, vendorsMacs_dict)
#get_hostnames(devices)
