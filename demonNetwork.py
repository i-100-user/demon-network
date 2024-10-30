#!/usr/bin/env python3
from scapy.all import ARP,Ether,srp
import pyfiglet
#------------------------------------------------------------------------
def print_ascii_banner(text):
    ascii_banner = pyfiglet.figlet_format(text)
    print(ascii_banner)

def scan_network(ip):
    target_ip = f"{ip.rsplit('.', 1)[0]}.0/24"
    print(f"Escaneando el rango: {target_ip}")

    arp    = ARP(pdst=target_ip)
    ether  = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    if devices:
        print("Dispositivos activos en la red:")
        for device in devices:
            print(f"IP: {device['ip']}, MAC: {device['mac']}")
    else:
        print("No se encontraron dispositivos activos en la red.")
#-------------------------------------------------------------------------
print_ascii_banner("Network Scanner")
user_ip = input("Introduce tu IP --> ") 
scan_network(user_ip)
