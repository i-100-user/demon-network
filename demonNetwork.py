#!/usr/bin/env python3
from scapy.all import ARP,Ether,srp
import pyfiglet

# Función para mostrar el banner en ASCII
def print_ascii_banner(text):
    ascii_banner = pyfiglet.figlet_format(text)
    print(ascii_banner)

# Función para escanear el segmento de red
def scan_network(ip):
    # Configura el rango de red /24
    target_ip = f"{ip.rsplit('.', 1)[0]}.0/24"
    print(f"Escaneando el rango: {target_ip}")

    # Crea la solicitud ARP
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Envía el paquete y recibe la respuesta
    result = srp(packet, timeout=2, verbose=0)[0]

    # Procesa la respuesta y muestra dispositivos activos
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    # Muestra los dispositivos activos
    if devices:
        print("Dispositivos activos en la red:")
        for device in devices:
            print(f"IP: {device['ip']}, MAC: {device['mac']}")
    else:
        print("No se encontraron dispositivos activos en la red.")

# Muestra el banner y solicita la IP del usuario
print_ascii_banner("Network Scanner")
user_ip = input("Introduce tu IP --> ")  # Solicita la IP sin animación
scan_network(user_ip)

