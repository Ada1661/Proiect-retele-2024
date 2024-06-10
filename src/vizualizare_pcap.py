from scapy.all import rdpcap

# numele fisierului .pcap
pcap_file = '198.7.0.2_capture.pcap'

# citim fisierul
print(f'Citire fisier .pcap: {pcap_file}')
packets = rdpcap(pcap_file)

print(f'Numar de pachete capturate: {len(packets)}')

# parcurge si afiseaza fiecare pachet
for i, packet in enumerate(packets):
    print(f'Pachet {i + 1}')
    print(packet.show())
    print('\n' + '-' * 50 + '\n')
