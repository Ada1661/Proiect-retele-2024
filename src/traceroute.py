import requests
import socket
import traceback
import random
import time

print('Starting script...')

# def limite si timeout
limit = 30 # TTL max, nr max de hop-uri
timeout = 3 # timpul max de asteptare pt un raspuns

# fct pt obtinerea locatiei unui IP folosind ip-api
def get_location(ip):
    try:
        print(f'Getting location for IP: {ip}')
        # facem o cerere HTTP catre ip-api pt a obtine locatia IP-ului
        response = requests.get(f'http://ip-api.com/json/{ip}')
        # code 200 == request reusit
        if response.status_code == 200:
           data = response.json()
           # retinem datele cautate daca s-a facut extragerea cu succes
           if data['status'] == 'success':
              city = data['city']
              region = data['region']
              contry = data['country']
              return city, region, country
    # pt cazul in care extragerea nu a putut fi facuta
    except Exception as e:
        print(f'Error fetching location for IP {ip}: {e}')
    return None, None, None

# fct pt afisarea locatiei unui IP si scrierea acesteia in fisier   
def print_location(ip):
    global f
    data = get_location(ip)
    if all(d is not None for d in data):
        f.write(f'{ip} | {data[0]} - {data[1]}, {data[2]}\n')
    else:
        f.write(f'{ip} | Invalid Location!\n')
        
def out_location():
    for route in routes:
        print_location(route)
        
# fct pt generarea unui port random intre valorile specificate
def random_port():
    return random.randint(33434, 33534)

# fct principala de traceroute
def traceroute(ip, port, hop_count = 1):
    # timpul de start pt a masura durata
    start_time = time.time()
    # setam TTL pt socketul UDP in header-ul de IP
    TTL = hop_count
    if hop_count > limit:
        return
    udp_send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, TTL)
    
    # trimitem un mesaj UDP catre un tuplu (IP, port)
    udp_send_sock.sendto(b'salut', (ip, port))
    
    try:
        # data = datele primite prin socket
        # addr = adresa asociata datelor primite, ip, port
        # asteptam un raspuns ICMP
        data, addr = icmp_recv_socket.recvfrom(63535)
        # timpul de final pt a masura durata
        end_time = time.time()
    except socket.timeout:
        # daca se produce un timeout afisam * * *
        print(f'{hop_count} * * *')
        # incrementam hop_count si reincercam
        return traceroute(ip, random_port(), hop_count + 1)
    except Exception as e:
        print(f'Exception: {e}')
        return
        
    # memoram IP-ul returnat
    # adresa intoarce un tuplu (ip, port)
    current_ip = addr[0]
    # primul byte din headerul ICMP
    first_byte = data[20]

    # verificam daca pachetul este ICMP "Time Exceeded" sau am ajuns la destinatie
    if first_byte != 11 or current_ip == ip:
        return

    # adaugam IP-ul la lista de rute
    routes.append(current_ip)
    
    # calculam durata in milisecunde
    duration_ms = round((end_time - start_time) * 1000, 2)

    print(f'IP:{addr[0]} TTL:{TTL} Hops: {hop_count} {duration_ms} ms')
    
    # continuam cu uramatorul hop
    traceroute(ip, random_port(), hop_count + 1)

# in lista astea pastram IP-urile prin care trec pachetele
routes = []
#f = open('traceroute.txt', 'w')
try:
    f = open('traceroute.txt', 'w')
    print('File opened succesfully.')
except Exception as e:
    print(f'Failed to open file: {e}')


# cream un socket de tip UDP pt trimiterea pachetelor
udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# cream socketul RAW pt primirea pachetelor ICMP
icmp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

# setam timeout pt socketul ICMP
icmp_recv_socket.settimeout(timeout)

# executam fct traceroute pt un IP de test
#traceroute('google.com', random_port(), 1)
print('Starting traceroute...')
traceroute('google.com', random_port(), 1)

out_location()

f.close()
print('File closed.')
udp_send_sock.close()
icmp_recv_socket.close()
print('Sockets closed.')
