import socket  
import hashlib 
import base64 

def send_dns_request(filename, server_ip):
    # construirea unei interogari DNS
    domain = filename.split('.')[0] + '.tunel.live' 
    query = bytearray()
    query.extend(b'\xAA\xBB')  # ID-ul tranzactiei
    query.extend(b'\x01\x00')  
    query.extend(b'\x00\x01')  # QDCOUNT: 1 Intrebare
    query.extend(b'\x00\x00')  # ANCOUNT: 0 Raspuns
    query.extend(b'\x00\x00')  # NSCOUNT: 0 Inregistrari de servere de nume
    query.extend(b'\x00\x00')  # ARCOUNT: 0 Inregistrari suplimentare

    for part in domain.split('.'):
        query.append(len(part))
        for char in part:
            query.append(ord(char))
    query.extend(b'\x00')  # sfarsitul numelui de domeniu
    query.extend(b'\x00\x10')  # QTYPE: Inregistrare TXT
    query.extend(b'\x00\x01')  # QCLASS: IN

    # afisarea interogarii construite
    print(f"Cererea DNS construita: {query.hex()}")

    # trimiterea interogarii DNS
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        print(f"Trimiterea cererii catre {server_ip}:53")
        sock.sendto(query, (server_ip, 53))
        response, _ = sock.recvfrom(1024)  

    # depanare: Afisarea raspunsului primit
    print(f"Raspuns primit: {response.hex()}")
    return response

def save_file(response, filename):
    # parsarea raspunsului DNS pentru a extrage datele fisierului
    index = 12  # se sare peste antet
    qdcount = int.from_bytes(response[4:6], byteorder='big')
    ancount = int.from_bytes(response[6:8], byteorder='big')
    print(f"QDCOUNT: {qdcount}, ANCOUNT: {ancount}")

    # se sar întrebarile
    for _ in range(qdcount):
        while response[index] != 0:
            index += 1
        index += 5  # se sare peste byte-ul nul și QTYPE + QCLASS

    print({index})

    # procesarea raspunsurilor
    txt_data = bytearray()
    for _ in range(ancount):
        if response[index] == 0xc0:  # Pointer de nume
            index += 2
        else:
            while response[index] != 0:
                index += 1
            index += 1

        type = response[index:index + 2]
        index += 2
        clas = response[index:index + 2]
        index += 2
        ttl = response[index:index + 4]
        index += 4
        data_length = int.from_bytes(response[index:index + 2], byteorder='big')
        index += 2

        if type == b'\x00\x10':  # inregistrare TXT
            length = response[index]
            txt_data.extend(response[index + 1:index + 1 + length])
            index += 1 + length
            print( {txt_data})
        else:
            index += data_length

    if txt_data:
        decoded_data = base64.b64decode(txt_data)
        with open(filename, 'wb') as file:
            file.write(decoded_data)
        print(f"Fisierul {filename} a fost salvat.")
    else:
        print("TXT response not found")

def calculate_checksum(filename):
    md5_hash = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

# utilizare de exemplu
if __name__ == '__main__':
    server_ip = '127.0.0.1'  
    filename = 'retele.com.tunel.live'  
    response = send_dns_request(filename, server_ip)
    save_file(response, 'file.txt')


    reassembled_filename = 'file.txt'
    reassembled_checksum = calculate_checksum(reassembled_filename)
    print({reassembled_checksum})

