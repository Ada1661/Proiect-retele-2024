# importul bibliotecilor necesare
import base64  # pentru codificarea și decodificarea textului
import socket  # pentru comunicarea prin socket
import glob  # pentru cautarea de fisiere în directoare
import json  # pentru manipularea datelor JSON
import hashlib  # pentru calcularea hash-urilor MD5

# Crearea unui socket UDP pentru a primi cereri DNS
port = 53
ip = '127.0.0.1'
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, port))

# Functie pentru calculul checksum-ului unui fisier
def calculate_checksum(filename):
    md5_hash = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

# Functie pentru încarcarea datelor zonelor DNS din fisiere JSON
def load_zones():
    jsonzone = {}
    zonefiles = glob.glob('zones/*.zone')
    for zone in zonefiles:
        with open(zone) as zonedata:
            data = json.load(zonedata)
            zonename = data["$origin"]
            jsonzone[zonename] = data
    return jsonzone

zonedata = load_zones()

# Funcție pentru construirea setului de flaguri pentru răspunsul DNS
def getflags(flags):
    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])
    QR = '1'
    OPCODE = ''.join([str((ord(byte1) >> bit) & 1) for bit in range(1, 5)])
    AA = '1'
    TC = '0'
    RD = '0'
    RA = '0'
    Z = '000'
    RCODE = '0000'
    return int(QR + OPCODE + AA + TC + RD, 2).to_bytes(1, byteorder='big') + int(RA + Z + RCODE, 2).to_bytes(1, byteorder='big')

# Functie pentru extragerea domeniului 
def getquestiondomain(data):
    state = 0
    expectedlength = 0
    domainstring = ''
    domainparts = []
    x = 0
    y = 0
    for byte in data:
        if state == 1:
            if byte != 0:
                domainstring += chr(byte)
            x += 1
            if x == expectedlength:
                domainparts.append(domainstring)
                domainstring = ''
                state = 0
                x = 0
            if byte == 0:
                domainparts.append(domainstring)
                break
        else:
            state = 1
            expectedlength = byte
        y += 1
    questiontype = data[y:y + 2]
    return (domainparts, questiontype)

# Functie pentru construirea înregistrarii TXT pentru raspunsul DNS
def build_txt_record(text):
    rbytes = b'\xc0\x0c' + bytes([0]) + bytes([16]) + bytes([0]) + bytes([1]) + int(60).to_bytes(4, byteorder='big')
    rbytes += bytes([0, len(text)]) + text.encode()
    return rbytes

# Functie pentru construirea raspunsului DNS pentru cererea de fisier
def build_file_response(TransactionID, Flags, filename):
    QDCOUNT = b'\x00\x01'
    NSCOUNT = (0).to_bytes(2, byteorder='big')
    ARCOUNT = (0).to_bytes(2, byteorder='big')
    dnsbody = b''
    try:
        with open(filename, 'rb') as file:
            chunks = []
            while True:
                chunk = file.read(250)
                if not chunk:
                    break
                chunk_base64 = base64.b64encode(chunk).decode('utf-8')
                chunks.append(chunk_base64)
        
            checksum = calculate_checksum(filename)
            chunks.insert(0, checksum)
            ANCOUNT = len(chunks).to_bytes(2, byteorder='big')
            dnsheader = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT
            for chunk in chunks:
                dnsbody += build_txt_record(chunk)
        return dnsheader + dnsbody
    except FileNotFoundError:
        error_msg = "File not found."
        dnsbody += build_txt_record(base64.b64encode(error_msg.encode()).decode('utf-8'))
        ANCOUNT = (1).to_bytes(2, byteorder='big')
        dnsheader = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT
        return dnsheader + dnsbody

# Functie pentru construirea raspunsului DNS in functie de cererea primita
def buildresponse(data):
    TransactionID = data[:2]
    Flags = getflags(data[2:4])
    domain, questiontype = getquestiondomain(data[12:])
    if questiontype == b'\x00\x10' and domain[-2:] == ['tunnel', 'live']:
        filename = domain[0] + '.' + domain[1]
        return build_file_response(TransactionID, Flags, filename)
    else:
        return b''

#bucla pentru primirea și gestionarea cererilor DNS
while True:
    data, addr = sock.recvfrom(512)
    print(f"Received data: {data} from {addr}")
    r = buildresponse(data)
    print(f"Sending response: {r}")
    sock.sendto(r, addr)

