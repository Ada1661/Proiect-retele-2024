import socket, glob, json

# Definirea portului și adresei IP pentru legarea serverului DNS
port = 53
ip = '127.0.0.1'

# Crearea unui socket UDP
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, port))

def load_zones():
    """
    Încarcă datele zonei DNS din fișierele JSON din directorul 'zones'.
    """
    jsonzone = {}
    # Găsește toate fișierele cu extensia .zone în directorul 'zones'
    zonefiles = glob.glob('zones/*.zone')

    for zone in zonefiles:
        with open(zone) as zonedata:
            data = json.load(zonedata)  # Încarcă datele JSON din fișierul zonei
            zonename = data["$origin"]  # Obține originea zonei
            jsonzone[zonename] = data   # Adaugă datele zonei în dicționarul jsonzone
    return jsonzone

# Încarcă datele zonei
zonedata = load_zones()

def getflags(flags):
    """
    Generează flagurile pentru răspunsul DNS.
    """
    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])

    rflags = ''

    QR = '1'  # Query/Response (1 pentru răspuns)

    # Opcode - setat pe interogare standard
    OPCODE = ''
    for bit in range(1,5):
        OPCODE += str(ord(byte1) & (1 << bit))

    AA = '1'  # Authoritative Answer
    TC = '0'  # Truncation
    RD = '0'  # Recursion Desired

    # Byte 2

    RA = '0'  # Recursion Available
    Z = '000'  # Reserved
    RCODE = '0000'  # Response Code

    # Convertim flagurile în bytes și le returnăm
    return int(QR + OPCODE + AA + TC + RD, 2).to_bytes(1, byteorder='big') + int(RA + Z + RCODE, 2).to_bytes(1, byteorder='big')

def getquestiondomain(data):
    """
    Extrage domeniul interogat și tipul întrebării din datele DNS.
    """
    state = 0
    expectedlength = 0
    domainstring = ''
    domainparts = []
    x = 0
    y = 0
    for byte in data:
        if state == 1:
            if byte != 0:
                domainstring += chr(byte)  # Construiște stringul domeniului
            x += 1
            if x == expectedlength:
                domainparts.append(domainstring)  # Adaugă partea domeniului la listă
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

    # Tipul întrebării (A, TXT etc.)
    questiontype = data[y:y+2]

    return (domainparts, questiontype)

def getzone(domain):
    """
    Găsește datele zonei corespunzătoare domeniului interogat.
    """
    global zonedata
    zone_name = '.'.join(domain)
    return zonedata[zone_name]

def getrecs(data):
    """
    Obține înregistrările corespunzătoare din datele DNS.
    """
    domain, questiontype = getquestiondomain(data)
    qt = ''
    if questiontype == b'\x00\x01':
        qt = 'a'  # Tipul A

    zone = getzone(domain)

    return (zone[qt], qt, domain)

def buildquestion(domainname, rectype):
    """
    Construiește secțiunea de întrebare din răspunsul DNS.
    """
    qbytes = b''

    for part in domainname:
        length = len(part)
        qbytes += bytes([length])

        for char in part:
            qbytes += ord(char).to_bytes(1, byteorder='big')

    if rectype == 'a':
        qbytes += (1).to_bytes(2, byteorder='big')

    qbytes += (1).to_bytes(2, byteorder='big')

    return qbytes

def rectobytes(domainname, rectype, recttl, recval):
    """
    Convertește înregistrările DNS în bytes.
    """
    rbytes = b'\xc0\x0c'

    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes += int(recttl).to_bytes(4, byteorder='big')

    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([4])

        for part in recval.split('.'):
            rbytes += bytes([int(part)])
    return rbytes

def buildresponse(data):
    """
    Construiește răspunsul DNS pe baza întrebării primite.
    """
    # ID-ul tranzacției
    TransactionID = data[:2]

    # Obține flagurile
    Flags = getflags(data[2:4])

    # Numărul de întrebări
    QDCOUNT = b'\x00\x01'

    # Numărul de răspunsuri
    ANCOUNT = len(getrecs(data[12:])[0]).to_bytes(2, byteorder='big')

    # Numărul de Nameserver
    NSCOUNT = (0).to_bytes(2, byteorder='big')

    # Numărul de înregistrări suplimentare
    ARCOUNT = (0).to_bytes(2, byteorder='big')

    dnsheader = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    # Creează corpul răspunsului DNS
    dnsbody = b''

    # Obține răspunsul pentru interogare
    records, rectype, domainname = getrecs(data[12:])

    dnsquestion = buildquestion(domainname, rectype)

    for record in records:
        dnsbody += rectobytes(domainname, rectype, record["ttl"], record["value"])

    return dnsheader + dnsquestion + dnsbody

# Buclează la infinit pentru a răspunde la interogările DNS
while 1:
    data, addr = sock.recvfrom(512)  # Primește date de la client
    r = buildresponse(data)  # Construiește răspunsul
    sock.sendto(r, addr)  # Trimite răspunsul clientului

