import socket, glob, json

# definirea portului si adresei IP pentru legarea serverului DNS
port = 53
ip = '127.0.0.1' #'127.0.0.1'

# crearea unui socket UDP
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, port))

def load_zones():
    """
    incarca datele zonei DNS din fisierele JSON din directorul 'zones'.
    """
    jsonzone = {}
    # gaseste toate fisierele cu extensia .zone in directorul 'zones'
    zonefiles = glob.glob('zones/*.zone')

    for zone in zonefiles:
        with open(zone) as zonedata:
            data = json.load(zonedata)  # incarca datele JSON din fisierul zonei
            zonename = data["$origin"]  # obtine originea zonei
            jsonzone[zonename] = data   # adauga datele zonei in dictionarul jsonzone
    return jsonzone

# incarca datele zonei
zonedata = load_zones()

def getflags(flags):
    """
    genereaza flagurile pentru raspunsul DNS.
    """
    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])

    rflags = ''

    QR = '1'  # Query/Response (1 pentru raspuns)

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

    # convertim flagurile in bytes si le returnam
    return int(QR + OPCODE + AA + TC + RD, 2).to_bytes(1, byteorder='big') + int(RA + Z + RCODE, 2).to_bytes(1, byteorder='big')

def getquestiondomain(data):
    """
    extrage domeniul interogat si tipul intrebarii din datele DNS.
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
                domainstring += chr(byte)  # construiste stringul domeniului
            x += 1
            if x == expectedlength:
                domainparts.append(domainstring)  # adauga partea domeniului la lista
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

    # tipul intrebarii (A, TXT etc.)
    questiontype = data[y:y+2]

    return (domainparts, questiontype)

def getzone(domain):
    """
    gaseste datele zonei corespunzatoare domeniului interogat.
    """
    global zonedata
    zone_name = '.'.join(domain)
    return zonedata[zone_name]

def getrecs(data):
    """
    obtine inregistrarile corespunzatoare din datele DNS.
    """
    domain, questiontype = getquestiondomain(data)
    qt = ''
    if questiontype == b'\x00\x01':
        qt = 'a'  # tipul A

    zone = getzone(domain)

    return (zone[qt], qt, domain)

def buildquestion(domainname, rectype):
    """
    construieste sectiunea de intrebare din raspunsul DNS.
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
    converteste inregistrarile DNS in bytes.
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
    construieste raspunsul DNS pe baza intrebarii primite.
    """
    # ID-ul tranzactiei
    TransactionID = data[:2]

    # obtine flagurile
    Flags = getflags(data[2:4])

    # Numărul de întrebări
    QDCOUNT = b'\x00\x01'

    # numarul de raspunsuri
    ANCOUNT = len(getrecs(data[12:])[0]).to_bytes(2, byteorder='big')

    # numarul de Nameserver
    NSCOUNT = (0).to_bytes(2, byteorder='big')

    # numarul de inregistrari suplimentare
    ARCOUNT = (0).to_bytes(2, byteorder='big')

    dnsheader = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    # creeaza corpul raspunsului DNS
    dnsbody = b''

    # obtine raspunsul pentru interogare
    records, rectype, domainname = getrecs(data[12:])

    dnsquestion = buildquestion(domainname, rectype)

    for record in records:
        dnsbody += rectobytes(domainname, rectype, record["ttl"], record["value"])

    return dnsheader + dnsquestion + dnsbody

# bucleaza la infinit pentru a raspunde la interogările DNS
while 1:
    data, addr = sock.recvfrom(512)  # primeste date de la client
    r = buildresponse(data)  # construieste raspunsul
    sock.sendto(r, addr)  # trimite raspunsul clientului

