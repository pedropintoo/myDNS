'''
# DNS Header from RFC 1035 for reference:
#                                     1  1  1  1  1  1
#       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+To Decimal
#     |                      ID                       | # Transaction ID
#     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   | # Flags
#     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#     |                    QDCOUNT                    |From Hex
#     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#     |                    ANCOUNT                    |
#     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#     |                    NSCOUNT                    |
#     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#     |                    ARCOUNT                    |
#     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
'''
import socket, glob, json



def recToBytes(domainNamePosition, recType, recttl, recval):
    
    # Position of domain Name - Compression
    compression = int(1<<15) + int(1<<14) + domainNamePosition # '11' + Offset
    
    rBytes = compression.to_bytes(2, byteorder='big')
    
    
    if recType == 'a':
        rBytes = rBytes + b'\x00\x01'
    
    rBytes = rBytes + b'\x00\x01' 
    
    rBytes = rBytes + int(recttl).to_bytes(4, byteorder='big')
    
    if recType == 'a':
        rBytes = rBytes + b'\x00\x04'  # data is stored in 4 bytes
    
        for part in recval.split('.'):
            rBytes += bytes([int(part)])
    
    return rBytes

def getZone(domain):
    global zoneData
    
    zone_name = '.'.join(domain) + '.' # like: 'howcode.org.'
    return zoneData[zone_name]

def getQuestionDomain(data):
    
    state = 0
    expectedLength = 0
    domainString = ''
    domainParts = []
    x = 0
    dataIndex = -1
    
    for byte in data:
        if state == 1:
            domainString += chr(byte)
            x += 1
            if x == expectedLength:
                domainParts.append(domainString) # when a part of a string ends
                domainString = ''
                state = 0
                x = 0
            if byte == 0:
                domainParts.append(domainString) # when the string ends \x00
                break
        else:
            state = 1
            expectedLength = byte

        dataIndex += 1
            
    questionType = data[dataIndex+1:dataIndex+3] # like: '.org'

    return (domainParts[:-1], questionType)

def getRecs(data):
    # Answer Code
    domain, questionType = getQuestionDomain(data)

    qt = ''
    if questionType == b'\x00\x01': # type A
        qt = 'a'
    
    zone = getZone(domain)
    
    return (zone[qt], qt, domain)

def getFlags(flags):
    
    byte1 = bytes(flags[0])
    byte2 = bytes(flags[1])
    
    responseFlags = ''
    
    QR = '1'
    Opcode = ''
    for bit in range(1,5): # 1, 2, 3, 4 bits
        Opcode += str(ord(byte1)&(1<<bit)) # bitwise!
    AA = '1'
    TC = '0'    # always requests small than 512 bytes
    RD = '0'
    RA = '0'
    Z = '000'
    RCODE = '0000'
    
    return int(QR+Opcode+AA+TC+RD, 2).to_bytes(1, byteorder='big')+int(RA+Z+RCODE, 2).to_bytes(1, byteorder='big')

def buildQuestion(domainName, recType):
    qBytes = b''
    
    for part in domainName:
        length = len(part)
        qBytes += bytes([length])
        
        for char in part:
            qBytes += ord(char).to_bytes(1, byteorder='big')
    
    qBytes += b'\x00' # end of word

    if recType == 'a':
        qBytes += (1).to_bytes(2, byteorder='big')
    
    qBytes += (1).to_bytes(2, byteorder='big') # IN class (almost every time..)
    
    return qBytes
    
def buildResponse(data):
    
    # Transaction ID
    transactionID = data[:2] # first two bytes
        
    # Get the Flags
    flags = getFlags(data[2:4]) # third and fourth bytes

    # Question Count
    QDCOUNT = b'\x00\x01' # 1 -> two bytes

    # Answer Count
    ANCOUNT = len(getRecs(data[12:])[0]).to_bytes(2, byteorder='big')
    
    # Nameserver Count
    NSCOUNT = (0).to_bytes(2, byteorder='big')

    # Additional Count
    ARCOUNT = (0).to_bytes(2, byteorder='big')
    
    
    ## HEADER
    dnsHeader = transactionID+flags+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT


    records, recType, domainName = getRecs(data[12:])
    
    dnsQuestion = buildQuestion(domainName, recType)

    ## BODY
    dnsBody = b''
    
    '''
    In order to reduce the size of messages, the domain system utilizes a
    compression scheme which eliminates the repetition of domain names in a
    message.  In this scheme, an entire domain name or a list of labels at
    the end of a domain name is replaced with a pointer to a prior occurance
    of the same name.

    The pointer takes the form of a two octet sequence:

        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        | 1  1|                OFFSET                   |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    '''
    
    domainNamePosition = len(dnsHeader) # Offset of Header: byte that starts the domainName (used for compression)

    for record in records:
        dnsBody += recToBytes(domainNamePosition, recType, record["ttl"], record["value"])

    return dnsHeader + dnsQuestion + dnsBody

def load_zones():
    
    jsonZone = {}   
    zoneFiles = glob.glob('zones/*.zone') # list of zone files

    for zone in zoneFiles:
        with open(zone) as zoneData:
            data = json.load(zoneData)
            zoneName = data["$origin"]
            jsonZone[zoneName] = data
    
    return jsonZone


if __name__ == '__main__':
    port = 53
    ip = "127.0.0.1"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))

    zoneData = load_zones()
    zone2 = load_zones()
    
    while 1:
        data, addr = sock.recvfrom(512) # 512 octets or less
        response = buildResponse(data)
        sock.sendto(response, addr)