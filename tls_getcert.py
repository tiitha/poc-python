#!/usr/bin/python

import argparse, datetime, os, socket, sys, time, urlparse

## (Please, insert your feedback here)
## Task took ... hours
## The most difficult part was ...


# parse arguments
parser = argparse.ArgumentParser(description='TLS v1.2 client')
parser.add_argument('url', type=str, help='URL to request')
parser.add_argument('--certificate', type=str, help='File to write PEM-encoded server certificate')
args = parser.parse_args()

# converts bytes (big endian) to integer
def bn(bytes):
        num = 0
        for byte in bytes:
                num <<= 8
                num |= ord(byte)
        return num

# converts integer to bytes (big endian)
def nb(i, length=0):
    bytes = ""
    for smth in xrange(length):
        bytes = chr(i & 0xff) + bytes
        i >>= 8
    return bytes

# returns TLS record that contains client_hello handshake message
def client_hello():

    print "--> client_hello()"

    # list of cipher suites the client supports
    csuite = "\x00\x05" # TLS_RSA_WITH_RC4_128_SHA
    csuite+= "\x00\x2f" # TLS_RSA_WITH_AES_128_CBC_SHA
    csuite+= "\x00\x35" # TLS_RSA_WITH_AES_256_CBC_SHA
    csuite+= "\x00\x39" # TLS_DHE_RSA_WITH_AES_256_CBC_SHA

    # add handshake message header
    client_hello = "\x03\x03"
    client_hello += nb(int(time.time()),4) 	# timestamp
    client_hello += os.urandom(28) 		# client randomness
    client_hello += "\x00" 			# session id len + sessionID
    client_hello += "\x00\x08" 			# cipher len
    client_hello += csuite 			# cipher
    client_hello += "\x01" 			# compression len
    client_hello += "\x00" 			# compressions
    client_hello += "" 				# extensions
    client_hello = "\x01"+nb(len(client_hello),3)+client_hello	# build packet

    # add record layer header
    record = "\x16\x03\x01" + nb(len(client_hello),2) + client_hello

    return record

# returns TLS record that contains 'Certificate unknown' fatal alert message
def alert():
    print "--> alert()"

    # add alert message
    alert = "\x01\x00"	# warning: client closed
    # add record layer header
    record = "\x15\x03\x01"+nb(len(alert),2)+alert
    return record

# parse TLS handshake messages
def parsehandshake(r):
    global server_hello_done_received

    # read handshake message type and length from message header
    htype = r[0]

    if htype == "\x02":
        print " <--- server_hello()"
	i = 6
	server_random = r[i:i+32]
	# hack to get timestamps that are not in the range of platform time_t
	gmt = datetime.datetime.fromtimestamp(0) + datetime.timedelta( seconds=bn(r[i:i+4]) )
	gmt = gmt.strftime('%Y-%m-%d %H:%M:%S') + " ("+r[i:i+4].encode("hex")+")"
	i += 32
	sess_len = bn(r[i])
	i += 1
	sessid = r[i:i+sess_len]
	i += sess_len
        print " [+] server randomness:", server_random.encode('hex').upper()
        print " [+] server timestamp:", gmt
        print " [+] TLS session ID:", sessid.encode('hex').upper()
	cipher = r[i:i+2]
        if cipher=="\x00\x2f":
            print "     [+] Cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA"
        elif cipher=="\x00\x35":
            print "     [+] Cipher suite: TLS_RSA_WITH_AES_256_CBC_SHA"
        elif cipher=="\x00\x39":
            print "     [+] Cipher suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
        elif cipher=="\x00\x05":
            print "     [+] Cipher suite: TLS_RSA_WITH_RC4_128_SHA"
        else:
            print "[-] Unsupported cipher suite selected:", cipher.encode('hex')
            sys.exit(1)
	i += 2
	compression = r[i:i+1]
        if compression!="\x00":
            print "[-] Wrong compression:", compression.encode('hex')
            sys.exit(1)

    elif htype == "\x0b":
        print " <--- certificate()"
	i = 4
	# certificates 
	certs_len = bn(r[i:i+3])
	i += 3
	certs = r[i:certs_len+i]
	# get the first certificate
	certlen = bn(certs[0:3])
        print " [+] Server certificate length:", certlen
        if args.certificate:
	    cert = certs[3:certlen+3]
	    cert = "-----BEGIN CERTIFICATE-----\n" + cert.encode('base64') + "-----END CERTIFICATE-----\n"
	    open(args.certificate, 'wb').write(cert)
            print "     [+] Server certificate stored in:", args.certificate
	i += certs_len
	if len(r) > i:
	    print r[i:i+1]
	    parsehandshake(r[i:len(r)])
    elif htype == "\x0e":
        print " <--- server_hello_done()"
	server_hello_done_received =True
    else:
        print "[-] Unknown Handshake Type:", htype.encode('hex')
        sys.exit(1)

    # handle the case of several handshake messages in one record

# parses TLS record
def parserecord(r):
    # read from TLS record header content type and length
    content_type = bn(r[0])
    content_len  = bn(r[1:4])
    return r

# read from the socket full TLS record
def readrecord():
    # read TLS record header (5 bytes)
    header = s.recv(5)

    # find data length
    data_len = bn(header[3:5])

    # read TLS record body
    i = 1024
    record = ""
    while data_len>len(record):
        if data_len - len(record) < 1024:
	    i = data_len - len(record)
        record += s.recv(i)

    if len(header)>0 and header[0] == "\x16":
       parsehandshake(record)
    return record

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
url = urlparse.urlparse(args.url)
host = url.netloc
port = 443
path = url.path

s.connect((host, port))
s.send(client_hello())

server_hello_done_received = False
while not server_hello_done_received:
    parserecord(readrecord())

s.send(alert())

print "[+] Closing TCP connection!"
s.close()