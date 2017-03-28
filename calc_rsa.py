#!/usr/bin/python
# -*- coding: utf-8 -*-

# For a n-bit RSA key, direct encryption (with PKCS#1 "old-style" padding) works for 
# arbitrary binary messages up to floor(n/8)-11 bytes. In other words, for a 1024-bit 
# RSA key (128 bytes), up to 117 bytes.

p = 3	# first prime number
q = 11	# second prime number
n = p * q
# f(n) = (3-1) * (11-1) = 20
e = 7	
d = 3 	# (d * e) % φ(n) = 1

# public key: 7, 33
# private key: 3, 33

def str_to_int(string):
	return reduce(lambda x, y : (x << 8) + y, map(ord, string))

def int_to_str(i, n):
	text = ""
	f = int(floor(log(n, 2)/8.0 + 1))
	for j in range(f):
		text = chr(i & 0xff) + text
		i >>= 8
	return text

def encrypt(data):
	return pow(data, e, n)

def decrypt(data):
	return pow(data, d, n)

# Max. payload limit for ecryption depends on the size of the key (modulus)
data = 2


encrypted = encrypt(data)
print "encrypted value of "+str(data)+": "+str(encrypted)

decrypted = decrypt(encrypted)
print "decrypted value of "+str(encrypted)+": "+str(decrypted)
