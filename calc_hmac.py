#!/usr/bin/python
import hashlib
import hmac

key = "supersecretkey"
msg = "message"

def sxor(s1,s2):    
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

def calculate_hmac(key, msg):

	m = hashlib.sha1()

	block_size = m.block_size

	if len(key) > block_size:
		m.update(key)
		key = m.digest()

	if len(key) < block_size:
		key = key + ('\x00' * (block_size - len(key)))

	i_key_pad = sxor('\x36' * block_size, key)
	o_key_pad = sxor('\x5c' * block_size, key)

	return hashlib.sha1( o_key_pad + hashlib.sha1(i_key_pad + msg).digest() )


print calculate_hmac(key, msg).hexdigest()
print hmac.new(key, msg, hashlib.sha1).hexdigest()