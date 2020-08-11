import rsa
import sys
import hashlib

(pubkey, privkey) = rsa.newkeys(512)

pubkey_str = pubkey.save_pkcs1()

print(pubkey_str.decode('utf-8'))

if pubkey_str.startswith(b'-----BEGIN RSA PUBLIC KEY-----\n') and pubkey_str.endswith(b'\n-----END RSA PUBLIC KEY-----\n') and sys.getsizeof(rsa.PublicKey.load_pkcs1(pubkey_str)) * 8 == 2048:
	print('KEY VALID')
else:
	print('KEY INVALID')
hash_object = hashlib.md5('test'.encode())
print(hash_object.hexdigest())