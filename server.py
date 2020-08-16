
import datetime
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Cipher import AES
from Cryptodome import Random

global DEBUG
DEBUG = True

payload = []
timedelta = datetime.datetime.now()
print('[{}] [Main] > Generating RSA keypair.'.format(datetime.datetime.now()))
privatekeysrv = RSA.generate(2048)
privatekeysrvpem = privatekeysrv.exportKey('PEM')
print('[{}] [Main] > RSA keypair generated for {} seconds.'.format(datetime.datetime.now(), (datetime.datetime.now() - timedelta).total_seconds()))
publickeysrv = privatekeysrv.publickey()
publickeysrvpem = publickeysrv.exportKey('PEM')

timedelta = datetime.datetime.now()
print('[{}] [Main] > Generating RSA keypair.'.format(datetime.datetime.now()))
privatekeycli = RSA.generate(2048)
privatekeyclipem = privatekeycli.exportKey('PEM')
print('[{}] [Main] > RSA keypair generated for {} seconds.'.format(datetime.datetime.now(), (datetime.datetime.now() - timedelta).total_seconds()))
publickeycli = privatekeycli.publickey()
publickeyclipem = publickeycli.exportKey('PEM')

message = (str(input("{} > ".format(datetime.datetime.now())))).encode('utf-8')
def encrypt(message):
	timedelta = datetime.datetime.now()
	print('[{}] [Main] > Generating signature.'.format(datetime.datetime.now()))
	print(message)
	####################################################################################################
	myhash = SHA256.new(message)
	signature = PKCS1_v1_5.new(privatekeycli)
	signature = signature.sign(myhash)
	print('[{}] [Main] > Message succesefully signed with signature.'.format(datetime.datetime.now()))
	# signature encrypt
	print('[{}] [Main] > Encrypting signature.'.format(datetime.datetime.now()))
	cipherrsa = PKCS1_OAEP.new(publickeysrv)
	sig = cipherrsa.encrypt(signature[:128])
	sig = sig + cipherrsa.encrypt(signature[128:])
	payload.append(sig)
	####################################################################################################
	print('[{}] [Main] > Generating 256 bit session key.'.format(datetime.datetime.now()))
	# creation 256 bit session key 
	sessionkey = Random.new().read(32) # 256 bit
	# encryption AES of the message
	print('[{}] [Main] > Encryption AES of the message.'.format(datetime.datetime.now()))
	iv = Random.new().read(16) # 128 bit
	obj = AES.new(sessionkey, AES.MODE_CFB, iv)
	ciphertext = iv + obj.encrypt(message) #SEND DATA
	payload.append(ciphertext)
	# encryption RSA of the session key
	print('[{}] [Main] > Encryption RSA of the session key.'.format(datetime.datetime.now()))
	cipherrsa = PKCS1_OAEP.new(publickeysrv)
	sessionkey = cipherrsa.encrypt(sessionkey) #SEND DATA
	payload.append(sessionkey)
	
	payload1 = b'\x00\x01\x01\x00'.join(payload)
	print('[{}] [Main] > Message succesefully encrypted for {} seconds.'.format(datetime.datetime.now(), (datetime.datetime.now() - timedelta).total_seconds()))
	payload_recieved  = payload1.split(b'\x00\x01\x01\x00')
	if payload == payload_recieved and len(payload) == 3:
		print('[{}] [Main] > Payload not corrupted.'.format(datetime.datetime.now()))
		return(payload1)
	else:
		print('[{}] [Main] > Error : Payload corrupted! Payload parts {}/{}/3'.format(datetime.datetime.now(), len(payload), len(payload_recieved)))
		return('[Message corrupted]'.encode('utf-8'))

def decrypt(data):
	timedelta = datetime.datetime.now()
	print('[{}] [Main] > Parsing data.'.format(datetime.datetime.now()))
	payload = data.split(b'\x00\x01\x01\x00')
	signature = payload[0]
	ciphertext = payload[1]
	sessionkey = payload[2]
	# decryption session key
	print('[{}] [Main] > Decrypting session key.'.format(datetime.datetime.now()))
	cipherrsa = PKCS1_OAEP.new(privatekeysrv)
	sessionkey = cipherrsa.decrypt(sessionkey)
	# decryption message
	print('[{}] [Main] > Decrypting message.'.format(datetime.datetime.now()))
	iv = ciphertext[:16]
	obj = AES.new(sessionkey, AES.MODE_CFB, iv)
	message = obj.decrypt(ciphertext)
	message = message[16:]
	print('[{}] [Main] > Decrypting signature.'.format(datetime.datetime.now()))
	# decryption signature
	####################################################################################################
	cipherrsa = PKCS1_OAEP.new(privatekeysrv)
	sig = cipherrsa.decrypt(signature[:256])
	sig = sig + cipherrsa.decrypt(signature[256:])
	print('[{}] [Main] > Signature verification.'.format(datetime.datetime.now()))
	# signature verification

	verification = PKCS1_v1_5.new(publickeycli).verify(SHA256.new(message), sig)
	####################################################################################################
	
	if verification == True:
		print('[{}] [Main] > Signature succesefully verified.'.format(datetime.datetime.now()))
		print('[{}] [Main] > Message succesefully decrypted for {} seconds'.format(datetime.datetime.now(), (datetime.datetime.now() - timedelta).total_seconds()))
	else:
		print('[{}] [Main] > Error : Signature verification failure, your data not secure, please reconnect.'.format(datetime.datetime.now()))
	return message.decode('utf-8')

print(decrypt(encrypt(message)))
