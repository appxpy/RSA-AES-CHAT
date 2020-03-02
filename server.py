import socket
import select
import time
from datetime import datetime
############KEYGEN###############
import base64
import string
import random
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
N = 128
password_provided = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(N)) # This is input in the form of a string
print('Current session password is: ', password_provided)
password = password_provided.encode()
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=128,
    salt=salt,
    iterations=128452,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once
print(len(key))
############KEYGEN###############
HOST = '0.0.0.0'
PORT = 8080

socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
socket.bind((HOST, PORT))

clients = []
print('[Server started]')
while True:
	try:
		data, addr = socket.recvfrom(1024)
		if data.deconde('utf-8') == 'KEYREQUEST':
			socket.sendto(key, addr)
		if addr not in clients:
			clients.append(addr)
		timestamp = str(datetime.now())

		print('[{}] [{}] [{}] {}'.format(timestamp, addr[0], addr[1], data.decode('utf-8')))
		time.sleep(.5)
		for client in clients:
			if addr != client:
				socket.sendto(data, client)
	except Exception as e:
		print('[DEBUG]==>', e)
		print('[Server closed]')
		break

socket.close()