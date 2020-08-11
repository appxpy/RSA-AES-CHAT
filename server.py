import socket
import select
import time
import hashlib
import rsa
import json
from datetime import datetime
global CLIENTS
global USERS
####################
print('[Generating RSA keypair...]')
(PUBKEY, PRIVATEKEY) = rsa.newkeys(2048)
PUBKEY_STR = PUBKEY.save_pkcs1()
####################
#CLIENTS = {
#	'192.168.0.1': 'OFFLINE | AUTH | ONLINE | NO AUTH | KEY REQUEST'	
#}
CLIENTS = {}
USERS = {
	'George': '532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25'
#	'George2': '532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25'
}

HOST = '127.0.0.1'
PORT = 8760

socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
socket.bind((HOST, PORT))


print('[Dedicated server started]')
while True:
	try:
		data, addr = socket.recvfrom(2048)
		if addr not in CLIENTS or CLIENTS[addr] == 'NO AUTH' or CLIENTS[addr] == 'OFFLINE' or CLIENTS[addr] == 'KEY REQUEST':
			CLIENTS[addr] = 'KEY REQUEST'
			if data.decode('utf-8') == '---RSA KEY REQUEST---':
				socket.sendto(PUBKEY_STR, addr)
				CLIENTS[addr] = 'AUTH'
		elif CLIENTS[addr] == 'AUTH':
			try:
				payload = json.loads(rsa.decrypt(data, PRIVATEKEY).decode('utf-8'))
			except:
				socket.sendto('---AUTHORIZATION FAILURE---'.encode('utf-8'), addr)
				CLIENTS[addr] = 'NO AUTH'
			else:
				if payload['login'] in USERS.keys():
					if USERS[payload['login']] == payload['password']:
						socket.sendto('---AUTHORIZED SUCCESS---'.encode('utf-8'), addr)
						CLIENTS[addr] = 'ONLINE'
				else:
					socket.sendto('---AUTHORIZATION FAILURE---'.encode('utf-8'), addr)
					CLIENTS[addr] = 'NO AUTH'	
		else:	
			print('[{}] [{}:{}] > {}'.format(str(datetime.now()), addr[0], addr[1], rsa.decrypt(data, PRIVATEKEY).decode('utf-8')))
		time.sleep(.5)
		for client in CLIENTS.keys():
			if addr != client:
				socket.sendto(data, client)
	except Exception as e:
		print('[{}] [DEBUG] >'.format(str(datetime.now())), e)
		for client in CLIENTS.keys():
			if CLIENTS[client] == 'ONLINE':
				socket.sendto('---CLOSE CONNECTION---'.encode('utf-8'), client)
		print('[Dedicated server closed]')
		break

socket.close()