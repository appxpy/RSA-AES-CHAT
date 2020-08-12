
import socket
import time
import threading
import sys
import hashlib
import rsa
import json

global KEYS
KEYS = []
HOST = socket.gethostbyname("") 
PORT = 8761
server = ('localhost', 8760)


join = False
shutdown = False
key_recieved = False
authorized = False

def recieve(name, socket):
	while shutdown == False:
		try:
			while True:
				data, addr = socket.recvfrom(2048)
		
				data = f.decrypt(data).decode('utf-8')
				
				if data == '---CLOSE CONNECTION---':
					socket.close()
					sys.exit()
					break

				if data == '---HEARTBEAT---':
					socket.sendto(rsa.encrypt('---HEARTBEAT---'.encode('utf-8'), KEY))
				if data != '---RSA KEY REQUEST---':
					print(data)

		
				time.sleep(.5)
		except:
			pass

socket = socket.socket(socket.AF_INET ,socket.SOCK_DGRAM)
socket.bind((HOST,PORT))
socket.setblocking(0)
try:
	socket.sendto('---RSA KEY REQUEST---'.encode('utf-8'), server)
except:
	print('Error : Network is unreachable.')
	sys.exit()
iteration = 0
while key_recieved == False:
	try:
		data, addr = socket.recvfrom(2048)
		key_recieved = True
	except Exception as e:
		time.sleep(.5)
		if iteration == 9:
			iteration = 0
		suffix = str('.') * (iteration // 2)
		iteration += 1
		sys.stdout.write('Initializing secure connection{}    \r'.format(suffix))
		sys.stdout.flush()
		pass


print('Secure connection initialized, public key :\n', data.decode('utf-8'))
print('\n\n')
global KEY
KEY = rsa.PublicKey.load_pkcs1(data)
user = str(input('Login : '))
if len(list(user)) > 256:
	print('Too long login (>256 chars)')
	sys.exit()
password = str(input('Password : '))
if len(list(password)) > 256:
	print('Too long password (>256 chars)')
	sys.exit()
hash_object = hashlib.sha256(password.encode())
password = hash_object.hexdigest()
payload = rsa.encrypt((json.dumps({'login': user, 'password': password})).encode('utf-8'), KEY)

while authorized == False:
	try:
		print('Authorizing...', end='\r')
		socket.sendto(payload, server)
		data, addr = socket.recvfrom(2048)
		if data.decode('utf-8') == '---AUTHORIZATION FAILURE---':
			print('Authorization failure : Invalid login or password.')
			socket.close()
			sys.exit()
		elif data.decode('utf-8') == '---AUTHORIZED SUCCESS---':
			print('Welcome back,', user, '.')
			authorized = True
			break
		else:
			print('Authorization failure : Invalid server response (', data.decode('utf-8') ,')')
			socket.close()
			sys.exit()
	except Exception as e:
		time.sleep(.5)
		print('Authorizing...', end='\r')
		pass
recieveThread = threading.Thread(target = recieve, args = ("RTrieve", socket))
recieveThread.start()

while shutdown == False:
	if join == False:
		socket.sendto(rsa.encrypt(("---JOIN CHAT---").encode("utf-8"), KEY),server)

		join = True
	else:
		try:
			message = str(input('>'))

			if message != "":
				socket.sendto(rsa.encrypt((message).encode("utf-8"), KEY),server)

			time.sleep(.5)
		except Exception as e:
			socket.sendto(rsa.encrypt(("---LEFT CHAT---").encode("utf-8"), KEY),server)
			recieveThread.join()
			socket.close()
			input('Press enter to exit.')
			break
sys.exit()






