import socket
import time
import threading
from cryptography.fernet import Fernet

HOST = socket.gethostbyname(socket.gethostname())
PORT = 0
try:
	file = open('SERVER_IP.txt', 'r').read()
except:
	file = open('SERVER_IP.txt', 'w').close()
	file = open('SERVER_IP.txt', 'r').read()

print('file')
if file == '':
	input('Enter global ip of device the server.py is running on. Press enter to exit.')
	file.close()
else:
	print(file)
	server_ip = str(file)
	server = (server_ip, 8080)
	print('Connecting to: ', server)


join = False
shutdown = False
key_recieved = False

def recieve(name, socket):
	while shutdown == False:
		try:
			while True:
				data, addr = socket.recvfrom(1024)
		
				data = f.decrypt(data).decode('utf-8')
		
				if data != '---KEYREQUEST--':
					print(data)
		
				time.sleep(.5)
		except:
			pass
	
socket = socket.socket(socket.AF_INET ,socket.SOCK_DGRAM)
socket.bind((HOST,PORT))
socket.setblocking(0)

socket.sendto('---KEYREQUEST---'.encode('utf-8'), server)

while key_recieved == False:
	try:
		data, addr = socket.recvfrom(1024)
		key_recieved = True
	except Exception as e:
		time.sleep(.2)
		print('Recieving session key...')
		pass
key = data
f = Fernet(key)
recieveThread = threading.Thread(target = recieve, args = ("RTrieve", socket))
recieveThread.start()

alias = str(input('Please, enter your name: '))

while shutdown == False:
	if join == False:
		socket.sendto(f.encrypt(("["+alias + "] - Joined the chat ").encode("utf-8")),server)

		join = True
	else:
		try:
			message = str(input())

			if message != "":
				socket.sendto(f.encrypt(("["+alias + "] ==> " + message).encode("utf-8")),server)

			time.sleep(.5)
		except Exception as e:
			print(e)
			socket.sendto(f.encrypt(("["+alias + "] - Left the chat ").encode("utf-8")),server)
			shutdown == True
			break
recieveThread.join()
socket.close()






