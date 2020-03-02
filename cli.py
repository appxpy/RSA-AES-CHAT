import socket
import time
import threading
from cryptography.fernet import Fernet

HOST = socket.gethostbyname(socket.gethostname())
PORT = 0
server = ('178.140.207.179', 8080)


join = False
shutdown = False

def recieve(name, socket):
	while shutdown == False:
		try:
			while True:
				data, addr = socket.recvfrom(1024)

				if 
		
				data = f.decrypt(data).decode('utf-8')
		
				print(data)
		
				time.sleep(.5)
		except:
			pass
	
socket = socket.socket(socket.AF_INET ,socket.SOCK_DGRAM)
socket.bind((HOST,PORT))
socket.setblocking(0)

socket.sendto('KEYREQUEST'.encode('utf-8'), server)
data, addr = socket.recvfrom(1024)
key = data
f = Fernet(key)
recieveThread = threading.Thread(target = recieve, args = ("RTrieve", socket))
recieveThread.start()

alias = str(input('Please, enter your name: '))

while shutdown == False:
	if join == False:
		socket.sendto(("["+alias + "] - Joined the chat ").encode("utf-8"),server)

		join = True
	else:
		try:
			message = str(input())

			if message != "":
				socket.sendto(f.encrypt("["+alias + "] ==> " + message).encode("utf-8"),server)

			time.sleep(.5)
		except Exception as e:
			socket.sendto(("["+alias + "] - Left the chat x").encode("utf-8"),server)
			shutdown == True
			break
recieveThread.join()
socket.close()






