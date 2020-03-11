try:
    import socket
    import time
    import threading
    import sys
    from cryptography.fernet import Fernet
except:
	print('Installing packages!')
	import subprocess
	import sys
	packagelist = ['cryptography']
	for package in packagelist:
		subprocess.check_call([sys.executable, "-m", "pip", "install", package])
finally:
	import socket
	import time
	import threading
	import sys
	from cryptography.fernet import Fernet


HOST = socket.gethostbyname(socket.gethostname())
PORT = 0
server = ('192.168.14.55', 8080)


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
			socket.sendto(f.encrypt(("["+alias + "] - Left the chat ").encode("utf-8")),server)
			recieveThread.join()
			socket.close()
			input('Press enter to exit.')
			break
sys.exit()






