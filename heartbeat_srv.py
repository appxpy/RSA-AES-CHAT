# Python program to implement server side of chat room. 
import socket 
import select 
import sys 
import datetime
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Cipher import AES
from Cryptodome import Random
from threading import Thread

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 

HOST = '10.0.0.102'
  
PORT = 8008

timedelta = datetime.datetime.now()
print('[{}] [Main] > Generating RSA keypair.'.format(datetime.datetime.now()))
PRIVATEKEY = RSA.generate(2048)
print('[{}] [Main] > RSA keypair generated for {} seconds.'.format(datetime.datetime.now(), (datetime.datetime.now() - timedelta).total_seconds()))
PUBLICKEY =PRIVATEKEY.publickey()

server.bind((HOST, PORT)) 
  
server.listen(500) 
  
CLIENTS = [] 
CLIENTS_KEYS = {}
def encrypt(msg):
	encryptedmsg = msg.encode('utf-8')
	return encryptedmsg
def clientthread(conn, addr): 

    conn.send(encrypt('test'))
  
    while True: 
            try: 
                message = conn.recv(2048) 
                if message: 
  
                    print("<" + addr[0] + "> " + message)

                    message_to_send = "<" + addr[0] + "> " + message 
                    broadcast(encrypt(message_to_send), conn) 
  
                else: 
                    remove(conn) 
  
            except: 
                continue
  
def broadcast(message, connection): 
    for clients in CLIENTS: 
        if clients!=connection: 
            try: 
                clients.send(encrypt(message))
            except: 
                clients.close() 
                remove(clients) 
def remove(connection): 
    if connection in CLIENTS: 
        CLIENTS.remove(connection) 
  
while True: 

    conn, addr = server.accept() 
  
    CLIENTS.append(conn) 
    print(addr[0] + " connected")
    thread = Thread(target = clientthread, args = (conn,addr))    
    thread.start() 
  
conn.close() 
server.close() 