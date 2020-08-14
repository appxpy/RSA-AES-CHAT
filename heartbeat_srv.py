# Python program to implement server side of chat room. 
import socket 
import select 
import sys 
import datetime
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Cipher import AES
from Cryptodome import Random
import threading
from threading import Thread
import sys

timedelta = datetime.datetime.now()
print('[{}] [Server] [Main] > Generating RSA keypair.'.format(datetime.datetime.now()))
privatekeysrv = RSA.generate(2048)
privatekeysrvpem = privatekeysrv.exportKey('PEM')
print('[{}] [Server] [Main] > RSA keypair generated for {} seconds.'.format(datetime.datetime.now(), (datetime.datetime.now() - timedelta).total_seconds()))
publickeysrv = privatekeysrv.publickey()
publickeysrvpem = publickeysrv.exportKey('PEM')

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 

HOST = '10.0.0.102'
PORT = 8008

server.bind((HOST, PORT)) 
  
server.listen(500) 
  
CLIENTS = []
THREADS = [] 
CLIENTS_KEYS = {}

key = False
auth = False

def encrypt(message,publickeycli):
    payload = []
    timedelta = datetime.datetime.now()
    print('[{}] [Main] > Generating signature.'.format(datetime.datetime.now()))
    ####################################################################################################
    myhash = SHA256.new(message)
    signature = PKCS1_v1_5.new(privatekeysrv)
    signature = signature.sign(myhash)
    print('[{}] [Main] > Message succesefully signed with signature.'.format(datetime.datetime.now()))
    # signature encrypt
    print('[{}] [Main] > Encrypting signature.'.format(datetime.datetime.now()))
    cipherrsa = PKCS1_OAEP.new(publickeycli)
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
    cipherrsa = PKCS1_OAEP.new(publickeycli)
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

def decrypt(data, publickeycli):
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

def clientthread(conn, addr): 
    threadName = threading.currentThread().name
    print('[{}] [{}:{}] [{}] > Client TCP listner started.'.format(datetime.datetime.now(), addr[0], addr[1], threadName))
    try:
        conn.send(publickeysrvpem)
        print('[{}] [{}:{}] [{}] > Sended public RSA key, waiting for client response.'.format(datetime.datetime.now(), addr[0], addr[1], threadName))
        publickeyclipem = conn.recv(2048)
        publickeycli = RSA.importKey(publickeyclipem)
        CLIENTS_KEYS[addr[0]] = publickeycli
        print('[{}] [{}:{}] [{}] > Client & Server public key keyexchanging successful.'.format(datetime.datetime.now(), addr[0], addr[1], threadName))
    except Exception as e:
        print('[{}] [{}:{}] [{}] > Error : unexpected exception occured : {}'.format(datetime.datetime.now(), addr[0], addr[1], threadName, e)) 
        remove(conn)
        print('[{}] [{}:{}] [{}] > Connection closed, stopping thread activity...'.format(datetime.datetime.now(), addr[0], addr[1], threadName)) 
        THREADS.remove(threading.currentThread()) 
        sys.exit()

    while True: 
            try:
                message = conn.recv(2048)
                
                if message != b'': 
                    message = decrypt(message, publickeycli)
                    print('[{}] [{}:{}] [{}] > {}.'.format(datetime.datetime.now(), addr[0], addr[1], threadName, message))
                    message_to_send = encrypt(("< {} > {}".format(addr[0], message)).encode('utf-8'), publickeycli)
                    broadcast(message_to_send, conn) 
                else:
                    print('[{}] [{}:{}] [{}] > Recieved null-byte, closing connection.'.format(datetime.datetime.now(), addr[0], addr[1], threadName)) 
                    remove(conn)
                    THREADS.remove(threading.currentThread()) 
                    print('[{}] [{}:{}] [{}] > Connection closed, stopping thread activity...'.format(datetime.datetime.now(), addr[0], addr[1], threadName)) 
                    sys.exit()
            except Exception as ex: 
                print('[{}] [{}:{}] [{}] > Error : unexpected exception occured : {}'.format(datetime.datetime.now(), addr[0], addr[1], threadName, e)) 
                remove(conn)
                CLIENTS_KEYS.remove(addr[0])
                print('[{}] [{}:{}] [{}] > Connection closed, stopping thread activity...'.format(datetime.datetime.now(), addr[0], addr[1], threadName)) 
                THREADS.remove(threading.currentThread())
                break 
    threading.currentThread().join()
def broadcast(message, connection): 
    for clients in CLIENTS: 
        if clients!=connection: 
            try:
                print(clients, connection)
                clients.send(message)   
            except Exception as e:
                print('[{}] [Server] [Broadcast] > Error : unexpected exception occured : {}'.format(datetime.datetime.now(), addr[0], addr[1], e)) 
                clients.close() 
                remove(clients) 
def remove(connection): 
    if connection in CLIENTS: 
        CLIENTS.remove(connection) 
  
while True: 

    conn, addr = server.accept() 
  
    CLIENTS.append(conn) 
    print('[{}] [Server] [Main] > Detected connection from {}, starting new threaded TCP listner.'.format(datetime.datetime.now(), addr[0]))
    thread = Thread(target = clientthread, args = (conn,addr))   
    THREADS.append(thread)
    thread.start() 
  
conn.close() 
server.close() 