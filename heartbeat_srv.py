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
import json
from uuid import uuid4
from threading import Thread
import sys
global CLIENTS_KEYS
global SHUTDOWN
global MESSAGES
global USERS

timedelta = datetime.datetime.now()
print('[{}] [Server] [Main] > Generating RSA keypair.'.format(datetime.datetime.now()))
privatekeysrv = RSA.generate(2048)
privatekeysrvpem = privatekeysrv.exportKey('PEM')
print('[{}] [Server] [Main] > RSA keypair generated for {} seconds.'.format(datetime.datetime.now(), (datetime.datetime.now() - timedelta).total_seconds()))
publickeysrv = privatekeysrv.publickey()
publickeysrvpem = publickeysrv.exportKey('PEM')

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 

HOST = '10.0.0.103'
PORT = 8008

server.bind((HOST, PORT)) 
  
server.listen(500) 

f = open('users.json', 'r+')
f1 = open('messages.json', 'r+')
f2 = open('blocked.json', 'r+')

CLIENTS = []
THREADS = [] 
CLIENTS_KEYS = {}
CLIENTS_TOKENS = {}


try:
    USERS = json.loads(f.read())
except:
    f.close()
    f = open('users.json', 'w')
    f.write('{}')
    f.close()
    USERS = {}
else:
    f.close()

try:
    MESSAGES = json.loads(f1.read())
except:
    f1.close()
    f1 = open('messages.json', 'w')
    f1.write('{}')
    f1.close()
    MESSAGES = {}
else:
    f1.close()

try:
    BLOCKED_LIST = json.loads(f2.read())
except:
    f2.close()
    f2 = open('blocked.json', 'w')
    f2.write('{}')
    f2.close()
    BLOCKED_LIST = {}
else:
    f2.close()


key = False
auth = False
SHUTDOWN = False

def generate_token():
    rand_token = uuid4()
    return(rand_token.bytes)

def encrypt(message,publickeycli):
    print(publickeycli)
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
        CLIENTS_KEYS[conn] = [publickeycli, generate_token()]
        print('[{}] [{}:{}] [{}] > Client & Server public key keyexchanging successful.'.format(datetime.datetime.now(), addr[0], addr[1], threadName))
        data = conn.recv(2048)
        data = json.loads(decrypt(data, publickeycli))
        if addr[0] in BLOCKED_LIST:
            if BLOCKED_LIST[addr[0]] != 'Inf':
                if (datetime.datetime.now() - BLOCKED_LIST[addr[0]]).total_seconds() < 60:
                    timestamp = 60 - (datetime.datetime.now() - BLOCKED_LIST[addr[0]]).total_seconds()
                    payload = encrypt((json.dumps({
                        'status': '<TEMPBLOCKED>',
                        'timestamp': str(round(timestamp,1)),
                        'history': {
                            'None': 'Temporary blocked.'
                        }
                    })).encode('utf-8'), publickeycli)
                    conn.send(payload)
            else:
                payload = encrypt((json.dumps({
                    'status': '<TEMPBLOCKED>',
                    'timestamp': 'Infinity',
                    'history': {
                        'None': 'Permanently blocked.'
                    }
                })).encode('utf-8'), publickeycli)
                conn.send(payload)
        if data['login'] in USERS.keys():
            if USERS[data['login']] == data['password']:
                payload = (json.dumps({'status': '<SUCCESS>', 'history': MESSAGES})).encode('utf-8')
                print('flag5')
                conn.send(encrypt(payload, publickeycli))
                message = ('---< {} joined the chat >---'.format(addr[0])).encode('utf-8')
                broadcast(message , conn)
            else:
                BLOCKED_LIST[addr[0]] = datetime.datetime.now()
                conn.send(encrypt(json.dumps({'status' : '<INVALIDCREDENTIALS>', 'history': {'None': 'Invalid credentials.'}}).encode('utf-8'), publickeycli))
                remove(CLIENTS_KEYS[conn])
                print('[{}] [{}:{}] [{}] > Error : Invalid credentials.'.format(datetime.datetime.now(), addr[0], addr[1], threadName, e)) 
                remove(conn)
                print('[{}] [{}:{}] [{}] > Connection closed, stopping thread activity...'.format(datetime.datetime.now(), addr[0], addr[1], threadName)) 
                THREADS.remove(threading.currentThread())
                sys.exit()
        else:
            BLOCKED_LIST[addr[0]] = datetime.datetime.now()
            conn.send(encrypt(json.dumps({'status' : '<INVALIDCREDENTIALS>', 'history': {'None': 'Invalid credentials.'}}).encode('utf-8'), publickeycli))
            remove(CLIENTS_KEYS[conn])
            print('[{}] [{}:{}] [{}] > Error : Invalid credentials'.format(datetime.datetime.now(), addr[0], addr[1], threadName, e)) 
            remove(conn)
            print('[{}] [{}:{}] [{}] > Connection closed, stopping thread activity...'.format(datetime.datetime.now(), addr[0], addr[1], threadName)) 
            THREADS.remove(threading.currentThread())
            sys.exit()
    except Exception as e:
        remove(CLIENTS_KEYS[conn])
        print('[{}] [{}:{}] [{}] > Error : unexpected exception occured : {}'.format(datetime.datetime.now(), addr[0], addr[1], threadName, e)) 
        remove(conn)
        print('[{}] [{}:{}] [{}] > Connection closed, stopping thread activity...'.format(datetime.datetime.now(), addr[0], addr[1], threadName)) 
        THREADS.remove(threading.currentThread())
        sys.exit()
    while not SHUTDOWN: 
        try:
            message = conn.recv(2048)
            
            if message != b'': 
                message = decrypt(message, publickeycli)
                print('[{}] [{}:{}] [{}] > {}'.format(datetime.datetime.now(), addr[0], addr[1], threadName, message))
                message_to_send = "< {} > {}".format(addr[0], message).encode('utf-8')
                MESSAGES[str(datetime.datetime.now())] = message_to_send.decode("utf-8")
                broadcast(message_to_send, conn) 
            elif decrypt(message,publickeycli) == '\n':
                continue
            else:
                message = '---< {} left the chat >---'.format(addr[0]).encode('utf-8')
                broadcast(message , conn)
                remove(CLIENTS_KEYS[conn])
                print('[{}] [{}:{}] [{}] > Recieved null-byte, closing connection.'.format(datetime.datetime.now(), addr[0], addr[1], threadName)) 
                remove(conn)
                THREADS.remove(threading.currentThread()) 
                print('[{}] [{}:{}] [{}] > Connection closed, stopping thread activity...'.format(datetime.datetime.now(), addr[0], addr[1], threadName)) 
                sys.exit()
        except Exception as e: 
            message = '---< {} left the chat >---'.format(addr[0]).encode('utf-8')
            broadcast(message , conn)
            remove(CLIENTS_KEYS[conn])
            print('[{}] [{}:{}] [{}] > Error : unexpected exception occured : {}'.format(datetime.datetime.now(), addr[0], addr[1], threadName, e)) 
            remove(conn)
            print('[{}] [{}:{}] [{}] > Connection closed, stopping thread activity...'.format(datetime.datetime.now(), addr[0], addr[1], threadName)) 
            THREADS.remove(threading.currentThread())
            break 
    sys.exit()
def broadcast(message, connection): 
    print('flag1')
    for clients in CLIENTS: 
        print('flag2')
        if clients != connection: 
            print('flag3')
            try:
                print('flag4')
                publickeycli = CLIENTS_KEYS[clients][0]
                print('flag5')
                print(publickeycli)
                clients.send(encrypt(message, publickeycli))   
            except Exception as e:
                print('[{}] [Server] [Broadcast] > Error : unexpected exception occured : {}'.format(datetime.datetime.now(), addr[0], addr[1], e)) 
                clients.close() 
                remove(clients) 
def remove(connection): 
    if connection in CLIENTS: 
        CLIENTS.remove(connection) 
def handshakethread():  
        while not SHUTDOWN:
            try: 
                conn, addr = server.accept() 
                CLIENTS.append(conn) 
                print('[{}] [Server] [Main] > Detected connection from {}, starting new threaded TCP listner.'.format(datetime.datetime.now(), addr[0]))
                thread = Thread(target = clientthread, args = (conn,addr))   
                THREADS.append(thread)
                thread.start() 
            except Exception as e:
                print('[{}] [Server] [Handshake] > Error : unexpected exception occured : {}'.format(datetime.datetime.now(), e))
                continue
        sys.exit()
handshakethread = threading.Thread(target=handshakethread)
handshakethread.start()
try:
    while not SHUTDOWN:
        cmd = str(input(""))
        if cmd.lower() == 'stop':
            print('[{}] [Server] [Main] > Causing fatal errors to stop server activity.'.format(datetime.datetime.now()))
            SHUTDOWN = True
            f1 = open('messages.json', 'w', encoding='utf-8')
            f1.write(json.dumps(MESSAGES, indent=4, ensure_ascii=False))
            f1.close()
            f2 = open('blocked.json', 'w', encoding='utf-8')
            f2.write(json.dumps(BLOCKED_LIST, indent=4, ensure_ascii=False))
            f2.close()

            break
        elif (cmd.lower()).startswith('broadcast '):
            data = cmd.split(" ")
            data.pop(0)
            data = " ".join(data)
            data = ("< SERVER > {}".format(data)).encode('utf-8')
            MESSAGES[str(datetime.datetime.now())] = data.decode('utf-8')
            for cli in CLIENTS:
                try:
                    publickeycli = CLIENTS_KEYS[cli][0]
                    cli.send(encrypt(data, publickeycli))   
                except Exception as e:
                    print('[{}] [Server] [Broadcast] > Error : unexpected exception occured : {}'.format(datetime.datetime.now(), addr[0], addr[1], e)) 
                    cli.close() 
                    remove(cli) 
        elif cmd.lower() == 'blocked':
            print(BLOCKED_LIST)
        elif cmd.lower() == 'publickeys':
            print(CLIENTS_KEYS)
        else:
            print(MESSAGES)
    for conn in CLIENTS:
        conn.close() 
    server.close()
except KeyboardInterrupt:
    f1 = open('messages.json', 'w', encoding='utf-8')
    f1.write(json.dumps(MESSAGES, indent=4, ensure_ascii=False))
    f1.close()
    f2 = open('blocked.json', 'w', encoding='utf-8')
    f2.write(json.dumps(BLOCKED_LIST, indent=4, ensure_ascii=False))
    f2.close()
    for thread in THREADS:
        thread.join()
    SHUTDOWN = True
    for conn in CLIENTS:
        conn.close() 
    server.close()
except Exception as e:
    print('[{}] [Server] [Main] > Error : unexpected error occured : {}.'.format(datetime.datetime.now(), e))
    f1 = open('messages.json', 'w', encoding='utf-8')
    f1.write(json.dumps(MESSAGES, indent=4, ensure_ascii=False))
    f1.close()
    f2 = open('blocked.json', 'w', encoding='utf-8')
    f2.write(json.dumps(BLOCKED_LIST, indent=4, ensure_ascii=False))
    f2.close()
    SHUTDOWN = True
    for conn in CLIENTS:
        conn.close() 
    server.close()











