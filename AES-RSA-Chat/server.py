import socket
import sys
import datetime
import json
import time
from threading import Thread, Event
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Cipher import AES
from Cryptodome import Random

HOST = '0.0.0.0'
PORT = 8080

global CLIENTS_KEYS
global MESSAGES
global USERS
global CLIENTS_USERS
global BLOCKED_LIST

CLIENTS = []
CLIENTS_USERS = {}
THREADS = {}
CLIENTS_KEYS = {}
CLIENTS_TOKENS = {}


def encrypt(message, publickeycli, privatekeysrv):
    privatekeysrv = RSA.importKey(privatekeysrvpem)
    payload = []
    timedelta = datetime.datetime.now()
    print('[{}] [Main] > Generating signature.'.format(datetime.datetime.now()))
    ####################################################################################################
    myhash = SHA256.new(message)
    signature = PKCS1_v1_5.new(privatekeysrv)
    signature = signature.sign(myhash)
    print('[{}] [Main] > Message succesefully signed with signature.'.format(
        datetime.datetime.now()))
    # signature encrypt
    print('[{}] [Main] > Encrypting signature.'.format(datetime.datetime.now()))
    cipherrsa = PKCS1_OAEP.new(publickeycli)
    sig = cipherrsa.encrypt(signature[:128])
    sig = sig + cipherrsa.encrypt(signature[128:])
    payload.append(sig)
    ####################################################################################################
    print('[{}] [Main] > Generating 256 bit session key.'.format(
        datetime.datetime.now()))
    # creation 256 bit session key
    sessionkey = Random.new().read(32)  # 256 bit
    # encryption AES of the message
    print('[{}] [Main] > Encryption AES of the message.'.format(
        datetime.datetime.now()))
    iv = Random.new().read(16)  # 128 bit
    obj = AES.new(sessionkey, AES.MODE_CFB, iv)
    ciphertext = iv + obj.encrypt(message)  # SEND DATA
    payload.append(ciphertext)
    # encryption RSA of the session key
    print('[{}] [Main] > Encryption RSA of the session key.'.format(
        datetime.datetime.now()))
    cipherrsa = PKCS1_OAEP.new(publickeycli)
    sessionkey = cipherrsa.encrypt(sessionkey)  # SEND DATA
    payload.append(sessionkey)

    payload1 = b'\x00\x01\x01\x00'.join(payload)
    print('[{}] [Main] > Message succesefully encrypted for {} seconds.'.format(
        datetime.datetime.now(), (datetime.datetime.now() - timedelta).total_seconds()))
    payload_recieved = payload1.split(b'\x00\x01\x01\x00')
    if payload == payload_recieved and len(payload) == 3:
        print('[{}] [Main] > Payload not corrupted.'.format(
            datetime.datetime.now()))
        return(payload1)
    else:
        print('[{}] [Main] > Error : Payload corrupted! Payload parts {}/{}/3'.format(
            datetime.datetime.now(), len(payload), len(payload_recieved)))
        return('[Message corrupted]'.encode('utf-8'))


def decrypt(data, publickeycli, privatekeysrvpem):
    privatekeysrv = RSA.importKey(privatekeysrvpem)
    timedelta = datetime.datetime.now()
    print('[{}] [Main] > Parsing data.'.format(datetime.datetime.now()))
    payload = data.split(b'\x00\x01\x01\x00')
    if len(payload) == 3:
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
        verification = PKCS1_v1_5.new(
            publickeycli).verify(SHA256.new(message), sig)
        ####################################################################################################
        if verification == True:
            print('[{}] [Main] > Signature succesefully verified.'.format(
                datetime.datetime.now()))
            print('[{}] [Main] > Message succesefully decrypted for {} seconds'.format(
                datetime.datetime.now(), (datetime.datetime.now() - timedelta).total_seconds()))
        else:
            print('[{}] [Main] > Error : Signature verification failure, your data not secure, please reconnect.'.format(
                datetime.datetime.now()))
        return message.decode('utf-8')
    else:
        return None


def broadcast(message, connection, publickeycli, privatekeysrvpem):
    for clients in CLIENTS:
        if clients != connection:
            try:
                publickeycli = CLIENTS_KEYS[clients]
                clients.send(encrypt(message, publickeycli, privatekeysrvpem))
            except Exception as e:
                print(f'[{datetime.datetime.now()}] [Server] [Broadcast] > Error : unexpected exception occured : {e}')
                clients.close()
                remove(clients)


def _remove(connection):

    if connection in CLIENTS:

        CLIENTS.remove(connection)


class ClientThread(Thread):

    def __init__(self, conn, addr, keys):
        Thread.__init__(self)
        super(ClientThread, self).__init__()
        self.conn = conn
        self.addr = addr
        self.ip = addr[0]
        self.port = addr[1]
        self.publickeysrvpem = keys[0]
        self.privatekeysrvpem = keys[1]

        self._stop_event = Event()

    def run(self):
        try:

            self.conn.send(self.publickeysrvpem)  # 01 ##########

            print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Sended public RSA key, waiting for client response.')

            publickeyclipem = self.conn.recv(8192)  # 02 ##########
            self.publickeycli = RSA.importKey(publickeyclipem)

            CLIENTS_KEYS[self.conn] = self.publickeycli

            print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Client & Server public key keyexchanging successful.')

            data = self.conn.recv(8192)  # 03 ##########
            data = json.loads(
                decrypt(data, self.publickeycli, self.privatekeysrvpem))

            self.login = data['login']

            if self.login in CLIENTS_USERS:

                BLOCKED_LIST[self.ip] = str(datetime.datetime.now())

                self.conn.send(encrypt(json.dumps({'status': '<ALREADYONLINE>', 'history': {
                               'None': 'This user is already online.'}}).encode('utf-8'), self.publickeycli, self.privatekeysrvpem))

                print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Error : User {login} tried to login, while account is online.')
                print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Connection closed, stopping thread activity...')

                self.stop()

            else:

                if self.ip in BLOCKED_LIST or self.login in BLOCKED_LIST:

                    if self.ip in BLOCKED_LIST:

                        if BLOCKED_LIST[self.ip] != 'Inf':

                            if (datetime.datetime.now() - datetime.datetime.strptime(BLOCKED_LIST[self.ip], '%Y-%m-%d %H:%M:%S.%f')).total_seconds() < 60:

                                timestamp = 60 - (datetime.datetime.now() - datetime.datetime.strptime(
                                    BLOCKED_LIST[self.ip], '%Y-%m-%d %H:%M:%S.%f')).total_seconds()

                                payload = encrypt((json.dumps({
                                    'status': '<TEMPBLOCKED>',
                                    'timestamp': str(round(timestamp, 1)),
                                    'history': {
                                        'None': 'Temporary blocked.'
                                    }
                                })).encode('utf-8'), self.publickeycli, self.privatekeysrvpem)

                                self.conn.send(payload)  # 04 ##########

                                print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Error : IP {self.ip} temporary blocked')
                                print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Connection closed, stopping thread activity...')

                                self.stop()

                            else:

                                del BLOCKED_LIST[self.ip]
                        else:

                            payload = encrypt((json.dumps({
                                'status': '<BLOCKED>',
                                'timestamp': 'Infinity',
                                'history': {
                                    'None': 'Permanently blocked.'
                                }
                            })).encode('utf-8'), self.publickeycli, self.privatekeysrvpem)
                            self.conn.send(payload)  # 04 ##########

                            del CLIENTS_KEYS[self.conn]

                            print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Error : IP {self.ip} permanently blocked')
                            print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Connection closed, stopping thread activity...')

                            self.stop()

                    elif self.login in BLOCKED_LIST:

                        if BLOCKED_LIST[self.login] != 'Inf':

                            if (datetime.datetime.now() - datetime.datetime.strptime(BLOCKED_LIST[self.login], '%Y-%m-%d %H:%M:%S.%f')).total_seconds() < 60:

                                timestamp = 60 - (datetime.datetime.now() - datetime.datetime.strptime(
                                    BLOCKED_LIST[self.login], '%Y-%m-%d %H:%M:%S.%f')).total_seconds()

                                payload = encrypt((json.dumps({
                                    'status': '<TEMPBLOCKED>',
                                    'timestamp': str(round(timestamp, 1)),
                                    'history': {
                                        'None': 'Temporary blocked.'
                                    }
                                })).encode('utf-8'), self.publickeycli, self.privatekeysrvpem)
                                self.conn.send(payload)  # 04 ##########

                                print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Error : User {self.login} temporary blocked')
                                print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Connection closed, stopping thread activity...')

                                self.stop()

                            else:

                                del BLOCKED_LIST[self.login]

                        else:

                            payload = encrypt((json.dumps({
                                'status': '<BLOCKED>',
                                'timestamp': 'Infinity',
                                'history': {
                                    'None': 'Permanently blocked.'
                                }
                            })).encode('utf-8'), self.publickeycli, self.privatekeysrvpem)
                            self.conn.send(payload)  # 04 ##########

                            del CLIENTS_KEYS[self.conn]

                            print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Error : User {self.login} permanently blocked')
                            print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Connection closed, stopping thread activity...')

                            self.stop()

                if self.login in USERS.keys():

                    if USERS[data['login']][0] == data['password']:

                        for msg in list(MESSAGES.keys()):
                            if sys.getsizeof(MESSAGES) > 2048:
                                del MESSAGES[msg]
                            else:
                                break
                        payload = (json.dumps(
                            {'status': '<SUCCESS>', 'history': MESSAGES})).encode('utf-8')
                        data = encrypt(payload, self.publickeycli,
                                       self.privatekeysrvpem)
                        # 04 ##########
                        self.conn.send(
                            encrypt(payload, self.publickeycli, self.privatekeysrvpem))
                        CLIENTS.append(self.conn)

                        message = f'---< {self.login} joined the chat >---'.encode('utf-8')
                        broadcast(message, self.conn,
                                  self.publickeycli, self.privatekeysrvpem)

                        CLIENTS_USERS[self.login] = [
                            self.conn, datetime.datetime.now()]

                    else:

                        BLOCKED_LIST[self.ip] = str(datetime.datetime.now())
                        self.conn.send(encrypt(json.dumps({'status': '<INVALIDCREDENTIALS>', 'history': {
                                       'None': 'Invalid credentials.'}}).encode('utf-8'), self.publickeycli, self.privatekeysrvpem))

                        del CLIENTS_KEYS[self.conn]
                        print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Error : Invalid credentials.')
                        print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Connection closed, stopping thread activity...')

                else:

                    BLOCKED_LIST[self.ip] = str(datetime.datetime.now())
                    self.conn.send(encrypt(json.dumps({'status': '<INVALIDCREDENTIALS>', 'history': {
                                   'None': 'Invalid credentials.'}}).encode('utf-8'), self.publickeycli, self.privatekeysrvpem))

                    del CLIENTS_KEYS[self.conn]

                    print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Error : Invalid credentials')
                    print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Connection closed, stopping thread activity...')

                    self.stop()

        except KeyboardInterrupt:

            if self.conn in CLIENTS_KEYS:
                del CLIENTS_KEYS[self.conn]

            print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Closing connection & thread activity...')

            self.stop()

        except Exception as e:

            if self.conn in CLIENTS_KEYS:
                del CLIENTS_KEYS[self.conn]

            print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Error : unexpected exception occured : {e}')
            print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Connection closed, stopping thread activity...')

            self.stop()

        else:

            self.listner()

    def listner(self):

        while not self.stopped():

            try:
                starttime = time.time()

                while (time.time() - starttime) > 60:
                    message = self.conn.recv(8192)

                    if message != b'':

                        message = decrypt(
                        message, self.publickeycli, self.privatekeysrvpem)
                        print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] {self.login} > {message}')

                        message_to_send = "< {} > {}".format(
                            self.login, message).encode('utf-8')
                        MESSAGES[str(datetime.datetime.now())
                                ] = message_to_send.decode("utf-8")

                        broadcast(message_to_send, self.conn,
                                self.publickeycli, self.privatekeysrvpem)

                    else:

                        message = f'---< {self.login} left the chat >---'.encode('utf-8')
                        broadcast(message, self.conn, self.publickeycli,
                                self.privatekeysrvpem)

                        _remove(self.conn)

                        if self.login in CLIENTS_USERS:
                            del CLIENTS_USERS[self.login]
                        if self.conn in CLIENTS_KEYS:
                            del CLIENTS_KEYS[self.conn]

                        print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Recieved null-byte, closing connection.')
                        print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Connection closed, stopping thread activity...')

                        self.stop()

                if (time.time() - starttime) > 60:

                    self.conn.send(b'')
                    continue
                    
            except KeyboardInterrupt:

                message = f'---< {self.login} left the chat >---'.encode('utf-8')
                broadcast(message, self.conn, self.publickeycli,
                          self.privatekeysrvpem)

                _remove(self.conn)

                if self.login in CLIENTS_USERS:
                    del CLIENTS_USERS[self.login]
                if self.conn in CLIENTS_KEYS:
                    del CLIENTS_KEYS[self.conn]

                print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Closing connection & thread activity...')

                self.stop()

            except Exception as e:

                message = f'---< {self.login} left the chat >---'.encode('utf-8')
                broadcast(message, self.conn, self.publickeycli,
                          self.privatekeysrvpem)

                if self.login in CLIENTS_USERS:
                    del CLIENTS_USERS[self.login]
                if self.conn in CLIENTS_KEYS:
                    del CLIENTS_KEYS[self.conn]

                _remove(self.conn)

                print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Error : unexpected exception occured : {e}')
                print(f'[{datetime.datetime.now()}] [{self.ip}:{self.port}] [{self.name}] > Connection closed, stopping thread activity...')

                self.stop()

    def stopped(self):

        return self._stop_event.is_set()

    def stop(self):

        self._stop_event.set()

        return

###################################################################################################
###################################################################################################


def shutdown():
    global handshakeProcessActivity

    print('[{}] [Server] [Main] > Causing fatal errors to stop server activity.'.format(
        datetime.datetime.now()))

    f1 = open('messages.json', 'w', encoding='utf-8')
    f1.write(json.dumps(MESSAGES, indent=4, ensure_ascii=False))
    f1.close()

    f2 = open('blocked.json', 'w', encoding='utf-8')
    f2.write(json.dumps(BLOCKED_LIST, indent=4, ensure_ascii=False))
    f2.close()

    handshakeProcessActivity = False

    for thread in THREADS:
        thread._stop_event.set()

    server.close()
    sys.exit()


def handshakeThread(server, publickeysrvpem, privatekeysrvpem):
    global handshakeProcessActivity

    keys = [publickeysrvpem, privatekeysrvpem]
    while handshakeProcessActivity:
        try:
            conn, addr = server.accept()
            print('[{}] [Server] [Main] > Detected connection from {}, starting new threaded TCP listner.'.format(
                datetime.datetime.now(), addr[0]))
            thread = ClientThread(conn, addr, keys)
            THREADS[conn] = thread
            thread.start()
        except Exception as e:
            print(f'[{datetime.datetime.now()}] [Server] [Handshake] > Error : unexpected exception occured : {e}')
            handshakeProcessActivity = False


def kick(connection, sit):

    thread = THREADS[connection]

    if sit == 'kick':

        connection.send(encrypt('You have been kicked from the server.'.encode(
            'utf-8'), thread.publickeycli, thread.privatekeysrvpem))

    else:

        connection.send(encrypt('Your account have been permanently blocked.'.encode(
            'utf-8'), thread.publickeycli, thread.privatekeysrvpem))

    thread._stop_event.set()

    connection.close()


def main():

    global handshakeProcess

    while True:

        cmd = sys.stdin.readline()
        sys.stdout.write(f'[{datetime.datetime.now()}] [Server] [Console] > ')
        sys.stdout.write(cmd)
        sys.stdout.flush()

        cmd = cmd.replace('\n', '')
        if cmd.lower() == 'stop':

            shutdown()

        elif (cmd.lower()).startswith('unban'):

            data = cmd.split(" ")

            if len(data) != 2:

                print('[{}] [Server] [Main] > Error while parsing command args. Usage : unban <user>'.format(
                    datetime.datetime.now()))

            else:

                data = data[1]

                if data in USERS.keys():

                    if data in BLOCKED_LIST.keys():

                        del BLOCKED_LIST[data]

                        print('[{}] [Server] [Main] > User {} succesefully unbanned.'.format(
                            datetime.datetime.now(), data))

                    else:

                        print(f'[{datetime.datetime.now()}] [Server] [Main] > Error : User already unbanned.')

                else:

                    print(f'[{datetime.datetime.now()}] [Server] [Main] > Error : User does not exist.')

        elif (cmd.lower()).startswith('kick'):

            data = cmd.split(" ")

            if len(data) != 2:

                print('[{}] [Server] [Main] > Error while parsing command args. Usage : kick <user>'.format(
                    datetime.datetime.now()))

            else:

                data = data[1]

                if data in USERS.keys() and data in CLIENTS_USERS.keys():

                    kick(CLIENTS_USERS[data][0], 'kick')

                    print(f'[{datetime.datetime.now()}] [Server] [Main] > User {data} kicked succesefully.')

                else:

                    print(f'[{datetime.datetime.now()}] [Server] [Main] > Error : User does not exist or offline.')

        elif (cmd.lower()).startswith('ban'):

            data = cmd.split(" ")

            if len(data) != 2:

                print('[{}] [Server] [Main] > Error while parsing command args. Usage : ban <user>'.format(
                    datetime.datetime.now()))

            else:

                data = data[1]

                if data in USERS.keys():

                    BLOCKED_LIST[data] = 'Inf'

                    if data in CLIENTS_USERS.keys():

                        conn = CLIENTS_USERS[data][0]

                        print('[{}] [Server] [Main] > User {} is online, closing connection.'.format(
                            datetime.datetime.now(), data))

                        kick(conn, 'ban')

                    print('[{}] [Server] [Main] > User {} succesefully blocked.'.format(
                        datetime.datetime.now(), data))

                else:

                    print(f'[{datetime.datetime.now()}] [Server] [Main] > Error : User does not exist.')

        elif (cmd.lower()).startswith('broadcast'):

            data = cmd.split(" ")

            if len(data) == 1:

                print('[{}] [Server] [Main] > Error while parsing command args. Usage : broadcast <message>'.format(
                    datetime.datetime.now()))

            else:

                data.pop(0)
                data = " ".join(data)
                data = data + '\n'
                data = ("< SERVER > {}".format(data)).encode('utf-8')

                MESSAGES[str(datetime.datetime.now())] = data.decode('utf-8')

                for _conn in CLIENTS:
                
                	try:
                
                		publickeycli = CLIENTS_KEYS[_conn]
                		_conn.send(encrypt(data, publickeycli, privatekeysrv))
                
                	except Exception as e:
                
                		print('[{}] [Server] [Broadcast] > Error : unexpected exception occured : {}'.format(datetime.datetime.now(), e))
                		_conn.close()
                		_remove(_conn)

        elif cmd.lower() == 'blocked':

            total = len(list(BLOCKED_LIST.keys()))

            if total == 0:

                print('There is no blocked IPs or accounts.')

            else:

                print('Total {} blocked IPs & accounts'.format(total))

            timestamp = datetime.datetime.now()

            for item in BLOCKED_LIST.keys():

                if BLOCKED_LIST[item] != 'Inf':

                    left_time = round((timestamp - datetime.datetime.strptime(
                        BLOCKED_LIST[item], '%Y-%m-%d %H:%M:%S.%f')).total_seconds(), 1)

                    if left_time > 60:

                        status = 'UNLOCKED'

                    else:

                        status = 'TEMPORARY BLOCKED FOR {}'.format(
                            60 - left_time)

                else:

                    status = 'PERMANENTLY BLOCKED'

                print('> {} : {}'.format(item, status))

        elif cmd.lower() == 'publickeys':

            print(CLIENTS_KEYS)

        elif cmd.lower() == 'online':
            print(CLIENTS_USERS)
            print('Online users:')

            for item in CLIENTS_USERS.keys():

                print('User {} since {}'.format(item, CLIENTS_USERS[item][1]))
        else:

            print('[{}] [Server] [Console] > Error : No such command. Type "help" to see list of available commands.'.format(
                datetime.datetime.now()))


if __name__ == "__main__":

    try:

        timedelta = datetime.datetime.now()

        print(f'[{datetime.datetime.now()}] [Server] [Main] > Generating RSA keypair.')

        privatekeysrv = RSA.generate(2048)
        privatekeysrvpem = privatekeysrv.exportKey('PEM')

        print(f'[{datetime.datetime.now()}] [Server] [Main] > RSA keypair generated for {round(((datetime.datetime.now() - timedelta).total_seconds()), 1)} seconds.')

        publickeysrv = privatekeysrv.publickey()
        publickeysrvpem = publickeysrv.exportKey('PEM')

        arg_payload = [publickeysrvpem, privatekeysrv]

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        print(f'[{datetime.datetime.now()}] [Server] [Main] > Binding server to {HOST}:{PORT}.')

        server.bind((HOST, PORT))

        server.listen(500)

        f = open('users.json', 'r+')

        f1 = open('messages.json', 'r+')

        f2 = open('blocked.json', 'r+')

    except KeyboardInterrupt:

        print(f'\r[{datetime.datetime.now()}] [Server] [Main] > Closing...')
        sys.exit()

    except Exception as e:

        print(f'[{datetime.datetime.now()}] [Server] [Main] > Error : unexpected exception occured : {e}')
        sys.exit()

    try:
        global USERS

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

        global MESSAGES

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

        global BLOCKED_LIST

        BLOCKED_LIST = json.loads(f2.read())

    except:

        f2.close()
        f2 = open('blocked.json', 'w')
        f2.write('{}')
        f2.close()
        BLOCKED_LIST = {}

    else:

        f2.close()

    try:
        global handshakeProcessActivity

        handshakeProcessActivity = True

        handshakeProcess = Thread(target=handshakeThread, args=[
                                  server, publickeysrvpem, privatekeysrvpem])
        handshakeProcess.start()

        global mainProcess

        mainProcess = Thread(target=main)
        mainProcess.start()

    except KeyboardInterrupt:

        print(f'[{datetime.datetime.now()}] [Server] [Main] > Closing...')

        shutdown()

    except Exception as e:

        print(f'[{datetime.datetime.now()}] [Server] [Main] > Error : unexpected error occured : {e}.')

        shutdown()
