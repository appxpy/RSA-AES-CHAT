import eel
from PIL import Image, ImageDraw, ImageFont
import os
import hashlib
import socket
import datetime
import select
import sys
import json
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Cipher import AES
from Cryptodome import Random
import sys
import threading

global DEBUG
global SHUTDOWN
global publickeycli
global privatekeysrv
SHUTDOWN = False

DEBUG = True

publickeycli = b''
privatekeysrv = b''

HOST = '10.0.0.100'
PORT = 8008

eel.init('web')

def stop(server):
	server.close()

@eel.expose()
def generateKeys():

		timedelta = datetime.datetime.now()

		if DEBUG:
			print('[{}] [Main] > Generating RSA keypair.'.format(
				datetime.datetime.now()))

		global privatekeycli
		privatekeycli = RSA.generate(2048)

		privatekeyclipem = privatekeycli.exportKey('PEM')

		if DEBUG:
			print('[{}] [Main] > RSA keypair generated for {} seconds.'.format(
				datetime.datetime.now(), (datetime.datetime.now() - timedelta).total_seconds()))

		global publickeycli
		global publickeyclipem
		publickeycli = privatekeycli.publickey()

		publickeyclipem = publickeycli.exportKey('PEM')
		
		return True

@eel.expose()

def auth(login, password):

	try:

		global publickeycli
		global privatekeycli
		global publickeyclipem

		print('[{}] [Main] > Connecting to server.'.format(datetime.datetime.now()))

		global server
		server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	
		server.connect((HOST, PORT))

	except KeyboardInterrupt:

		print('[{}] [Main] > Closing...'.format(datetime.datetime.now()))

		stop(server)

		return '{"status": "<KEYBOARDINTERRUPT>"}'
		#ERR CODE 0001
	except Exception as e:

		print('[{}] [Main] > Error : Server is unreachable : {}'.format(
			datetime.datetime.now(), e))

		return '{"status": "<SERVERUNREACHABLE>"}'

	try:

		publickeysrvpem = server.recv(8192)  # 01 ##########

		if DEBUG:

			print('[{}] [Main] > Recieved greeting packet from server.'.format(
				datetime.datetime.now()))

		server.send(publickeyclipem)  # 02 ##########

		publickeysrv = RSA.importKey(publickeysrvpem)

		if DEBUG:
			print('[{}] [Main] > RSA key exchange completed successefully.'.format(
				datetime.datetime.now()))
		####AUTH####

		if DEBUG:
			print('[{}] [Main] > Starting authorization algorythm.'.format(
				datetime.datetime.now()))

		password = SHA256.new(password.encode('utf-8')).hexdigest()

		payload = {'login': login, 'password': password}

		server.send(encrypt((json.dumps(payload)).encode(
			'utf-8'), publickeysrv))  # 03 ##########

		if DEBUG:

			print('[{}] [Main] > Sending encrypted auth credentials to server.'.format(
				datetime.datetime.now()))

		data = server.recv(8192)  # 04 ##########

		if DEBUG:

			print('[{}] [Main] > Recieved server response.'.format(
				datetime.datetime.now()))

		dataJson = decrypt(data, publickeysrv)

		data = json.loads(dataJson)

		if data['status'] == '<INVALIDCREDENTIALS>':

			print('[{}] [Main] > Error : Invalid login or password.'.format(
				datetime.datetime.now()))

			stop(server)

			return dataJson

		elif data['status'] == '<ALREADYONLINE>':

			print('[{}] [Main] > Error : User with such nickname already online.'.format(
				datetime.datetime.now()))

			stop(server)

			return dataJson

		elif data['status'] == '<TEMPBLOCKED>':

			left_ban_time = data['timestamp']

			print('[{}] [Main] > Error : This account temporary blocked for {} second(s).'.format(
				datetime.datetime.now(), left_ban_time))

			stop(server)

			return dataJson

		elif data['status'] == '<BLOCKED>':

			print('[{}] [Main] > Error : This account blocked.'.format(
				datetime.datetime.now()))

			stop(server)

			return dataJson

		elif data['status'] == '<SUCCESS>':

			print('[{}] [Main] > Authorization successeful!'.format(
				datetime.datetime.now()))
			for message in data['history'].items():
				print(message[1] + '\n', end='')

			global listnerThread
			listnerThread = threading.Thread(target=listner, args=(server,))
			listnerThread.start()

			return dataJson

			

	except Exception as e:
		print('[{}] [Main] > Error : Unexpected error occured during authorization process : {}.'.format(
			datetime.datetime.now(), e))
		
		stop(server)

		return '{"status": "<EXCEPTION>", "text": "{e}"}'.format(e)

	except KeyboardInterrupt:
		print('[{}] [Main] > Closing...'.format(
			datetime.datetime.now()))

		stop(server)

		return '{"status": "<KEYBOARDINTERRUPT>"}'

def encrypt(message, publickeysrv):
	global DEBUG
	payload = []
	timedelta = datetime.datetime.now()
	if DEBUG:
		print('[{}] [Main] > Generating signature.'.format(
			datetime.datetime.now()))
	####################################################################################################
	myhash = SHA256.new(message)
	signature = PKCS1_v1_5.new(privatekeycli)
	signature = signature.sign(myhash)
	if DEBUG:
		print('[{}] [Main] > Message succesefully signed with signature.'.format(
			datetime.datetime.now()))
	# signature encrypt
	if DEBUG:
		print('[{}] [Main] > Encrypting signature.'.format(
			datetime.datetime.now()))
	cipherrsa = PKCS1_OAEP.new(publickeysrv)
	sig = cipherrsa.encrypt(signature[:128])
	sig = sig + cipherrsa.encrypt(signature[128:])
	payload.append(sig)
	####################################################################################################
	if DEBUG:
		print('[{}] [Main] > Generating 256 bit session key.'.format(
			datetime.datetime.now()))
	# creation 256 bit session key
	sessionkey = Random.new().read(32)  # 256 bit
	# encryption AES of the message
	if DEBUG:
		print('[{}] [Main] > Encryption AES of the message.'.format(
			datetime.datetime.now()))
	iv = Random.new().read(16)  # 128 bit
	obj = AES.new(sessionkey, AES.MODE_CFB, iv)
	ciphertext = iv + obj.encrypt(message)  # SEND DATA
	payload.append(ciphertext)
	# encryption RSA of the session key
	if DEBUG:
		print('[{}] [Main] > Encryption RSA of the session key.'.format(
			datetime.datetime.now()))
	cipherrsa = PKCS1_OAEP.new(publickeysrv)
	sessionkey = cipherrsa.encrypt(sessionkey)  # SEND DATA
	payload.append(sessionkey)

	payload1 = b'\x00\x01\x01\x00'.join(payload)
	if DEBUG:
		print('[{}] [Main] > Message succesefully encrypted for {} seconds.'.format(
			datetime.datetime.now(), (datetime.datetime.now() - timedelta).total_seconds()))
	payload_recieved = payload1.split(b'\x00\x01\x01\x00')
	if payload == payload_recieved and len(payload) == 3:
		if DEBUG:
			print('[{}] [Main] > Payload not corrupted.'.format(
				datetime.datetime.now()))
		return(payload1)
	else:
		print('[{}] [Main] > Error : Message corrupted! Payload parts {}/{}/3'.format(
			datetime.datetime.now(), len(payload), len(payload_recieved)))
		return(b'')


def decrypt(data, publickeysrv):
	global DEBUG
	timedelta = datetime.datetime.now()
	if DEBUG:
		print('[{}] [Main] > Parsing data.'.format(datetime.datetime.now()))
	payload = data.split(b'\x00\x01\x01\x00')
	signature = payload[0]
	ciphertext = payload[1]
	sessionkey = payload[2]
	# decryption session key
	if DEBUG:
		print('[{}] [Main] > Decrypting session key.'.format(
			datetime.datetime.now()))
	cipherrsa = PKCS1_OAEP.new(privatekeycli)
	sessionkey = cipherrsa.decrypt(sessionkey)
	# decryption message
	if DEBUG:
		print('[{}] [Main] > Decrypting message.'.format(
			datetime.datetime.now()))
	iv = ciphertext[:16]
	obj = AES.new(sessionkey, AES.MODE_CFB, iv)
	message = obj.decrypt(ciphertext)
	message = message[16:]
	if DEBUG:
		print('[{}] [Main] > Decrypting signature.'.format(
			datetime.datetime.now()))
	# decryption signature
	####################################################################################################
	cipherrsa = PKCS1_OAEP.new(privatekeycli)
	sig = cipherrsa.decrypt(signature[:256])
	sig = sig + cipherrsa.decrypt(signature[256:])
	if DEBUG:
		print('[{}] [Main] > Signature verification.'.format(
			datetime.datetime.now()))
	# signature verification

	verification = PKCS1_v1_5.new(
		publickeysrv).verify(SHA256.new(message), sig)
	####################################################################################################

	if verification == True:
		if DEBUG:
			print('[{}] [Main] > Signature succesefully verified.'.format(
				datetime.datetime.now()))
			print('[{}] [Main] > Message successefully decrypted for {} seconds'.format(
				datetime.datetime.now(), (datetime.datetime.now() - timedelta).total_seconds()))
	else:
		print('< SECURITY ALERT >')
		print('[{}] [Main] > Error : Signature verification failure, your data not secure, please reconnect.'.format(
			datetime.datetime.now()))
	return message.decode('utf-8')




@eel.expose
def sendData(message):
	try:

		global server
		global publickeysrv
		server.send(encrypt(
			message.encode('utf-8'), publickeysrv))

	except Exception as e:

		#error_message 0009 Message sending failure

		stop(server)


def listner(server):
	try:
		global SHUTDOWN
		while not SHUTDOWN:

			sockets_list = [sys.stdin, server]

			read_sockets, write_socket, error_socket = select.select(
				sockets_list, [], [])

			for socks in read_sockets:

				if socks == server:

					message = socks.recv(8192)

					if message == b'':

						stop(server)

					else:

						print(decrypt(message, self.publickeysrv))

	except Exception as e:
		print('[{}] [Main] > Error : Unexpected error occured during authorization process : {}.'.format(
			datetime.datetime.now(), e))
		
		stop(server)

		SHUTDOWN = True

	except KeyboardInterrupt:
		print('[{}] [Main] > Closing...'.format(
			datetime.datetime.now()))

		stop(server)


		SHUTDOWN = True

def draw_ellipse(image, bounds, width=1, outline='white', antialias=4):
	"""Improved ellipse drawing function, based on PIL.ImageDraw."""

	# Use a single channel image (mode='L') as mask.
	# The size of the mask can be increased relative to the imput image
	# to get smoother looking results. 
	mask = Image.new(
		size=[int(dim * antialias) for dim in image.size],
		mode='L', color='black')
	draw = ImageDraw.Draw(mask)

	# draw outer shape in white (color) and inner shape in black (transparent)
	for offset, fill in (width/-2.0, 'gray'), (width/2.0, 'black'):
		left, top = [(value + offset) * antialias for value in bounds[:2]]
		right, bottom = [(value - offset) * antialias for value in bounds[2:]]
		draw.ellipse([left, top, right, bottom], fill=fill)

	# downsample the mask using PIL.Image.LANCZOS 
	# (a high-quality downsampling filter).
	mask = mask.resize(image.size, Image.LANCZOS)
	# paste outline color to input image through the mask
	image.paste(outline, mask=mask)


@eel.expose
def generatePic(txt="NO DATA", status ='Offline', size=55, color=(255,255,0), bg=(255,0,0,0)):
	import hashlib
	hash_object = hashlib.sha256(txt.encode('utf-8'))
	filename = hash_object.hexdigest()
	W, H = (55,55)
	ellipse_box = [27.5,27.5,27.5,27.5]
	img_fraction = 0.8
	fontsize = 1
	font = ImageFont.truetype('UbuntuMono-Regular.ttf', fontsize)
	image = Image.new(mode = "RGBA", size = (55,55), color = bg)
	while font.getsize(txt)[0] < img_fraction*image.size[0]:
		# iterate until the text size is just larger than the criteria
		fontsize += 1
		font = ImageFont.truetype("UbuntuMono-Regular.ttf", fontsize)

	fontsize -= 1
	font = ImageFont.truetype("UbuntuMono-Regular.ttf", fontsize)

	draw = ImageDraw.Draw(image)

	w, h = draw.textsize(txt, font=font)
	
	draw_ellipse(image, ellipse_box, width=48)

	draw_ellipse(image, [2.5,2.5,52.5,52.5], outline=(102,204,102), width=3, antialias=8)

	draw.text(((W-w)/2,(H-h)/2.25), txt, font=font, fill='black') # put the text on the image

	image.save(r'web/img/' + filename + '_online.png')

	image = Image.new(mode = "RGBA", size = (55,55), color = bg)

	draw = ImageDraw.Draw(image)

	w, h = draw.textsize(txt, font=font)
	
	draw_ellipse(image, ellipse_box, width=48, outline=(67, 71, 83))

	draw_ellipse(image, [2.5,2.5,52.5,52.5], outline=(67, 71, 83), width=3, antialias=8)

	draw.text(((W-w)/2,(H-h)/2.25), txt, font=font, fill='black') # put the text on the image

	image.save(r'web/img/' + filename + '_offline.png')

	return([filename, txt, status])

eel.start('index.html', port=8080)