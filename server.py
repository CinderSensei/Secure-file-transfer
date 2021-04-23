import sys
import os
import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Counter
from Crypto.PublicKey import RSA
import hashlib
import random

HOST = '127.0.0.1'
PORT = 65432

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

blocks = {}

key = RSA.generate(2048)
private_key = key.export_key()
file_out = open("private.pem", "wb")
file_out.write(private_key)
file_out.close()

public_key = key.publickey().export_key()
file_out = open("receiver.pem", "wb")
file_out.write(public_key)
file_out.close()


IV = None
session_key = None

private_key = RSA.import_key(open("private.pem").read())



filename = sys.argv[1]
filename2 = " "

block_size = 16
block_counter = 0

def getSessionKey():
	cipher_rsa = PKCS1_OAEP.new(private_key)
	global IV
	global session_key
	IV = int.from_bytes(conn.recv(16), sys.byteorder)
	session_key = cipher_rsa.decrypt(conn.recv(256))


def createBlocks():
	f = open(filename,'rb')
	global block_counter
	while True:
		string = f.read(16)
		el = {block_counter: string}
		blocks.update(el)
		if not string:
			break
		block_counter += 1
	f.close()


def block_finder(x,y):
	return (int(x) * int(y)) + int(x)

def transferBlocks():
	global block_counter
	global session_key
	global IV

	i = 0
	conn.sendall(block_counter.to_bytes(16, sys.byteorder))
	print("File is being transmitted..\n")
	while i < block_counter:

		if i == 2000 or i == 3000 or i == 4000 or i == 5237:
			i += 1
		
		head = i.to_bytes(16, sys.byteorder)

		string = blocks.get(i)
		

		length = len(string)	
		string += b"0"*(16-len(string)) # for the last block if it is smaller than 16 since i need to send fix sized packets
		

		ctr = Counter.new(128, initial_value=(IV+i))
		aes = AES.new(session_key, AES.MODE_CTR, counter=ctr)


		
		cipher2 = aes.encrypt(string)
		tail = aes.encrypt(hashlib.md5(string).digest())
		
		length = length.to_bytes(8, sys.byteorder)

		length = aes.encrypt(length)

		fin = head + cipher2 + tail + length
		conn.sendall(fin)
		i += 1
	block_counter = 0


def deliverPacket():

	
	
	arr_len = int.from_bytes(conn.recv(8), sys.byteorder)
	
	for i in range(arr_len):
	
		pack_no =  int.from_bytes(conn.recv(16), sys.byteorder)

		
		string = blocks.get(pack_no)
		
		head = pack_no.to_bytes(16, sys.byteorder)
		length = len(string)
		string += b"0"*(16-len(string))

		ctr = Counter.new(128, initial_value=(IV+pack_no))
		aes = AES.new(session_key, AES.MODE_CTR, counter=ctr)

		cipher = aes.encrypt(head)
		cipher2 = aes.encrypt(string)
		tail = aes.encrypt(hashlib.md5(string).digest())

		length = length.to_bytes(8, sys.byteorder)

		length = aes.encrypt(length)

		fin = cipher + cipher2 + tail + length
		conn.sendall(fin)
	



s.bind((HOST, PORT))
closeflag = False

while True:
	if(closeflag == True):
		s.close()
		break
	t = 2
	connflag = False
	while True:
		t = int(input("Server stand by...\n0-)Close server\n1-)Keep listening\n"))
		connflag = False
		brkflag = False
		if t == 0:
			closeflag = True
			break
		elif t==1:
			s.listen(5)
			print("Server waiting to be contacted..\n")
			conn, addr = s.accept()
			print('Connected by:', addr)

			while True:
				option = int(input("1-)Approve Connection\n2-)Transfer the file\n"))
				if option==1:
					getSessionKey()
					print("Key exchange complete!")
					option = int(input("2-)Transfer the file\n"))
					connflag = True
					while option < 2 or option > 2:
						option = int(input("Wrong option!\n2-)Transfer the file\n"))
				if option==2:
					if connflag == True:
						createBlocks()
						transferBlocks()
						controlflag = 5
						while controlflag != 4:
							controlflag = int.from_bytes(conn.recv(4), sys.byteorder)
							if controlflag == 0:
								print("All files sent are ok!\n")
							if controlflag == 1:
								deliverPacket()
								print("Sending missing packets..\n")
							if controlflag == 2:
								deliverPacket()
								print("Sending packets again..\n")
							if controlflag == 3:
								print("No retransmission needed!\n")
							if controlflag == 4:
								print("File transfer Successful!\n")
								brkflag = True
								break
					else:
						print("No connection recently! First accept the connection\n")
					if brkflag == True:
						break
		else:
			t = int(input("Wrong option. Server stand by...\n0-)Close server\n1-)Keep listening\n"))

	