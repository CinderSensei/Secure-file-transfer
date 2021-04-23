import sys
import os
import socket
import random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import hashlib

HOST = '127.0.0.1'
PORT = 65432

hasht = {}
arr = []
arr2 = []
arr3 = []
hash_hasht = {}
blockinfo = 0
missflag = False
corrflag = False

public_key = RSA.import_key(open("receiver.pem").read())

session_key = get_random_bytes(32)
IV = random.randint(0,9999999999999999) #Counter

def initiateConnection():
	s.connect((HOST, PORT))
	

def createSessionKeyandIV():
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    s.sendall(IV.to_bytes(16, sys.byteorder))
    s.sendall(enc_session_key)


def getFileData():
    global blockinfo
    global hash_hasht
    global hasht
    global session_key
    global arr
    blockinfo = s.recv(16)
    blockinfo = int.from_bytes(blockinfo, sys.byteorder)
    print("Server sending " + str(blockinfo) + " packets\n")

    rarr = []
    for i in range(5):
        rarr.append(random.randint(0,200000))

    i = 0
    while i < blockinfo: 
        
        if i==2000 or i == 3000 or i == 4000 or i == 5237: # Dropping packets to test missing retransmission
            i+=1


        data = s.recv(56)
        
        block_no = int.from_bytes(data[0:16], sys.byteorder)
        
        ctr = Counter.new(128, initial_value=(IV+block_no))
        aes = AES.new(session_key, AES.MODE_CTR, counter=ctr)
        
        plaindata = aes.decrypt(data[16:])
        
        
        block_data = plaindata[0:16]
        hash_val = plaindata[16:32]
        length = plaindata[32:40]
        length = int.from_bytes(length, sys.byteorder)
        
        if length < 16:
            block_data = plaindata[0:0+length]

        
        
        if i in rarr: # changing data to test retransmission for modified packets
            block_data = get_random_bytes(16)

        el = {block_no: block_data}
        el2 = {block_no: hash_val}
        hasht.update(el)
        hash_hasht.update(el2)
        arr.append(block_no)
        
        #print("packet #" + str(block_no) + " arrived\n")
        
        
        i+=1
        

def wr():
    f3 = open("Data"+".txt",'wb')
   


    for i in range(len(hasht)):
        if hasht.get(i) == None:
            i += 1
        f3.write(hasht.get(i))
        print("block #" + str(i) + " placed\n")

    #print("Your data is ready!\n")
    f3.close()


def isCorrupted():
    global hasht
    global hash_hasht
    global arr3
    global corrflag
    corrflag = False

    for i in range(len(hasht)):
        if hasht.get(i) == None or hash_hasht.get(i) == None:
            i+=1
        chckdata = hasht.get(i)
        chckhash = hash_hasht.get(i)
        if i == len(hasht)-1:
            chckdata += b"0"*(16-len(chckdata))
        if chckhash != hashlib.md5(chckdata).digest():
            arr3.append(i)
            corrflag = True


def requestCorrupted():
    global arr3
    global hasht
    global hash_hasht

    arr3.sort()
    s.sendall(len(arr3).to_bytes(8, sys.byteorder))
    for i in range(len(arr3)):
    
        req_val = arr3[i].to_bytes(16, sys.byteorder)
        s.sendall(req_val)

        data = s.recv(56)
        
        ctr = Counter.new(128, initial_value=(IV+arr3[i]))
        aes = AES.new(session_key, AES.MODE_CTR, counter=ctr)
        
        plaindata = aes.decrypt(data)
        
        block_no = plaindata[0:16]
        block_data = plaindata[16:32]       
        hash_val = plaindata[32:48]
        length = plaindata[48:56]
        
        length = int.from_bytes(length, sys.byteorder)
        block_no = int.from_bytes(block_no, sys.byteorder)

        if length < 16:
            block_data = plaindata[16:16+length]

       
        el = {block_no: block_data}
        el2 = {block_no: hash_val}
        hasht.update(el)
        hash_hasht.update(el2)
        print("File #" + str(arr3[i]) + " Fixed!")

    arr3.clear()



def isMissing():
    global arr
    global arr2
    global blockinfo
    global missflag
    missflag = False

    arr.sort()
    for i in range(blockinfo):
        if i > len(arr)-1:
            arr.append(i)            
            arr2.append(i)
            arr.sort()
            missflag = True
        
        elif i != arr[i]:
            arr.append(i)            
            arr2.append(i)
            arr.sort()
            missflag = True



def requestMissing():
    global arr
    global arr2
    global hasht
    global hash_hasht    


    s.sendall(len(arr2).to_bytes(8, sys.byteorder))      

    for i in range(len(arr2)):
    
        req_val = arr2[i].to_bytes(16, sys.byteorder)
        s.sendall(req_val)

        data = s.recv(56)
        
        ctr = Counter.new(128, initial_value=(IV+arr2[i]))
        aes = AES.new(session_key, AES.MODE_CTR, counter=ctr)
        
        plaindata = aes.decrypt(data)
        
        block_no = plaindata[0:16]
        block_data = plaindata[16:32]       
        hash_val = plaindata[32:48]
        length = plaindata[48:56]
        
        length = int.from_bytes(length, sys.byteorder)
        block_no = int.from_bytes(block_no, sys.byteorder)

        if length < 16:
            block_data = plaindata[16:16+length]


        el = {block_no: block_data}
        el2 = {block_no: hash_val}
        hasht.update(el)
        hash_hasht.update(el2)
        print("File #" + str(arr2[i]) + " recovered!")
    arr2.clear()








connflag = False
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    option = int(input("1-)Initiate a new connection\n2-)Get file data\n3-)Close the connection\n"))
    while True:
        if connflag == False:
            while option > 1 or option < 1:
                option = int(input("No connection established yet! Make the connection first\n1-)Initiate a new connection\n2-)Get file data\n3-)Close the connection\n"))
        if option == 1:
            initiateConnection()
            createSessionKeyandIV()
            connflag = True
            option = int(input("Connection established!\n2-)Get file data\n3-)Close the connection\n"))
            while option > 3 or option < 2:
                option = int(input("Wrong menu option!\n2-)Get file data\n3-)Close the connection\n"))
        if option==2:
            if connflag == True:
                getFileData()
                print("File transfer Complete!\n")
                while True:
                    chckoption = int(input("0-)Exit\n1-)Check missing blocks\n2-)Check corrupted blocks\n"))
                    while chckoption < 0 or chckoption > 2:
                        chckoption = int(input("Wrong option!\n0-)Exit\n1-)Check missing blocks\n2-)Check corrupted blocks\n"))
                    if chckoption == 0:
                        break
                    if chckoption == 1:
                        isMissing()
                        if missflag:
                            print("Missing files found! Fixing..")
                            controlflag = 1
                            s.sendall(controlflag.to_bytes(4,sys.byteorder))
                            requestMissing()
                            print("Missing files fixed!")    
                            

                        else:
                            print("No missing files found!")
                            controlflag = 0
                            s.sendall(controlflag.to_bytes(4,sys.byteorder))
                            

                    if chckoption == 2:
                        isCorrupted()
                        if corrflag:
                            print("Corrupted files found! Fixing..")
                            controlflag = 2
                            s.sendall(controlflag.to_bytes(4,sys.byteorder))
                            requestCorrupted()
                            print("Corrupted files fixed!")
                            
                        else:
                            print("No corrupted files found!")
                            controlflag = 3
                            s.sendall(controlflag.to_bytes(4,sys.byteorder))
                            
                connflag = False
                controlflag = 4
                s.sendall(controlflag.to_bytes(4,sys.byteorder))
                print("You are being disconnected..")
                break
            else:
                print("No connection established! Establish the connection first\n")
        if option==3:
            connflag = False
            break

wr()