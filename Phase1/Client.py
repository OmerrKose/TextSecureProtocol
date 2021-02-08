import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import Crypto.Random.random 
import random
import re
import json
from ecpy.curves import Curve,Point
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA


# KEY GENERETAION
def key_gen (P, n):
	sA = Crypto.Random.random.randint(0, n-1)
	QA = sA * P
	return QA, sA #Return public and secret key

# SIGNATURE GENERATION
def sign_gen(message, sA, P, n):
	message = message.encode()
	k = Crypto.Random.random.randint(1, n-2)
	R = k * P
	r = (R.x) % n #R.x is the x coordinate of R
	hashed = SHA3_256.new(message + r.to_bytes((r.bit_length()+7)//8, byteorder='big')) 
	h = int.from_bytes(hashed.digest(), byteorder='big') % n
	s = ((sA * h) + k) % n 
	return s, h

# SIGNATURE VERIFICATION
def sign_ver(s, h, P, QA, n, message):
	V = (s * P) - (h * QA)
	v = (V.x) % n #Where V.x is the x coordinate of V
	h_ = SHA3_256.new(message + v.to_bytes((v.bit_length()+7)//8, byteorder='big'))
	h2 = int.from_bytes(h_.digest(), byteorder = 'big') % n
	if (h2 == h):
		print("Accepted") 
	else:
		print("Rejected")


API_URL = 'http://cryptlygos.pythonanywhere.com'

stuID = 25224 #I had some issues with my stuID: 25224 so I had to proceed with Emre's ID 
stuID = str(stuID) #Change integer into string to use it in sign_gen function

# the curve
E = Curve.get_curve('secp256k1')
n = E.order
P = E.generator # Point

#HERE CREATE A LONG TERM KEY
# Q_A, s_A = key_gen(P, n) #Q_A is QA, s_A is sA from key_gen function
s_A = 134546546875157984751674986167
# print("Public key (x) is: ", Q_A.x, "\n", "Public key (y) is: ", Q_A.y)
# print("Private key is: ", s_A)
Q_A = s_A * P
s, h = sign_gen(stuID, s_A, P, n)
lkey = Q_A

'''
long term key: 29509839102577586074222745452099993053858858295471327937448704866823537944680 1024925158760875829467971466875796383909857881698104990455099328883912911929
774740310271439311185998702106838374589196288470948605258024798998019684805274606822709352697515475497776019606463787798459399503160249745210380920
'''
#server's long term key
QSer_long = Point(0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9 , 0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c, E)


# HERE GENERATE A EPHEMERAL KEY 
QA, sA = key_gen(P, n) #QA is QA, sA is sA from key_gen function
ekey = QA
print("2.2.1")


try:
	#REGISTRATION
	# mes = {'ID':stuID, 'h': h, 's': s, 'LKEY.X': lkey.x, 'LKEY.Y': lkey.y}
	# response = requests.put('{}/{}'.format(API_URL, "RegStep1"), json = mes)		
	# if((response.ok) == False): raise Exception(response.json())
	# print(response.json())

	# print("Enter verification code which is sent to you: ")	
	# code = int(input())

	# mes = {'ID':stuID, 'CODE': code}
	# response = requests.put('{}/{}'.format(API_URL, "RegStep3"), json = mes)
	# if((response.ok) == False): raise Exception(response.json())
	# print(response.json())


	#STS PROTOCOL
	mes = {'ID': stuID, 'EKEY.X': ekey.x, 'EKEY.Y': ekey.y}
	response = requests.put('{}/{}'.format(API_URL, "STSStep1&2"), json = mes)
	if((response.ok) == False): raise Exception(response.json())
	res=response.json()
	
	Q_B = Point(res['SKEY.X'], res['SKEY.Y'], E) # Creating point with returned response from the server
	
	#CALCULATE T, K, U
	
	T = sA * Q_B
	U = str(T.x) + str(T.y) + "BeYourselfNoMatterWhatTheySay" #Creating U
	U = U.encode()
	K = SHA3_256.new(U) #Cretaing K
	print("2.2.3")

	#SIGN MESSAGE

	#sL = 7486108231233185216953507621871585501672160862165401179319193705092911058079 # Long term private key
	W1 = str(QA.x) + str(QA.y) + str(Q_B.x) + str(Q_B.y) #Concetanetion of strings
	sigA_S, sigA_H = sign_gen(W1, s_A, P, n) #Signing the W1 with private key
	print("2.2.4")

	# ENCRYPTION

	txt = "s" + str(sigA_S) + "h" + str(sigA_H)  #Creating txt to be encrypted
	K = K.digest()
	Y = AES.new(K, AES.MODE_CTR) #Create AES object to use
	Y1 = Y.encrypt(txt.encode()) #Use created object to encrypt ciphertext
	ctext = Y.nonce + Y1 #Concatenate the object with ciphertext
	ctext = int.from_bytes(ctext, byteorder = 'big') #Convert it back to integer
	print("Encryption")

	###Send encrypted-signed keys and retrive server's signed keys
	mes = {'ID': stuID, 'FINAL MESSAGE': ctext}
	response = requests.put('{}/{}'.format(API_URL, "STSStep4&5"), json = mes)
	if((response.ok) == False): raise Exception(response.json()) 
	ctext = response.json() 

	#DECRYPTION 
	
	#Try to obtain signature values used by the server
	ctext = ctext.to_bytes((ctext.bit_length() + 7)//8, byteorder = 'big')
	c = AES.new(K, AES.MODE_CTR, nonce = ctext[0:8]) #Create new AES object to decrypt the obtained value
	Y2 = c.decrypt(ctext[8:]) #Decrypt ctext after nonced part
	Y2 = Y2.decode("utf-8") #Decoding

	#Obtain h and s values from the server's message to use it in verification
	H = Y2.find('h') #Findin h from the message to separate the sigB_H and sigB_S
	sigB_H = int(Y2[H + 1:])
	sigB_S = int(Y2[1: H])
	
	#Create W2 to verify the signature

	W2 = str(Q_B.x) + str(Q_B.y) + str(QA.x) + str(QA.y) #Creating W2 objcet from Q_B and QA

	#VERIFICATION

	sign_ver(sigB_S, sigB_H, P, QSer_long, n, W2.encode()) #Verify the recieved message using the W2 created and print the necessary results
	print("2.2.5")

	#get a message from server for 
	mes = {'ID': stuID}
	response = requests.get('{}/{}'.format(API_URL, "STSStep6"), json=mes)
	ctext= response.json()         
	print(ctext)

	#Decrypt

	ctext = ctext.to_bytes((ctext.bit_length() + 7)//8, byteorder = 'big') #Converting to bytes for performing operations
	d = AES.new(K, AES.MODE_CTR, nonce = ctext[0:8]) #Creating AES object to decrypt the recieved message
	W3 = d.decrypt(ctext[8:]) #Decryption after the nonced part
	W3 = W3.decode("utf-8")

	seperate = W3.find('.') #Finding "." to seperate random and message
	Rand = int(W3[seperate + 2:])
	Mess = W3[:seperate]
	print("2.2.6")

	#Add 1 to random to create the new message and encrypt it

	W4 = str(Mess) + str(Rand + 1) 
	e = AES.new(K, AES.MODE_CTR) #Creating new AES object
	ct = str(e.nonce) + W4 #Adding nonce to the ct 
	ct = e.encrypt(ct.encode()) #Encryption of ct
	ct = int.from_bytes(ct, byteorder = 'big') #Converting to integer from bytes to send to the server
	
	#send the message and get response of the server
	mes = {'ID': stuID, 'ctext': ct}
	response = requests.put('{}/{}'.format(API_URL, "STSStep7&8"), json = mes)
	ctext= response.json()         
	print("2.2.7")

#ÖMER KÖSE 25224, EMRE TAŞÇI 25467

except Exception as e:
	print(e)
