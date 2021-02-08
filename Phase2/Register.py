####### ÖMER KÖSE 25224 #######

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

API_URL = 'http://cryptlygos.pythonanywhere.com'

stuID =  25224 
stuID = str(stuID)

###### KEY GENERETAION ######
def key_gen (P, n):
	sA = Crypto.Random.random.randint(0, n-1)
	QA = sA * P
	return QA, sA #Return public and secret key

###### SIGNATURE GENERATION ######
def sign_gen(message, sA, P, n):
	message = message.encode()
	k = Crypto.Random.random.randint(1, n-2)
	R = k * P
	r = (R.x) % n #R.x is the x coordinate of R
	hashed = SHA3_256.new(message + r.to_bytes((r.bit_length()+7)//8, byteorder='big')) 
	h = int.from_bytes(hashed.digest(), byteorder='big') % n
	s = ((sA * h) + k) % n 
	return s, h

###### SIGNATURE VERIFICATION ######
def sign_ver(s, h, P, QA, n, message):
	V = (s * P) - (h * QA)
	v = (V.x) % n #Where V.x is the x coordinate of V
	h_ = SHA3_256.new(message + v.to_bytes((v.bit_length()+7)//8, byteorder='big'))
	h2 = int.from_bytes(h_.digest(), byteorder = 'big') % n
	if (h2 == h):
		print("Accepted") 
	else:
		print("Rejected")


###### THE CURVE ######
E = Curve.get_curve('secp256k1')
n = E.order
P = E.generator # Point

###### CREATING A LONG TERM KEY TO REGISTER TO THE SERVER ######
Q_A, s_A = key_gen(P, n) #Q_A is QA, s_A is sA from key_gen function
print("Public key (x) is: ", Q_A.x, "\n", "Public key (y) is: ", Q_A.y)
print("Private key is: ", s_A)
Q_A = s_A * P
s, h = sign_gen(stuID, s_A, P, n)
lkey = Q_A


###### REGISTER TO THE SERVER WITH THE CREATED KEYS ######
mes = {'ID':stuID, 'H': h, 'S': s, 'LKEY.X': lkey.x, 'LKEY.Y': lkey.y}
response = requests.put('{}/{}'.format(API_URL, "RegLongRqst"), json = mes)
print(response.json())
code = input()

mes = {'ID':stuID, 'CODE': code}
response = requests.put('{}/{}'.format(API_URL, "RegLong"), json = mes)
print(response.json())
