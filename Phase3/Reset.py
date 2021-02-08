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
sL =  ###Private Key
stuID = 25224
stuID = str(stuID)

###### THE CURVE ######

E = Curve.get_curve('secp256k1')
n = E.order
P = E.generator # Point

###### SIGNATURE VERIFICATION ######
def sign_gen(message, sA, P, n):
	message = message.encode()
	k = Crypto.Random.random.randint(1, n-2)
	R = k * P
	r = (R.x) % n #R.x is the x coordinate of R
	hashed = SHA3_256.new(message + r.to_bytes((r.bit_length()+7)//8, byteorder='big')) 
	h = int.from_bytes(hashed.digest(), byteorder='big') % n
	s = ((sA * h) + k) % n 
	return s, h

s, h = sign_gen(stuID, sL, P, n) #Signing my student id to delete the ephemeral keys

###### DELETE THE EPHEMERAL KEYS STORED IN THE SERVER ######
for i in range(10):
	mes = {'ID': stuID, 'S': s, 'H': h}
	response = requests.get('{}/{}'.format(API_URL, "RstEKey"), json = mes)
print(response)
