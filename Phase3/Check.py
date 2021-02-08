###### ÖMER KÖSE 25224 ######

import math
import timeit
import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
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

###### THE CURVE ######
E = Curve.get_curve('secp256k1')
n = E.order
P = E.generator # Point

sL =  ###Private Key of stuID 25224
qL = Point(92427390329553636311771010066096663367323322008522176546441889242975549242019, 42576946619751461035232671964692541329920129727674351090477202351762014679472, E) #Public Key of stuID 25224

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

s, h = sign_gen(str(stuID), sL, P, n) #Signing my student id to recieve the messages from the server

###### CHECK STATUS ######
mes = {'ID_A': stuID, 'H': h, 'S': s}
response = requests.get('{}/{}'.format(API_URL, "Status"), json = mes)
print("Status ", response.json())