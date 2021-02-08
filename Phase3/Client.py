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

API_URL = 'http://cryptlygos.pythonanywhere.com'

stuID =  25224  #stuID of Ömer Köse
stuID_B = 18007 #25467 #stuID of Emre Taşçı

###### THE CURVE ######
E = Curve.get_curve('secp256k1')
n = E.order
P = E.generator # Point

###### SERVER'S LONG TERM KEY ######
QSer_long = Point(0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9 , 0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c, E)
sL =  ###Private Key of stuID 25224
qL = Point(92427390329553636311771010066096663367323322008522176546441889242975549242019, 42576946619751461035232671964692541329920129727674351090477202351762014679472, E) #Public Key of stuID 25224

s, h = sign_gen(str(stuID), sL, P, n) #Signing my student id to recieve the messages from the server

####### STORE EPHEMERAL KEYS #######
keyArray = [] 

while True:
    print("Press r to reset ephemerals: ")
    print("Press n to create new ephemerals:")
    print("Press s to sent message: ")
    print("Press m to recieve messages: ")
    stroke = str(input())

    ###### RESET EPHEMERALS ######
    if (stroke == 'r'):
        ###### DELETE THE EPHEMERAL KEYS STORED IN THE SERVER ######
        for i in range(10):
            mes = {'ID': stuID, 'S': s, 'H': h}
            response = requests.get('{}/{}'.format(API_URL, "RstEKey"), json = mes)
        print(response)

    ###### CREATE NEW EPHEMERALS ######
    elif(stroke == 'n'):
        ####### SEND EPHEMERAL KEYS TO THE SERVER #######
        for i in range(10):
            keyArray.append(key_gen(P, n)) #Appending the keys in form of public, private to the array
            s, h = sign_gen(str(keyArray[i][0].x) + str(keyArray[i][0].y), sL, P, n) #Signing ephemeral keys in format of (QAi.x || QAi.y)
            mes = {'ID': stuID, 'KEYID': i , 'QAI.X': keyArray[i][0].x, 'QAI.Y': keyArray[i][0].y, 'Si': s, 'Hi': h}
            response = requests.put('{}/{}'.format(API_URL, "SendKey"), json = mes)
            print(response.json())

    ###### SENT MESSAGE ######
    elif (stroke == 's'):
        s_B, h_B = sign_gen(str(stuID_B), sL, P, n)

        ### Get key of the Student B
        mes = {'ID_A': stuID, 'ID_B':stuID_B, 'S': s_B, 'H': h_B}
        response = requests.get('{}/{}'.format(API_URL, "ReqKey"), json = mes)
        res = response.json()
        print(res)

        #Storing elements of the recieved message
        i = int(res["i"])
        j = int(res["j"])
        QB_j = Point(res["QBJ.x"], res["QBJ.y"], E) #Creating the point object to store the recieved points

        #Acessing to the private key of the ephemerals
        sBj = keyArray[int(i)][1]

        #Creating the session keys and msg
        T = sBj * QB_j #Multiplication of the private key created locally and sent by the server
        U = str(T.x) + str(T.y) + "NoNeedToRunAndHide"
        U = U.encode()
        KAB_enc = SHA3_256.new(U)
        KAB_enc = KAB_enc.digest()
        KAB_mac = SHA3_256.new(KAB_enc)
        KAB_mac = KAB_mac.digest()

        print("Enter message to be sent: ")	
        plaintext = str(input())

        ###### ENCRYPTION ######

        Y = AES.new(KAB_enc, AES.MODE_CTR) #Create AES object to use
        plaintext = Y.encrypt(plaintext.encode()) #Use created object to encrypt ciphertext

        macCalculator = HMAC.new(KAB_mac, digestmod=SHA256)
        macCalculator.update(plaintext)

        macCode = macCalculator.digest()

        ciphertext = Y.nonce + plaintext + macCode #Concatenate the object with ciphertext
        ciphertext = int.from_bytes(ciphertext, byteorder = 'big') #Convert it back to integer
        print("Encrypted")

        ### Send message to student B
        mes = {'ID_A': stuID, 'ID_B':stuID_B, 'I': i, 'J':j, 'MSG': ciphertext}
        response = requests.put('{}/{}'.format(API_URL, "SendMsg"), json = mes)
        print(response.json())

    ###### GET MESSAGE ######
    elif (stroke == 'm'):
        s, h = sign_gen(str(stuID), sL, P, n)
        ## Get your message
        mes = {'ID_A': stuID, 'S': s, 'H': h}
        response = requests.get('{}/{}'.format(API_URL, "ReqMsg_PH3"), json = mes)
        print(response.json())
        if(response.ok): ## Decrypt message
            response = response.json()

            #Storing elements of the recieved message
            id = response["IDB"]
            keyID = response["KEYID"]
            msg = response["MSG"]
            QB_j = Point(response["QBJ.X"], response["QBJ.Y"], E) #Creating the point object to store the recieved points

            #Acessing to the private key of the ephemerals
            sBj = keyArray[int(keyID)][1]

            #Creating the session keys and msg
            T = sBj * QB_j #Multiplication of the private key created locally and sent by the server
            U = str(T.x) + str(T.y) + "NoNeedToRunAndHide"
            U = U.encode()
            KAB_enc = SHA3_256.new(U)
            KAB_enc = KAB_enc.digest()
            KAB_mac = SHA3_256.new(KAB_enc)
            KAB_mac = KAB_mac.digest()

            
            ####### DECRYPT MESSAGE #######
            msg_bytes = msg.to_bytes((msg.bit_length() + 7)//8, byteorder = 'big')
            mac = msg_bytes[-32:]
            real_msg = msg_bytes[8:-32]
            c = AES.new(KAB_enc, AES.MODE_CTR, nonce = msg_bytes[0:8])
            decrypted = c.decrypt(real_msg) #Decrypt ctext after nonced part
            decrypted = decrypted.decode("UTF-8") #Decoding
            print(decrypted)
            
            #Creating hash object
            hashed = HMAC.new(KAB_mac, digestmod=SHA256)
            hashed = hashed.update(real_msg)
            
            #Verification of the hash if the message is authentic with the used mac value or not
            try:
                hashed.verify(mac)
                print("The message is authentic.")
            except ValueError:
                print("The message is not authentic.")



# #####Reset Long Term Key
# mes = {'ID': stuID}
# response = requests.get('{}/{}'.format(API_URL, "RstLongRqst"), json = mes)
# print(response.json())
# code = int(input())

# mes = {'ID': stuID ,'CODE': code}
# response = requests.get('{}/{}'.format(API_URL, "RstLong"), json = mes)
# print(response.json())

