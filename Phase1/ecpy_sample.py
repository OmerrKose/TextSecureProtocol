# Run "pip install ecpy" if ecpy is not installed
from random import randint, seed
from ecpy.curves import Curve
from Crypto.Hash import SHA3_256
from Crypto import Random   # a bit better secure random number generation 
import math

E = Curve.get_curve('secp256k1')
n = E.order
p = E.field
P = E.generator
a = E.a
b = E.b
print("Base point:\n", P)
print("p :", p)
print("a :", a)
print("b :", b)
print("n :", n)

k = Random.new().read(int(math.log(n,2)))
k = int.from_bytes(k, byteorder='big')%n

Q = k*P
print("\nQ:\n", Q)
print("Q on curve?", E.is_on_curve(Q))

#seed(13)

# ECDH Key exchange protocol simulation
# Alice side -1
a = Random.new().read(int(math.log(n,2)))
a = int.from_bytes(a, byteorder='big')%n
Pa = a*P

# Bob side -1 
b = Random.new().read(int(math.log(n,2)))
b = int.from_bytes(b, byteorder='big')%n

Pb = b*P

# Alice side -2
Ka = a*Pb
print("Ka: ", Ka)

# Bob side -2
Kb = b*Pa
print("Kb: ", Kb)

#Alice size -3
print("Ka.x: ", )
T = Ka.x+Ka.y

K = SHA3_256.new(T.to_bytes((T.bit_length()+7)//8, byteorder='big')+b'Hey, this is fun')
print(K.hexdigest())

#Bob size -3
print("Kb.x: ", )
T = Kb.x+Kb.y

K = SHA3_256.new(T.to_bytes((T.bit_length()+7)//8, byteorder='big')+b'Hey, this is fun')
print(K.hexdigest())

# check it
print("\nwondering...", (n+1)*P)



    
