# Run "pip install ecpy" if ecpy is not installed
from ecpy.curves import Curve,Point
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA
import Crypto.Random.random 
import math

# the curve
E = Curve.get_curve('secp256k1')
n = E.order
P = E.generator

# Signer
s = Crypto.Random.random.randint(2, n-1)
Q = s*P
private_key = ECPrivateKey(s, E)
public_key = ECPublicKey(Q)
signer = ECDSA()
sig    = signer.sign(b'Hello World',private_key)

#verifier needs the public key
public_key = ECPublicKey(Point(Q.x, Q.y, E))            # one way of setting elliptic curve point as the public key
verifier = ECDSA()
print(verifier.verify(b'Hello  World',sig,public_key))  # Wrong message
print(verifier.verify(b'Hello World',sig,public_key))   # Correct message 
    
