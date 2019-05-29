# Simple lousy POC for the OPAQUE-protocol
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Util.number import bytes_to_long, long_to_bytes

import pickle

import os,sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

print sys.path[-1]

from lib.aesgcm import AESGCM
from lib.dh import DHWRAPPER
from lib.oprf import OPRF
from lib.rsa import *

# Password registration
# This should be negotiated or default values :-)
DH = DHWRAPPER()
O = OPRF()

# Server Instantiation
rand = Random.new().read
privS = RSA.generate(1024, rand)
pubS = privS.publickey()

# Client
username = "ludvig"
password = b'password'
A,rp = O.dhOprf1(password)

# Server
kU = DH.gen_private_key()
vU,bU = O.dhOprf2(A,kU)

# Client
rwdU = O.dhOprf3(password,vU,bU,rp)
rwdU_first = rwdU

rand = Random.new().read
privU = RSA.generate(1024, rand)
pubU = privU.publickey()

# Env should be a struct or dict
env = {"privU": privU.exportKey(), "pubU":pubU.exportKey(), "pubS": pubS.exportKey()}
encoded_env = pickle.dumps(env).encode('base64', 'strict')

AES_NONCE = b'\x04'*12
envU = AESGCM(rwdU[:16], AES_NONCE).encrypt(bytes(encoded_env))

# Server saves this
client_username = username
client_k = kU
client_v = vU
client_envU = envU
client_pubU = pubU

# Client saves this
# privU, pubU

################################################
############ OPAQUE AUTHENTICATION #############
################################################

# Client
O = OPRF()

cx = DH.gen_private_key()
cy = DH.gen_public_key()

password = b'password'
A,r = O.dhOprf1(password)

# send A,r,cy

# Server
sx = DH.gen_private_key()
sy = DH.gen_public_key()

v,b = O.dhOprf2(A, client_k)

H = hashes.Hash(hashes.SHA256(), backend=default_backend())
H.update(long_to_bytes(cy))
H.update(long_to_bytes(sy))

sig = privS.decrypt(H.finalize())
shared_secret = DH.shared_secret(sx, cy)
mac_key = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=None,backend=default_backend()).derive(long_to_bytes(shared_secret))

H = hashes.Hash(hashes.SHA256(),backend=default_backend())
H.update(mac_key)
H.update(bytes(pubS.exportKey()))
mac = H.finalize()

# send v,b, envU, sy, sig, mac

# Client
rwdU = O.dhOprf3(password,v,b,r)

encoded = AESGCM(rwdU[:16], AES_NONCE).decrypt(client_envU[0], client_envU[1])
envU = pickle.loads(encoded.decode('base64', 'strict'))

H = hashes.Hash(hashes.SHA256(), backend=default_backend())
H.update(long_to_bytes(cy))
H.update(long_to_bytes(sy))
h_dh = H.finalize()

pub = RSA.importKey(envU['pubS'])
assert pub.encrypt(sig, 32)[0] == h_dh

shared_secret = DH.shared_secret(cx, sy)
mac_key = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=None,backend=default_backend()).derive(long_to_bytes(shared_secret))

H = hashes.Hash(hashes.SHA256(),backend=default_backend())
H.update(mac_key)
H.update(bytes(pubS.exportKey()))
assert mac == H.finalize()

priv_key = RSA.importKey(envU['privU'])
sig = priv_key.decrypt(h_dh)

H = hashes.Hash(hashes.SHA256(),backend=default_backend())
H.update(mac_key)
H.update(bytes(pubU.exportKey()))
mac_c = H.finalize()

# send sig, mac

# Server
H = hashes.Hash(hashes.SHA256(), backend=default_backend())
H.update(long_to_bytes(cy))
H.update(long_to_bytes(sy))
h_dh = H.finalize()

assert client_pubU.encrypt(sig,32)[0] == h_dh

H = hashes.Hash(hashes.SHA256(),backend=default_backend())
H.update(mac_key)
H.update(bytes(pubU.exportKey()))
if mac_c == H.finalize():
    print "AUTHENTICATED"
else:
    raise Exception("Wrong password")
