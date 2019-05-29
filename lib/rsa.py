from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto import Random

def gen_rsa_keys(path, size=None):
    if size is None:
        size = 1024
    rand = Random.new().read
    privS = RSA.generate(size, rand)
    pubS = privS.publickey()

    f = open(path+'/private.pem', 'wb')
    f.write(privS.exportKey())
    f.close()

    f = open(path+'/public.pem', 'wb')
    f.write(pubS.exportKey())
    f.close()

def read_rsa_keys(path):
    f = open(path+'/private.pem')
    priv = RSA.importKey(f.read())
    f.close()

    return priv, priv.publickey()

def sign(keyobj, digest):
    signer = PKCS1_PSS.new(keyobj)
    return signer.sign(digest)

def verify(keyobj, signature, digest):
    verifier = PKCS1_PSS.new(keyobj)
    return verifier.verify(digest, signature)
    
