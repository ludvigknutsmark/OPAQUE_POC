from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from Crypto.Util.number import bytes_to_long, long_to_bytes
from gmpy2 import invert
import random

from dh import DHWRAPPER
class OPRF():
    def __init__(self):
        self.DH = DHWRAPPER()
        self.g = self.DH.g
        self.p = self.DH.p
        
    def hashToGroup(self, x):
        while 1:
            derived = bytes_to_long(HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=None,backend=default_backend()).derive(x))
            random.seed(derived)
            x = random.randint(1, self.p-1)
            if x > 0 or x < 0:
                return x
    
    def dhOprf1(self, x):
        while 1:
            r = self.DH.gen_private_key()
            H_prime = self.hashToGroup(x)
            A = (pow(self.g, r, self.p)*H_prime)%self.p

            if A != 1 or A != self.p-1:
                return A, r

    def dhOprf2(self, A, k):
        if A < 0 and A > self.p:
            raise Exception("A not in group")

        v = pow(self.g, k, self.p)
        b = pow(A, k, self.p)

        return v,b

    def dhOprf3(self,x,v,b,r):
        
        if v < 1 or v > self.p-1:
            raise Exception("V not in group or small subgroup")
        
        if b < 1 or b > self.p-1: 
            raise Exception("V not in group or small subgroup")

        z = pow(v,r,self.p)
        z_i = invert(z,self.p)

        y = (b*z_i)%self.p

        H = hashes.Hash(hashes.SHA256(), backend=default_backend())
        H.update(x)
        H.update(long_to_bytes(v))
        H.update(long_to_bytes(y))
        
        return H.finalize()

