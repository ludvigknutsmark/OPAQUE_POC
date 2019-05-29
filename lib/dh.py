# Simple lousy POC for the OPAQUE-protocol
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh

from util import hkdf_wrapper, hash_list

class DHWRAPPER():
    def __init__(self, g=None, p=None): 
        if g is None:
            self.g = 2
        else:
            self.g = g
        if p is None:
            self.p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
        else:
            self.p = p

        pn = dh.DHParameterNumbers(self.p,self.g)
        self.params = pn.parameters(default_backend())
        self.private = None
    
    def gen_private_key(self):
        self.private = self.params.generate_private_key()
        return self.private.private_numbers().x

    def gen_public_key(self):
        if self.private is None:
            raise Exception("Private key must be generated")

        pubkey = self.private.public_key()
        
        return pubkey.public_numbers().y

    def shared_secret(self, private, public):
        return pow(public,private,self.p)

    # Creates a MAC from shared_secret and Additional Data
    def MAC(self, y, AD):
        dh_secret = self.shared_secret(self.private.private_numbers().x, y)
        mac_key = hkdf_wrapper(dh_secret)
        return hash_list([mac_key, AD]).digest(), mac_key
            
