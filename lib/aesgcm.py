from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

class AESGCM():
    def __init__(self, key, nonce):
        self.key = key
        self.nonce = nonce
        self.cipher = Cipher(
                algorithms.AES(self.key),
                None,
                backend=default_backend()
        )
        self.cipher.mode = modes.GCM(self.nonce)

    def encrypt(self, plaintext): 
        stream = self.cipher.encryptor()
        ciphertext = stream.update(plaintext)+stream.finalize()
        return ciphertext, stream.tag

    def decrypt(self,ciphertext, authTag):
        self.cipher.mode = modes.GCM(self.nonce, authTag)
        stream = self.cipher.decryptor()
        plaintext = stream.update(ciphertext)+stream.finalize()
        return plaintext
