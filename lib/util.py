import json,yaml

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Hash import SHA

# Creates a json from a dict
def create_json(src):
    return json.dumps(src)

def from_json(src):
    data = yaml.safe_load(src)
    return data

def hash_list(arr):
    H = SHA.new()
    for element in arr:
        if isinstance(element, long) or isinstance(element, int):
            element = long_to_bytes(element)
        H.update(element)
        
    return H

def hkdf_wrapper(data):
    if isinstance(data, long) or isinstance(data, int):
        data = long_to_bytes(data)

    return HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=None,backend=default_backend()).derive(data)

