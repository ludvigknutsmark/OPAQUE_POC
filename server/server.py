import socket, os, sys
# Tmp abspath since nothing works #TODO
sys.path.insert(0, r'/home/ludvig/Projects/OPAQUE_POC')

# RSA imports
from Crypto.PublicKey import RSA
from Crypto import Random

# Utils
from Crypto.Random.random import randint
from base64 import b64encode, b64decode

# Lib imports
from lib.rsa import *
from lib.util import *
from lib.oprf import OPRF
from lib.dh import DHWRAPPER

HOST = '127.0.0.1'
PORT = 65432

def recv_until(conn):
    data = ""
    while True:
        data += conn.recv(1024)
        if data.find('\r\n\r\n') > -1:
            break
        
    response = from_json(data[:-4])

    if 'error' in response:
        raise Exception(response["error"])
    return response

def server_loop(s):
    while 1:
        conn, addr = s.accept()

        data = recv_until(conn)
        if data["operation"] == "register":
            handle_register(conn, data)
        
        elif data["operation"] == "login":
            handle_authentication(conn, data)
        
        else:
            pass

def get_authdata_from_username(username):
    f = open("auth_data", "rb")
    data = f.readlines()
    f.close()

    for line in data:
        try:
            userdata = from_json(line)
            if userdata["username"] == username:
                return from_json(userdata["auth_data"])
        except:
            pass
    
    return None

def handle_register(conn, data):
    O = OPRF()
    A = data["A"]
    kU = randint(1, O.p-1)
    v,b = O.dhOprf2(A, kU)

    priv, pub = read_rsa_keys(os.getcwd())
    
    data = {"v": v,
            "b":b,
            "pubS": pub.exportKey()}
    conn.send(create_json(data)+'\r\n\r\n')
    
    data = recv_until(conn)
    # Add server data
    data["k"] = kU
    
    user_record = {"username": data["username"], "auth_data": create_json(data)}
    f = open("auth_data", "ab")
    f.write(create_json(user_record)+'\n')
    f.close()

def handle_authentication(conn, data):
    # Get data
    auth_data = get_authdata_from_username(data["username"])
    if auth_data is None:
        raise Exception("Not a user")

    DH = DHWRAPPER()
    O = OPRF()
    A = data["A"]
    cy = data["cy"]
    
    # Generate keys
    dh_x = DH.gen_private_key()
    dh_y = DH.gen_public_key()
    
    # Authentication start
    v,b = O.dhOprf2(A, auth_data["k"])

    # Prepare signature
    h = hash_list([cy,dh_y])
    priv, pub = read_rsa_keys(os.getcwd())
    signature = sign(priv, h)
    
    # Calculate mac
    mac, mac_key = DH.MAC(cy, auth_data["pub"])
    
    # Send data
    data = {"v": v, 
            "b":b, 
            "env": auth_data["env"], 
            "sy": dh_y, 
            "signature": b64encode(signature), 
            "mac": b64encode(mac)}
    conn.send(create_json(data)+'\r\n\r\n')
    
    # Verify signature
    data = recv_until(conn)
    h = hash_list([cy,dh_y])
    pub = RSA.importKey(auth_data["pub"])
    if not verify(pub, b64decode(data["signature"]), h):
        raise Exception("Signatures does not match")
    
    # Verify mac
    h = hash_list([mac_key, auth_data["pub"]])
    if b64decode(data["mac"]) != h.digest():
        raise Exception("Macs does not match")

    # Success! Send authentication = true
    data = {
            "authenticated": "true"}
    conn.send(create_json(data)+'\r\n\r\n')
    conn.close()

def main():
    if not os.path.isfile('private.pem'):
        gen_rsa_keys(os.getcwd())    
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    server_loop(s)
    
main()
