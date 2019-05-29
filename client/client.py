import socket,sys,os,pickle
from base64 import b64encode, b64decode
# Tmp abspath since nothing works TODO
sys.path.insert(0, r'/home/ludvig/Projects/OPAQUE_POC')

# Own imports
from lib.aesgcm import AESGCM
from lib.oprf import OPRF
from lib.rsa import *
from lib.util import *
from lib.dh import DHWRAPPER

HOST = '127.0.0.1'
PORT = 65432

def server_connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    
    return s

def server_send(socket, data):
    data = create_json(data)+'\r\n\r\n'
    socket.sendall(bytes(data))

def server_listen(socket):
    data = ""
    while True:
        data += socket.recv(1024)
        if data.find('\r\n\r\n') > -1:
            break

    response = from_json(data[:-4])
    if 'error' in response:
        raise Exception(response["error"])

    return response

def print_menu():
    print "1. Register new user"
    print "2. Login with registered user"
    print "3. Quit"

def register():
    s = server_connect()
    
    username = raw_input("Enter a username> ")
    password = raw_input("Select a password>")
    password_checker = raw_input("Reenter the password>")
    assert password == password_checker
    
    O = OPRF()
    # Init
    A,r = O.dhOprf1(password)
    data = {"A": A,
            "operation": "register"}
    server_send(s, data)
    # reg2
    data = server_listen(s)
    v = data["v"]
    b = data["b"]
    pubS = data["pubS"]
    rwdU = O.dhOprf3(password, v,b,r)
    
    # Generate rsa key and create envU
    gen_rsa_keys(os.getcwd())
    priv,pub = read_rsa_keys(os.getcwd())
    env = {"privU": priv.exportKey(), "pubU":pub.exportKey(), "pubS":pubS}
    encoded_env = pickle.dumps(env).encode('base64', 'strict')

    AES_NONCE = os.urandom(12)
    envU = AESGCM(rwdU[:16], AES_NONCE).encrypt(bytes(encoded_env))
    # Saves it in a better representation.  
    env_l = [envU[0], envU[1], AES_NONCE]
    
    # User data that the server should store
    data = {
        "username": username,
        "v": v,
        "env": pickle.dumps(env_l).encode('base64', 'strict'),
        "pub": pub.exportKey()}
    server_send(s, data)
    
    # Remove keys
    os.remove("private.pem")
    os.remove("public.pem")

def login():
    s = server_connect()
    
    username = raw_input("Enter a username> ")
    password = raw_input("Select a password>")
    
    # Imports for authentication
    DH = DHWRAPPER()
    O = OPRF()
    # Diffie-Hellman params
    dh_x = DH.gen_private_key()
    dh_y = DH.gen_public_key()
    
    A,r = O.dhOprf1(password)

    data = {"A": A,
            "cy": dh_y,
            "username": username,
            "operation": "login"}
    server_send(s, data)
     
    # Initialize last round
    data = server_listen(s)
    rwdU = O.dhOprf3(password, data["v"], data["b"], r)
    
    pre_encoded = pickle.loads(data["env"].decode('base64', 'strict'))
    ciphertext = pre_encoded[0]
    auth_tag = pre_encoded[1]
    nonce = pre_encoded[2]
    
    try:
        encoded = AESGCM(rwdU[:16],nonce).decrypt(ciphertext,auth_tag)
        env = pickle.loads(encoded.decode('base64', 'strict'))
    except:
        data = {"error": "Wrong password attempt. Username:"+username}
        server_send(s, data)
        print "Wrong password."
        return
     
    # Verify signature
    h = hash_list([dh_y, data["sy"]])
    pubkey = RSA.importKey(env["pubS"])
    if not verify(pubkey, b64decode(data["signature"]) ,h):
        raise Exception("Signatures does not match")

    # Verify mac
    mac,mac_key = DH.MAC(data["sy"], env["pubU"])
    if b64decode(data["mac"]) != mac:
        raise Exception("Mac's does not match")

    # If you've come to this stage you're authenticated on the client side
    # Now the proof is sent to the server aswell
    
    # Create signature
    priv = RSA.importKey(env["privU"])
    signature = sign(priv, h)
    # Create mac
    mac = hash_list([mac_key, env["pubU"]])

    data = {"signature": b64encode(signature),
            "mac": b64encode(mac.digest())}
    server_send(s, data)

    data = server_listen(s)
    if data["authenticated"] == "true":
        print "AUTHENTICATED"
    else:
        print "ERROR AUTHENTICATING"

def main():
    print_menu()
    choice = raw_input(">")
    
    if choice == "1":
        register()

    elif choice == "2":
        login()
    else:
        print "Bye"
        exit(0)

main()
