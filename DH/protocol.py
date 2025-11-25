

import os
import time
import socket 
from typing import Tuple 

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# protocol constants
PARAMS_FILE = "dh_params.pem"
GENERATOR = 2
KEY_SIZE = 2048 
PRIVATE_KEY_BYTES = 256                                                                                             

# kdf 
KDF_ITERATIONS = 480000
KDF_HASH_ALGO = hashes.SHA256()

# aes-gcm
ENCRYPTION_KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12 
STEP_PAUSE = 1.0 

def get_dh_parameters() -> dh.DHParameters:

    if os.path.exists(PARAMS_FILE):
        print("[Shared] INFO: Loading cached DH parameters (p, g)...", flush=True)
        with open(PARAMS_FILE, "rb") as f:
            parameters = serialization.load_pem_parameters(f.read(), backend=default_backend())
    else:
        print(f"[Shared] INFO: Generating new {KEY_SIZE}-bit DH parameters (p, g)", flush=True)
        parameters = dh.generate_parameters(
            generator=GENERATOR,
            key_size=KEY_SIZE,
            backend=default_backend()
        )
        print(f"[Shared] INFO: Saving parameters to cache ({PARAMS_FILE})...", flush=True)
        with open(PARAMS_FILE, "wb") as f:
            f.write(parameters.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            ))
    return parameters

# Key pair generation g ^private mod p
def generate_dh_key_pair(p: int, g: int) -> Tuple[int, bytes]:
  

    print(f"[Crypto] Generating private key ({PRIVATE_KEY_BYTES} random bytes)...", flush=True)
    a = int.from_bytes(os.urandom(PRIVATE_KEY_BYTES), 'big')

    print(f"[Crypto] Calculating public key (g^private mod p)...", flush=True)
    public_key = pow(g, a, p)

    public_bytes = public_key.to_bytes((public_key.bit_length() + 7) // 8, 'big')
    return a, public_bytes


# Z calculation and KDF
def complete_key_exchange(other_public_key: int, my_private_key: int, p: int, salt: bytes) -> AESGCM:
  

    print(f"[Crypto] KDF-PREP: Calculating shared secret 'Z' (Y^a mod p o X^b mod p)...", flush=True)
    Z_secret_num = pow(other_public_key, my_private_key, p)
    
    Z_secret_bytes = Z_secret_num.to_bytes(KEY_SIZE // 8, 'big')
    print("[Crypto] KDF-PREP: Shared secret 'Z' calculated.", flush=True)
    
    print("[Crypto] KDF: Deriving symmetric key 'k' from 'Z' and 'salt'...", flush=True)
    encryption_key_k = derive_key(Z_secret_bytes, salt)
    
    print("[Crypto] INFO: Secure session key derived.", flush=True)
    return AESGCM(encryption_key_k)
# =========================================================================

def derive_key(shared_secret: bytes, salt: bytes) -> bytes:

    kdf = PBKDF2HMAC(
        algorithm=KDF_HASH_ALGO,
        length=ENCRYPTION_KEY_LENGTH,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(shared_secret) 
    return key

# chat message send/receive

HEADER_LENGTH = 4

def send_message(sock, message: bytes):
    """Serializa y envía un payload (longitud + mensaje)."""
    try:
        msg_len = len(message).to_bytes(HEADER_LENGTH, 'big')
        sock.sendall(msg_len + message)
    except BrokenPipeError:
        print("[Network] ERROR: Broken pipe.", flush=True)
        raise

def receive_message(sock) -> bytes:
    try:
        msg_len_bytes = sock.recv(HEADER_LENGTH)
        if not msg_len_bytes: return None 
        msg_len = int.from_bytes(msg_len_bytes, 'big')
        
        data = bytearray()
        while len(data) < msg_len:
            packet = sock.recv(min(msg_len - len(data), 4096))
            if not packet: return None 
            data.extend(packet)
        return bytes(data) 

    except ConnectionResetError:
        print("[Network] ERROR: Connection reset by peer.", flush=True)
        return None

def run_chat_loop(sock: socket.socket, aesgcm: AESGCM, role_name: str, starts_by_sending: bool):

    print(f"\n--- Chat with AES-GCM---")
    print(f" (Type 'exit' to end session)\n")
    
    try:
        while True:
            if starts_by_sending:
                # 1. Cifrar y Enviar (TX)
                my_msg = input(f"[{role_name}]")
                my_msg_bytes = my_msg.encode()
                
                send_nonce = os.urandom(NONCE_LENGTH)
                send_ciphertext = aesgcm.encrypt(send_nonce, my_msg_bytes, None)
                send_payload = send_nonce + send_ciphertext
                
                send_message(sock, send_payload)
                if my_msg == 'exit':
                    print(f"[{role_name}] INFO: Session exit initiated.", flush=True)
                    break
            
            # 2. Esperar y Descifrar (RX)
            print(f"[{role_name}] RX: Awaiting encrypted payload...", flush=True)
            encrypted_payload = receive_message(sock)
            if encrypted_payload is None:
                print(f"[{role_name}] INFO: Peer closed the connection.", flush=True)
                break
            
            nonce = encrypted_payload[:NONCE_LENGTH]
            ciphertext = encrypted_payload[NONCE_LENGTH:]
            try:
                decrypted_message = aesgcm.decrypt(nonce, ciphertext, None)
            except InvalidTag:
                print(f"[{role_name}] SECURITY ALERT: Authentication failed (InvalidTag)!!!", flush=True)
                continue

            msg = decrypted_message.decode()
            peer_role = "Client" if role_name == "Server" else "Server"
            print(f"[{peer_role} (decrypted)]: {msg}", flush=True)
            if msg == 'exit':
                print(f"[{role_name}] INFO: Peer requested exit. Closing.", flush=True)
                break
            
            if not starts_by_sending:
                starts_by_sending = True 
    
    except (BrokenPipeError, ConnectionResetError):
        print(f"[{role_name}] ERROR: Connection lost unexpectedly.", flush=True)
    finally:
        print(f"--- {role_name.upper()} SESSION TERMINATED ---", flush=True)
