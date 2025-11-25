# File: protocol_pqc.py
import os
import oqs
from typing import Tuple 

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# --- CONFIGURACIÓN QUANTUM ---
KEM_ALG = "Kyber512"

# Constantes (Igual que antes)
ENCRYPTION_KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12 
HEADER_LENGTH = 4
STEP_PAUSE = 1.0 
KDF_ITERATIONS = 480000

# --- FUNCIONES CORE QUANTUM (KEM) ---

def generate_kyber_keypair() -> Tuple[bytes, bytes, object]:
    """
    Retorna: (public_key, secret_key, kem_object)
    ¡IMPORTANTE!: Devolvemos el objeto 'kem' para mantenerlo vivo y reutilizarlo.
    """
    print(f"[PQC-Core] Inicializando {KEM_ALG}...", flush=True)
    kem = oqs.KeyEncapsulation(KEM_ALG)
    
    print(f"[PQC-Core] Generando llaves Kyber (Lattices)...", flush=True)
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    
    return public_key, secret_key, kem

def kyber_encapsulate(peer_public_key: bytes) -> Tuple[bytes, bytes]:
    """El CLIENTE encapsula (cierra la caja)."""
    print(f"[PQC-Core] Encapsulando secreto...", flush=True)
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        ciphertext, shared_secret = kem.encap_secret(peer_public_key)
    return ciphertext, shared_secret

def kyber_decapsulate(kem_context: object, ciphertext: bytes) -> bytes:
    """
    CORRECCIÓN: Usamos el 'kem_context' existente (que ya tiene la SK).
    No creamos uno nuevo con 'with', para evitar el error de memoria.
    """
    print(f"[PQC-Core] Decapsulando el ciphertext recibido...", flush=True)
    shared_secret = kem_context.decap_secret(ciphertext)
    return shared_secret

# --- FUNCIONES AUXILIARES (RED Y KDF) ---
# (Esto sigue idéntico a tu versión anterior)

def derive_aes_key(shared_secret: bytes, salt: bytes) -> AESGCM:
    print("[Crypto] KDF: Derivando llave AES desde el secreto Quantum...", flush=True)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=ENCRYPTION_KEY_LENGTH,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(shared_secret)
    return AESGCM(key)

def send_message(sock, message: bytes):
    try:
        msg_len = len(message).to_bytes(HEADER_LENGTH, 'big')
        sock.sendall(msg_len + message)
    except BrokenPipeError:
        pass

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
        return None

def run_chat_loop(sock, aesgcm, role_name, starts_by_sending):
    print(f"\n--- Chat QUANTUM-SECURE (AES-GCM) ---")
    try:
        while True:
            if starts_by_sending:
                my_msg = input(f"[{role_name}] > ")
                nonce = os.urandom(NONCE_LENGTH)
                ciphertext = aesgcm.encrypt(nonce, my_msg.encode(), None)
                send_message(sock, nonce + ciphertext)
                if my_msg == 'exit': break
            
            data = receive_message(sock)
            if not data: 
                print("Conexión cerrada.")
                break
            
            nonce, ciphertext = data[:NONCE_LENGTH], data[NONCE_LENGTH:]
            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode()
                peer = "Client" if role_name == "Server" else "Server"
                print(f"[{peer}] {plaintext}")
                if plaintext == 'exit': break
            except InvalidTag:
                print("ERROR: Ataque detectado o error de llave.")
            
            if not starts_by_sending: starts_by_sending = True
    except Exception as e:
        print(f"Error en chat: {e}")