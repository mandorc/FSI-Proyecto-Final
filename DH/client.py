# File: client.py

import socket
import time
import os
from typing import Tuple 


from DH.protocol import (
    get_dh_parameters, generate_dh_key_pair, complete_key_exchange,
    run_chat_loop, send_message, receive_message, 
    STEP_PAUSE, SALT_LENGTH
)

HOST = '127.0.0.1' # localhost
PORT = 12345

def run_client_handshake(sock: socket.socket, client_public_bytes: bytes) -> Tuple[int, bytes]:
    print("[Client] HANDSHAKE-1: Sending client's public key (X)...", flush=True)
    send_message(sock, client_public_bytes)
    time.sleep(STEP_PAUSE)
    
    print("[Client] HANDSHAKE-2: Awaiting server's public key (Y)...", flush=True)
    b_public_bytes = receive_message(sock)
    if b_public_bytes is None:
        print("[Client] ERROR: Server closed connection unexpectedly.", flush=True)
        return None, None
    Y_public = int.from_bytes(b_public_bytes, 'big')
    print("[Client] HANDSHAKE-2: Server key 'Y' received.", flush=True)
    time.sleep(STEP_PAUSE)
    
    print("[Client] HANDSHAKE-3: Generating and sending 'salt' for KDF...", flush=True)
    salt = os.urandom(SALT_LENGTH)
    send_message(sock, salt)
    time.sleep(STEP_PAUSE)
    
    return Y_public, salt

def main():
    print("--- CLIENT TERMINAL ---", flush=True)

    # 1. Cargar parámetros p, g
    print(f"[Client] INFO: Loading DH parameters (p, g)...", flush=True)
    dh_params = get_dh_parameters()
    p = dh_params.parameter_numbers().p
    g = dh_params.parameter_numbers().g
    print(f"[Client] INFO: Using 'p' ending in ...{p % 10000}, 'g' = {g}", flush=True)
    time.sleep(STEP_PAUSE)

    # 2 key pair generation 
    a_private, a_public_bytes = generate_dh_key_pair(p, g)
    print(f"[Client] INFO: Public key 'X' generated.", flush=True)
    time.sleep(STEP_PAUSE)

    # 3. Socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"[Client] INFO: Attempting to connect to server at {HOST}:{PORT}...", flush=True)
            s.connect((HOST, PORT))
            print(f"[Client] INFO: Connection established with server.")
            print("\n--- START of Cryptographic Handshake ---", flush=True)
            
            # 4. Handshake
            Y_public, salt = run_client_handshake(s, a_public_bytes)
            if Y_public is None:
                return # Salir si el handshake falló

            # 5. Session key calculation
            aesgcm = complete_key_exchange(Y_public, a_private, p, salt)
            
            print("[Client] INFO: Secure channel established. Handshake complete.", flush=True)
            
            # 6. Chat loop
            run_chat_loop(s, aesgcm, role_name="Client", starts_by_sending=True)

    except ConnectionRefusedError:
        print(f"[Client] ERROR: Connection refused. Is 'server.py' running?", flush=True)
    except Exception as e:
        print(f"[Client] ERROR: An unexpected error occurred: {e}", flush=True)

if __name__ == "__main__":
    main()