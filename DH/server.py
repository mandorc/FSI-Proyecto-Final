# File: server.py

import socket
import time
from typing import Tuple 

from DH.protocol import (
    get_dh_parameters, generate_dh_key_pair, complete_key_exchange,
    run_chat_loop, send_message, receive_message, 
    STEP_PAUSE, SALT_LENGTH
)

HOST = '127.0.0.1' # localhost
PORT = 12345


def run_server_handshake(conn: socket.socket, server_public_bytes: bytes) -> Tuple[int, bytes]:

    print("[Server] HANDSHAKE-1: Awaiting client's public key (X)...", flush=True)
    a_public_bytes = receive_message(conn)
    if a_public_bytes is None:
        print("[Server] ERROR: Client disconnected during handshake.", flush=True)
        return None, None
    X_public = int.from_bytes(a_public_bytes, 'big')
    print("[Server] HANDSHAKE-1: Client key 'X' received.", flush=True)
    time.sleep(STEP_PAUSE)

    print("[Server] HANDSHAKE-2: Sending server's public key (Y)...", flush=True)
    send_message(conn, server_public_bytes)
    time.sleep(STEP_PAUSE)

    print("[Server] HANDSHAKE-3: Awaiting 'salt' for KDF...", flush=True)
    salt = receive_message(conn)
    if salt is None:
        print("[Server] ERROR: Client disconnected during handshake.", flush=True)
        return None, None
    assert len(salt) == SALT_LENGTH
    print("[Server] HANDSHAKE-3: 'Salt' received.", flush=True)
    time.sleep(STEP_PAUSE)
    
    return X_public, salt

def main():

    print("--- SERVER TERMINAL ---", flush=True)

    # 1  p, g parameters
    print(f"[Server] INFO: Loading DH parameters (p, g)...", flush=True)
    dh_params = get_dh_parameters()
    p = dh_params.parameter_numbers().p
    g = dh_params.parameter_numbers().g
    print(f"[Server] INFO: Using 'p' ending in ...{p % 10000}, 'g' = {g}", flush=True)
    time.sleep(STEP_PAUSE)

    # 2. Key pair generation  
    b_private, b_public_bytes = generate_dh_key_pair(p, g)
    print(f"[Server] INFO: Public key 'Y' generated.", flush=True)
    time.sleep(STEP_PAUSE)

    # 3. Socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)        
        s.bind((HOST, PORT))
        s.listen()
        print(f"[Server] INFO: Socket bound to {HOST}:{PORT}. Awaiting connection...", flush=True)
        
        conn, addr = s.accept()
        
        with conn:
            print(f"[Server] INFO: Incoming connection accepted from {addr}.", flush=True)
            print("\n--- START of Cryptographic Handshake ---", flush=True)
            
            # 4. Handshake
            X_public, salt = run_server_handshake(conn, b_public_bytes)
            if X_public is None:
                print("[Server] ERROR: Handshake failed.", flush=True)
                return

            # 5. Session key calculation
            aesgcm = complete_key_exchange(X_public, b_private, p, salt)
            
            print("[Server] INFO: Secure channel established. Handshake complete.", flush=True)
            
            # 6. Chat loop
            run_chat_loop(conn, aesgcm, role_name="Server", starts_by_sending=False)

if __name__ == "__main__":
    main()