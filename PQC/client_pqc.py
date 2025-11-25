
import socket
import os
import time
from protocol_pqc import (
    kyber_encapsulate, derive_aes_key,
    run_chat_loop, send_message, receive_message, STEP_PAUSE, SALT_LENGTH
)

HOST = '127.0.0.1'
PORT = 12345

def main():
    print("--- CLIENT TERMINAL (QUANTUM SAFE) ---", flush=True)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"[Client] Connecting to {HOST}:{PORT}...", flush=True)
            s.connect((HOST, PORT))
            
            print("\n--- START Kyber Handshake (KEM) ---", flush=True)
            
            # 1. Receive Server's Public Key
            print("[Client] Waiting for Kyber public key...", flush=True)
            server_pk = receive_message(s)
            print(f"[Client] PK received ({len(server_pk)} bytes).", flush=True)
            time.sleep(STEP_PAUSE)
            

            ciphertext, shared_secret = kyber_encapsulate(server_pk)
            print(f"[Client] Secret encapsulated into ciphertext ({len(ciphertext)} bytes).", flush=True)
            

            send_message(s, ciphertext)
            
 
            salt = os.urandom(SALT_LENGTH)
            send_message(s, salt)

            aesgcm = derive_aes_key(shared_secret, salt)
            print("[Client] Post-Quantum secure channel established.", flush=True)

            run_chat_loop(s, aesgcm, "Client", True)

    except ConnectionRefusedError:
        print("[Client] Error: Server not found.")
    except Exception as e:
        print(f"[Client] Error: {e}")

if __name__ == "__main__":
    main()