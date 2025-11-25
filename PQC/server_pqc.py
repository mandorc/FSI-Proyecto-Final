# File: server_pqc.py
import socket
import time
from protocol_pqc import (
    generate_kyber_keypair, kyber_decapsulate, derive_aes_key,
    run_chat_loop, send_message, receive_message, STEP_PAUSE
)

HOST = '127.0.0.1'
PORT = 12345

def main():
    print("--- SERVER TERMINAL (QUANTUM SAFE) ---", flush=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)        
        s.bind((HOST, PORT))
        s.listen()
        print(f"[Server] Esperando conexión en {HOST}:{PORT}...", flush=True)
        
        conn, addr = s.accept()
        with conn:
            print(f"[Server] Conexión de {addr}. Iniciando Handshake Kyber...", flush=True)

            # 1. Generar Llaves (¡Guardamos server_kem!)
            # server_kem es el motor que contiene la llave privada en memoria
            pk_bytes, sk_bytes, server_kem = generate_kyber_keypair()
            time.sleep(STEP_PAUSE)

            # 2. Enviar PK
            print(f"[Server] Enviando Llave Pública Kyber ({len(pk_bytes)} bytes)...", flush=True)
            send_message(conn, pk_bytes)

            # 3. Recibir Ciphertext
            print("[Server] Esperando Ciphertext...", flush=True)
            ciphertext = receive_message(conn)
            
            # 4. Recibir Salt
            print("[Server] Esperando Salt...", flush=True)
            salt = receive_message(conn)
            
            # 5. Decapsular usando el MISMO objeto (server_kem)
            # Esto evita el crash de memoria
            shared_secret = kyber_decapsulate(server_kem, ciphertext)
            print(f"[Server] ¡Secreto Kyber recuperado! ({len(shared_secret)} bytes)", flush=True)
            
            # Limpiamos el motor Kyber manualment ahora que tenemos el secreto
            server_kem.free() 

            # 6. Derivar llave AES
            aesgcm = derive_aes_key(shared_secret, salt)
            
            # Chat
            run_chat_loop(conn, aesgcm, "Server", False)

if __name__ == "__main__":
    main()