import sys
import time
import os
import socket
import json


UDP_IP = "127.0.0.1"
UDP_PORT = 9870
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sys.path.append(os.path.join(os.getcwd(), 'DH'))
sys.path.append(os.path.join(os.getcwd(), 'PQC'))

from DH import protocol as dh_proto
from PQC import protocol_pqc as pqc_proto

def run_live_benchmark():
    print(f"--- 📡 STARTING STREAMING TO PLOTJUGGLER ({UDP_IP}:{UDP_PORT}) ---")
    print("Instructions: Open PlotJuggler -> Streaming -> Start UDP Server (Port 9870)")
    print("Press Ctrl+C to stop.")
    
    dh_params = dh_proto.get_dh_parameters()
    p = dh_params.parameter_numbers().p
    g = dh_params.parameter_numbers().g

    iteration = 0
    
    try:
        while True:
            iteration += 1
            
            #  METRIC 1: Diffie-Hellman 
            t0 = time.perf_counter()
            # 1. Simulate Key Generation
            a_priv, a_pub = dh_proto.generate_dh_key_pair(p, g)
            b_priv, b_pub = dh_proto.generate_dh_key_pair(p, g)
            # 2. Simulate Shared Secret Calculation (The heavy math part)
            s1 = pow(int.from_bytes(b_pub, 'big'), a_priv, p)
            
            dh_time = (time.perf_counter() - t0) * 1000 # Convert to milliseconds
            dh_size = len(a_pub) + len(b_pub) # Total bytes exchanged

            # --- METRIC 2: Kyber-512 (Post-Quantum) ---
            t0 = time.perf_counter()
            # 1. Server generates keys (KeyGen)
            pk, sk, server_kem = pqc_proto.generate_kyber_keypair()
            # 2. Client Encapsulates (Encap)
            ct, ss_c = pqc_proto.kyber_encapsulate(pk)
            # 3. Server Decapsulates (Decap)
            ss_s = pqc_proto.kyber_decapsulate(server_kem, ct)
            
            # Manual cleanup is required for liboqs objects
            server_kem.free() 
            
            kyber_time = (time.perf_counter() - t0) * 1000 # Convert to milliseconds
            kyber_size = len(pk) + len(ct) # Total bytes exchanged

            # --- PACK & SEND (JSON) ---
            # We send all metrics in a single JSON packet
            payload = {
                "iteration": iteration,
                "time_dh_ms": dh_time,         # Classic Time
                "time_kyber_ms": kyber_time,   # Quantum Time
                "size_dh_bytes": dh_size,      # Classic Network Load
                "size_kyber_bytes": kyber_size # Quantum Network Load
            }
            
            json_msg = json.dumps(payload)
            sock.sendto(json_msg.encode(), (UDP_IP, UDP_PORT))
            
            print(f"Iter {iteration}: DH={dh_time:.2f}ms | Kyber={kyber_time:.2f}ms (Sent via UDP)")

            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\n--- Benchmark Stopped ---")

if __name__ == "__main__":
    run_live_benchmark()