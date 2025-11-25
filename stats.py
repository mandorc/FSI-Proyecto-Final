
import sys
import time
import os
import matplotlib.pyplot as plt
import numpy as np


sys.path.append(os.path.join(os.getcwd(), 'DH'))
sys.path.append(os.path.join(os.getcwd(), 'PQC'))

from DH import protocol as dh_proto
from PQC import protocol_pqc as pqc_proto

def test_dh_performance(iterations=100):
    print(f"--- ⚔️  Ronda 1: Diffie-Hellman Clásico ({iterations} iters) ---")
    

    params = dh_proto.get_dh_parameters()
    p = params.parameter_numbers().p
    g = params.parameter_numbers().g
    
    start_time = time.time()
    total_bytes = 0
    
    for _ in range(iterations):

        a_priv, a_pub = dh_proto.generate_dh_key_pair(p, g)

        b_priv, b_pub = dh_proto.generate_dh_key_pair(p, g)
        
  
        total_bytes += len(a_pub) + len(b_pub)
        
        # 3. Calculamos secretos (la parte pesada de CPU)
        # Cliente calcula
        s1 = pow(int.from_bytes(b_pub, 'big'), a_priv, p)
        # Servidor calcula
        s2 = pow(int.from_bytes(a_pub, 'big'), b_priv, p)

    end_time = time.time()
    avg_time = (end_time - start_time) / iterations
    avg_bytes = total_bytes / iterations
    
    print(f"   ⏱️  Tiempo promedio: {avg_time:.5f} seg")
    print(f"   📦 Peso promedio:   {avg_bytes:.0f} bytes")
    return avg_time, avg_bytes

def test_kyber_performance(iterations=100):
    print(f"\n--- 🛡️  Ronda 2: Kyber-512 Post-Quantum ({iterations} iters) ---")
    
    start_time = time.time()
    total_bytes = 0
    
    for _ in range(iterations):
        # 1. Servidor genera (KeyGen)
        pk, sk, server_kem = pqc_proto.generate_kyber_keypair()
        
        # 2. Cliente Encapsula (Encap)
        ciphertext, shared_secret_client = pqc_proto.kyber_encapsulate(pk)
        
        # Tráfico: Llave pública + Ciphertext
        total_bytes += len(pk) + len(ciphertext)
        
        # 3. Servidor Decapsula (Decap)
        shared_secret_server = pqc_proto.kyber_decapsulate(server_kem, ciphertext)
        
        # Limpieza manual (importante en Kyber)
        server_kem.free()

    end_time = time.time()
    avg_time = (end_time - start_time) / iterations
    avg_bytes = total_bytes / iterations
    
    print(f"   ⏱️  Tiempo promedio: {avg_time:.5f} seg")
    print(f"   📦 Peso promedio:   {avg_bytes:.0f} bytes")
    return avg_time, avg_bytes

def plot_results(dh_res, pqc_res):
    labels = ['DH (Clásico)', 'Kyber (Quantum)']
    times = [dh_res[0] * 1000, pqc_res[0] * 1000] # Convertir a milisegundos
    sizes = [dh_res[1], pqc_res[1]] # Bytes

    x = np.arange(len(labels))
    width = 0.35

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # Gráfica 1: Velocidad (Menos es mejor)
    rects1 = ax1.bar(x, times, width, color=['red', 'green'])
    ax1.set_ylabel('Tiempo de CPU (ms)')
    ax1.set_title('Velocidad de Cómputo (Menos es mejor)')
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels)
    ax1.bar_label(rects1, padding=3, fmt='%.2f ms')

    # Gráfica 2: Tamaño de Paquete (Menos es mejor para la red)
    rects2 = ax2.bar(x, sizes, width, color=['orange', 'blue'])
    ax2.set_ylabel('Bytes transferidos')
    ax2.set_title('Peso en la Red (Menos es mejor)')
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels)
    ax2.bar_label(rects2, padding=3, fmt='%.0f B')

    fig.tight_layout()
    print("\n[INFO] Generando gráfica comparativa...")
    plt.show()

if __name__ == "__main__":
    print("=== INICIANDO VERSUS: CLÁSICO VS QUANTUM ===")
    iters = 50 # Número de pruebas
    
    dh_t, dh_b = test_dh_performance(iters)
    pqc_t, pqc_b = test_kyber_performance(iters)
    
    plot_results((dh_t, dh_b), (pqc_t, pqc_b))