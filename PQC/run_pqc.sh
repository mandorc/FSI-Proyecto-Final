#!/bin/bash

echo "--- MODO EN VIVO: QUANTUM SAFE (KYBER) + WIRESHARK ---"

# 1. Abrir Wireshark inmediatamente en modo captura (-k)
# Filtramos el puerto 12345 igual que antes
echo "[*] Abriendo Wireshark para capturar tráfico Quantum..."
wireshark -k -i lo -f "tcp port 12345" -Y "tcp.port == 12345" &

echo "[*] Esperando a que Wireshark cargue..."
sleep 5

# 2. Lanza el SERVIDOR PQC (Kyber)
echo "[*] Lanzando Servidor Post-Quantum (Kyber)..."
gnome-terminal --title="SERVIDOR PQC (KYBER)" -- bash -c "python3 server_pqc.py; exec bash"

sleep 2

# 3. Lanza el CLIENTE PQC (Kyber)
echo "[*] Lanzando Cliente Post-Quantum (Kyber)..."
gnome-terminal --title="CLIENTE PQC (KYBER)" -- bash -c "python3 client_pqc.py; exec bash"

echo "---------------------------------------------------"
echo "  ¡SISTEMA QUANTUM ACTIVO!"
echo "  1. En Wireshark verás paquetes diferentes al anterior."
echo "  2. El 'Handshake' ahora intercambia matrices de retículos (Kyber),"
echo "     no números enteros grandes (Diffie-Hellman)."
echo "---------------------------------------------------"