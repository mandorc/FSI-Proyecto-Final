#!/bin/bash

echo "--- LIVE MODE: QUANTUM SAFE (KYBER) + WIRESHARK ---"

# 1. Open Wireshark immediately in capture mode (-k)
# We filter port 12345 as before
echo "[*] Opening Wireshark to capture quantum traffic..."
wireshark -k -i lo -f "tcp port 12345" -Y "tcp.port == 12345" &

echo "[*] Waiting for Wireshark to load..."
sleep 5

# 2. Launch the PQC SERVER (Kyber)
echo "[*] Starting Post-Quantum Server (Kyber)..."
gnome-terminal --title="PQC SERVER (KYBER)" -- bash -c "python3 server_pqc.py; exec bash"

sleep 2

# 3. Launch the PQC CLIENT (Kyber)
echo "[*] Starting Post-Quantum Client (Kyber)..."
gnome-terminal --title="PQC CLIENT (KYBER)" -- bash -c "python3 client_pqc.py; exec bash"

echo "---------------------------------------------------"
echo "  QUANTUM SYSTEM ACTIVE!"
echo "  1. In Wireshark you'll see packets different than before."
echo "  2. The handshake now exchanges lattice matrices (Kyber),"
echo "     not large integers (Diffie-Hellman)."
echo "---------------------------------------------------"