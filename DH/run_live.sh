#!/bin/bash

echo "Wiseshark"
echo "[*] Abriendo Wireshark en vivo..."
wireshark -k -i lo -f "tcp port 12345" -Y "tcp.port == 12345" &
echo "[*] wiseshark init"
sleep 5
#Server
echo "[*] Server"
gnome-terminal --title="SERVIDOR" -- bash -c "python3 server.py; exec bash"

sleep 1

#Client
echo "[*] Client"
gnome-terminal --title="CLIENTE" -- bash -c "python3 client.py; exec bash"


