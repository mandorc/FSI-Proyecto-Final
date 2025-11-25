# Cipher Project: DH vs Post-Quantum (Kyber)

Este proyecto compara un intercambio de llaves clásico (Diffie-Hellman) contra uno resistente a computación cuántica (Kyber-512).

## Estructura
- `/DH`: Implementación clásica con Diffie-Hellman y AES-GCM.
- `/PQC`: Implementación Post-Quantum con Kyber-512 y AES-GCM.

## Requisitos Previos (Linux/Ubuntu)

1. Instalar dependencias del sistema para compilar Kyber:
   ```bash
   sudo apt install -y astyle cmake gcc ninja-build libssl-dev python3-dev unzip xsltproc doxygen graphviz python3-yaml valgrind