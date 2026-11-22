#!/bin/bash
# setup.sh - Script de instalación

echo "[*] Instalando herramientas WiFi..."

# 1. Actualizar sistema
sudo apt-get update
sudo apt-get upgrade -y

# 2. Instalar herramientas principales
sudo apt-get install -y \
    aircrack-ng \
    hashcat \
    hcxdumptool \
    hcxtools \
    mdk3 \
    bully \
    reaver \
    cowpatty \
    wireshark \
    tshark

# 3. Instalar dependencias Python
pip3 install colorama scapy pycryptodome

# 4. Crear estructura de directorios
mkdir -p wordlists results logs

# 5. Descargar wordlists comunes
echo "[*] Descargando wordlists..."
wget -O wordlists/rockyou.txt.gz https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt.gz
gunzip wordlists/rockyou.txt.gz

# 6. Configurar permisos
chmod +x wifi_auditor.py auto_wifi_audit.py smart_masks.py

echo "[+] Instalación completada!"
echo "[+] Ejecutar: sudo python3 wifi_auditor.py"