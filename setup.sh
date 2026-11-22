#!/bin/bash
# setup.sh - Instalación automática de dependencias

set -e

echo "======================================"
echo "  INSTALADOR AUDITORÍA WIFI"
echo "======================================"

if [ "$EUID" -ne 0 ]; then
    echo "[!] Ejecutar como root: sudo ./setup.sh"
    exit 1
fi

echo "[*] Actualizando sistema..."
apt-get update -y

echo "[*] Instalando herramientas de auditoría WiFi..."
apt-get install -y \
    aircrack-ng \
    hashcat \
    hcxdumptool \
    hcxtools \
    mdk3 \
    bully \
    reaver \
    cowpatty \
    wireshark \
    tshark \
    wireless-tools \
    wpasupplicant

echo "[*] Instalando dependencias Python..."
apt-get install -y python3-pip
pip3 install colorama scapy pycryptodome

echo "[*] Creando estructura de directorios..."
mkdir -p wordlists results logs

echo "[*] Descargando rockyou.txt..."
if [ ! -f wordlists/rockyou.txt ]; then
    wget -q -O wordlists/rockyou.txt.gz \
        https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt.gz \
        || echo "[!] No se pudo descargar rockyou.txt"
    if [ -f wordlists/rockyou.txt.gz ]; then
        gunzip -f wordlists/rockyou.txt.gz
    fi
fi

echo "[*] Generando máscaras inteligentes..."
python3 smart_masks.py || true

echo "[*] Configurando permisos..."
chmod +x wifi_auditor.py auto_wifi_audit.py smart_masks.py 2>/dev/null || true

echo ""
echo "======================================"
echo "  ✓ INSTALACIÓN COMPLETADA"
echo "======================================"
echo ""
echo "Ejecutar:"
echo "  sudo python3 wifi_auditor.py        # Menú interactivo"
echo "  sudo python3 auto_wifi_audit.py     # Automatización"
echo ""