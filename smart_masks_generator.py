#!/usr/bin/env python3
"""
smart_masks.py - Generador de máscaras inteligentes
"""

import itertools

def generate_smart_masks():
    """Generar máscaras basadas en patrones comunes"""
    
    masks = []
    
    # 1. Patrones numéricos
    masks.extend([
        "?d?d?d?d?d?d?d?d",          # 8 dígitos
        "?d?d?d?d?d?d?d?d?d?d",      # 10 dígitos
        "?d?d?d?d?d?d?d?d?d?d?d?d",  # 12 dígitos
    ])
    
    # 2. Patrones alfanuméricos comunes
    masks.extend([
        "?l?l?l?l?d?d?d?d",          # 4 letras + 4 números
        "?d?d?d?d?l?l?l?l",          # 4 números + 4 letras
        "?u?l?l?l?d?d?d",            # 1 mayúscula + 3 min + 3 números
        "?l?l?l?u?d?d?d",            # 3 min + 1 mayúscula + 3 números
    ])
    
    # 3. Patrones con palabras comunes
    wifi_prefixes = ["wifi", "wireless", "home", "admin", "user", "network"]
    for prefix in wifi_prefixes:
        masks.append(f"{prefix}?d?d?d?d")
        masks.append(f"{prefix}?d?d?d?d?d")
        masks.append(f"{prefix.capitalize()}?d?d?d?d")
    
    # 4. Patrones con caracteres especiales
    special_chars = ["!", "@", "#", "$", "%", "&", "*"]
    for char in special_chars:
        masks.append(f"?l?l?l?l?d?d?d?d{char}")
        masks.append(f"{char}?d?d?d?d?l?l?l?l")
    
    # 5. Patrones específicos por país/región
    # México: números de teléfono (10 dígitos)
    masks.append("?d?d?d?d?d?d?d?d?d?d")
    
    # España: DNI-like (8 números + letra)
    masks.append("?d?d?d?d?d?d?d?d?l")
    
    # Guardar máscaras
    with open("wordlists/smart_masks.txt", "w") as f:
        for mask in masks:
            f.write(f"{mask}\n")
    
    print(f"[+] {len(masks)} máscaras generadas en 'wordlists/smart_masks.txt'")
    print("\nEjemplos de uso:")
    print("  hashcat -m 22000 hash.hc22000 -a 3 wordlists/smart_masks.txt")
    print("  hashcat -m 2500 handshake.hccap -a 3 wordlists/smart_masks.txt")

def generate_custom_mask(pattern_type, length=8):
    """Generar máscara personalizada"""
    
    patterns = {
        "numeric": "?d" * length,
        "lowercase": "?l" * length,
        "uppercase": "?u" * length,
        "alphanumeric": "?a" * length,
        "mixed": "?l?l?l?l?d?d?d?d" if length == 8 else "?a" * length,
    }
    
    if pattern_type in patterns:
        return patterns[pattern_type]
    else:
        return "?a" * length

if __name__ == "__main__":
    generate_smart_masks()