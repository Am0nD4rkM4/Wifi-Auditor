#!/usr/bin/env python3
"""
smart_masks.py - Genera máscaras inteligentes para hashcat
"""

import os


def generate_smart_masks():
    os.makedirs("wordlists", exist_ok=True)
    masks = []

    # Patrones numéricos
    masks.extend([
        "?d?d?d?d?d?d?d?d",
        "?d?d?d?d?d?d?d?d?d?d",
        "?d?d?d?d?d?d?d?d?d?d?d?d",
    ])

    # Alfanuméricos comunes
    masks.extend([
        "?l?l?l?l?d?d?d?d",
        "?d?d?d?d?l?l?l?l",
        "?u?l?l?l?d?d?d",
        "?l?l?l?u?d?d?d",
        "?l?l?l?l?l?l?l?l",
    ])

    # Prefijos comunes
    for prefix in ["wifi", "wireless", "home", "admin", "user", "network"]:
        masks.append(f"{prefix}?d?d?d?d")
        masks.append(f"{prefix}?d?d?d?d?d")
        masks.append(f"{prefix.capitalize()}?d?d?d?d")

    # Con caracteres especiales
    for ch in ["!", "@", "#", "$", "%", "&", "*"]:
        masks.append(f"?l?l?l?l?d?d?d?d{ch}")
        masks.append(f"{ch}?d?d?d?d?l?l?l?l")

    # Regionales
    masks.append("?d?d?d?d?d?d?d?d?d?d")  # Teléfono México
    masks.append("?d?d?d?d?d?d?d?d?l")     # DNI España

    out_file = "wordlists/smart_masks.txt"
    with open(out_file, "w") as f:
        for m in masks:
            f.write(f"{m}\n")

    print(f"[+] {len(masks)} máscaras generadas en: {out_file}")
    print("\nUso:")
    print(f"  hashcat -m 22000 hash.hc22000 -a 3 {out_file}")
    print(f"  hashcat -m 2500 handshake.hccap -a 3 {out_file}")


if __name__ == "__main__":
    generate_smart_masks()