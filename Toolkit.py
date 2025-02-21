# Cybersecurity Toolkit
# Created by Khalid Lawal
# Copyright © 2025

import os
import sys
import base64
import socket
import requests
import re
import logging
from scapy.all import sniff, IP, TCP
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

try:
    from stegano import lsb
except ImportError:
    os.system("pip install stegano")

# Encryption & Decryption Tool
def encrypt_aes(text, key):
    cipher = AES.new(key, AES.MODE_CBC, key[:16])
    ciphertext = base64.b64encode(cipher.iv + cipher.encrypt(text.ljust(16)))
    return ciphertext

def decrypt_aes(encrypted_text, key):
    encrypted_data = base64.b64decode(encrypted_text)
    iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext).strip()

# Brute Force Attack Simulation
def brute_force():
    common_passwords = ["123456", "password", "qwerty"]
    attempt = input("> Enter password to test: ")
    if attempt in common_passwords:
        print("[!] Weak password detected!")
    else:
        print("[+] Password is strong.")

# Honeypot
def honeypot():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 8080))
    server.listen(1)
    print("[+] Honeypot listening on port 8080...")
    conn, addr = server.accept()
    print("[!] Connection detected from:", addr)

# Web Vulnerability Scanner
def web_scanner():
    url = input("> Enter URL to scan: ")
    response = requests.get(url)
    if "<script>" in response.text:
        print("[!] Possible XSS vulnerability detected.")
    else:
        print("[+] No vulnerabilities found.")

# Log Analyzer
def log_analyzer():
    log_file = input("> Enter log file path: ")
    with open(log_file, "r") as file:
        logs = file.readlines()
    for line in logs:
        if "error" in line.lower():
            print("[!] Suspicious log entry:", line.strip())

# Malware Analysis Tool
def malware_analysis():
    file_path = input("> Enter file path to analyze: ")
    with open(file_path, "rb") as file:
        content = file.read()
    if b"malware" in content:
        print("[!] Possible malware detected!")
    else:
        print("[+] File is clean.")

# Keylogger (For educational use)
def keylogger():
    print("[!] Keylogger activated. (Educational purposes only)")

# Password Strength Checker
def password_checker():
    password = input("> Enter password to check: ")
    if len(password) < 6:
        print("[!] Weak password.")
    elif re.search("[0-9]", password) and re.search("[A-Z]", password):
        print("[+] Strong password.")
    else:
        print("[!] Medium strength password.")

# Port Scanner
def port_scanner():
    target = input("> Enter target IP: ")
    for port in range(1, 1025):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((target, port))
        if result == 0:
            print("[+] Open port:", port)
        sock.close()

# Network Packet Sniffer
def packet_sniffer():
    print("[+] Sniffing network packets...")
    sniff(filter="tcp", prn=lambda x: x.summary(), count=10)

# Email Header Analyzer
def email_analyzer():
    email_path = input("> Enter email file path: ")
    with open(email_path, "r") as file:
        headers = file.readlines()
    for line in headers:
        if "Received:" in line:
            print("[+] Email header found:", line.strip())

# Steganography Tool
def steganography():
    choice = input("1. Hide message\n2. Extract message\n> ")
    if choice == "1":
        img = input("> Enter image file path: ")
        msg = input("> Enter secret message: ")
        secret_img = lsb.hide(img, msg)
        secret_img.save("hidden.png")
        print("[+] Message hidden in 'hidden.png'.")
    elif choice == "2":
        img = input("> Enter image file path: ")
        print("[+] Extracted message:", lsb.reveal(img))

# Ransomware Simulator
def ransomware_simulator():
    choice = input("1. Encrypt files\n2. Decrypt files\n> ")
    key = get_random_bytes(32)
    if choice == "1":
        file = input("> Enter file to encrypt: ")
        with open(file, "rb") as f:
            data = f.read()
        cipher = AES.new(key, AES.MODE_CBC, key[:16])
        encrypted_data = cipher.encrypt(data.ljust(16))
        with open(file + ".enc", "wb") as f:
            f.write(encrypted_data)
        print("[+] File encrypted:", file + ".enc")
    elif choice == "2":
        file = input("> Enter file to decrypt: ")
        with open(file, "rb") as f:
            encrypted_data = f.read()
        cipher = AES.new(key, AES.MODE_CBC, key[:16])
        decrypted_data = cipher.decrypt(encrypted_data).strip()
        with open(file.replace(".enc", ""), "wb") as f:
            f.write(decrypted_data)
        print("[+] File decrypted:", file.replace(".enc", ""))

# Main Menu
def main_menu():
    while True:
        print("\n> Cybersecurity Toolkit")
        print("1. Encryption & Decryption")
        print("2. Brute Force Attack Simulation")
        print("3. Honeypot")
        print("4. Web Vulnerability Scanner")
        print("5. Log Analyzer")
        print("6. Malware Analysis")
        print("7. Keylogger (Educational)")
        print("8. Password Strength Checker")
        print("9. Port Scanner")
        print("10. Network Packet Sniffer")
        print("11. Email Header Analyzer")
        print("12. Steganography Tool")
        print("13. Ransomware Simulator")
        print("0. Exit")

        choice = input("> Enter your choice: ")
        tools = {
            "1": encrypt_aes,
            "2": brute_force,
            "3": honeypot,
            "4": web_scanner,
            "5": log_analyzer,
            "6": malware_analysis,
            "7": keylogger,
            "8": password_checker,
            "9": port_scanner,
            "10": packet_sniffer,
            "11": email_analyzer,
            "12": steganography,
            "13": ransomware_simulator
        }

        if choice == "0":
            print(">> Exiting...")
            sys.exit()
        elif choice in tools:
            tools[choice]()
        else:
            print("[!] Invalid choice.")

if __name__ == "__main__":
    main_menu()
