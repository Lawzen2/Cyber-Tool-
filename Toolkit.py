# -*- coding: utf-8 -*-
from __future__ import print_function
import os
import sys
import time
import hashlib
import socket
import smtplib
import re
import base64
import zipfile
import threading
import requests
from cryptography.fernet import Fernet
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from scapy.all import sniff, IP
from email import message_from_string
from getpass import getpass

try:
    input = raw_input  # Python 2 compatibility
except NameError:
    pass

# ================= MENU =================
def main_menu():
    while True:
        print("\n> Cybersecurity Toolkit")
        print(">> 1. Encryption & Decryption Tool")
        print(">> 2. Brute Force Attack Simulator")
        print(">> 3. Honeypot for Intrusion Detection")
        print(">> 4. Web Vulnerability Scanner")
        print(">> 5. Log Analyzer")
        print(">> 6. Malware Analysis Tool")
        print(">> 7. Keylogger")
        print(">> 8. Password Strength Checker")
        print(">> 9. Port Scanner")
        print(">> 10. Network Packet Sniffer")
        print(">> 11. Email Header Analyzer")
        print(">> 12. Steganography Tool")
        print(">> 13. Ransomware Simulator")
        print(">> 0. Exit")

        choice = input("> Choose a tool: ")

        tools = {
            "1": encryption_tool,
            "2": brute_force_sim,
            "3": honeypot,
            "4": web_scanner,
            "5": log_analyzer,
            "6": malware_analysis,
            "7": keylogger,
            "8": password_checker,
            "9": port_scanner,
            "10": packet_sniffer,
            "11": email_analyzer,
            "12": steganography_tool,
            "13": ransomware_sim
        }

        if choice == "0":
            print(">> Exiting... Stay Safe!")
            break
        elif choice in tools:
            tools[choice]()
        else:
            print(">> Invalid option. Try again.")

# ================= TOOLS =================

def encryption_tool():
    print("\n> Encryption & Decryption")
    text = input(">> Enter text: ")
    key = Fernet.generate_key()
    f = Fernet(key)
    encrypted = f.encrypt(text.encode())
    decrypted = f.decrypt(encrypted)
    print(">> Key:", key.decode())
    print(">> Encrypted:", encrypted.decode())
    print(">> Decrypted:", decrypted.decode())

def brute_force_sim():
    print("\n> Brute Force Simulation")
    password = "secure123"
    attempts = ["123", "pass", "secure123"]
    for guess in attempts:
        print(">> Trying:", guess)
        time.sleep(1)
        if guess == password:
            print(">> Password cracked:", guess)
            break

def honeypot():
    print("\n> Honeypot Running (Ctrl+C to stop)")
    s = socket.socket()
    s.bind(("0.0.0.0", 9999))
    s.listen(1)
    while True:
        conn, addr = s.accept()
        print(">> Intrusion attempt from:", addr)
        conn.close()

def web_scanner():
    print("\n> Web Vulnerability Scanner")
    url = input(">> Enter URL: ")
    common = ["admin", "login", "phpinfo"]
    for path in common:
        try:
            r = requests.get(url + "/" + path)
            print(">>", url + "/" + path, ":", r.status_code)
        except:
            print(">> Failed to scan path:", path)

def log_analyzer():
    print("\n> Log Analyzer")
    path = input(">> Path to log file: ")
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                if "error" in line.lower():
                    print(">>", line.strip())

def malware_analysis():
    print("\n> Malware Analysis Tool")
    file = input(">> File to scan (e.g. .exe): ")
    if os.path.exists(file):
        with open(file, 'rb') as f:
            data = f.read()
            md5 = hashlib.md5(data).hexdigest()
            print(">> MD5:", md5)

def keylogger():
    print("\n> Keylogger (Simulated)")
    print(">> Press any keys (Ctrl+C to exit)")
    try:
        while True:
            char = getpass('>> ')
            print(">> Key pressed:", char)
    except KeyboardInterrupt:
        print(">> Logging stopped.")

def password_checker():
    print("\n> Password Strength Checker")
    pw = input(">> Enter password: ")
    strength = "Weak"
    if len(pw) > 8 and re.search(r"[A-Z]", pw) and re.search(r"[0-9]", pw):
        strength = "Strong"
    elif len(pw) > 6:
        strength = "Moderate"
    print(">> Strength:", strength)

def port_scanner():
    print("\n> Port Scanner")
    target = input(">> Target IP: ")
    for port in range(75, 81):
        s = socket.socket()
        s.settimeout(1)
        if s.connect_ex((target, port)) == 0:
            print(">> Port", port, "is open")
        s.close()

def packet_sniffer():
    print("\n> Packet Sniffer")
    print(">> Sniffing packets (Ctrl+C to stop)")
    sniff(filter="ip", prn=lambda x: x.summary(), store=0)

def email_analyzer():
    print("\n> Email Header Analyzer")
    raw = input(">> Paste full email headers: ")
    msg = message_from_string(raw)
    for header in ["From", "To", "Received", "Subject"]:
        print(">>", header + ":", msg.get(header))

def steganography_tool():
    print("\n> Steganography Tool")
    choice = input(">> 1) Hide  2) Extract: ")
    if choice == "1":
        msg = input(">> Message to hide: ")
        out = base64.b64encode(msg.encode())
        with open("hidden.txt", "wb") as f:
            f.write(out)
        print(">> Message hidden in hidden.txt")
    else:
        with open("hidden.txt", "rb") as f:
            data = base64.b64decode(f.read())
            print(">> Extracted Message:", data.decode())

def ransomware_sim():
    print("\n> Ransomware Simulator")
    file = input(">> File to simulate lock: ")
    if os.path.exists(file):
        with zipfile.ZipFile("locked.zip", 'w') as z:
            z.write(file)
        os.remove(file)
        print(">> File encrypted (simulated). Original removed.")

# ================= START =================
if __name__ == "__main__":
    main_menu()
    print("\nCreated by Khalid")
    print("Copyright © 2025")
