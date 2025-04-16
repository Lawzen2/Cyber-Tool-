# Cybersecurity Toolkit

A powerful Python-based cybersecurity toolkit that provides scanning, encryption, monitoring, and attack simulation tools to assist security professionals and students in learning and practicing cybersecurity skills.

## Features

This toolkit includes the following modules:

1. **Encryption & Decryption Tool** - Encrypts and decrypts text using the Fernet module.
2. **Brute Force Attack Simulator** - Simulates a basic dictionary brute force attack.
3. **Honeypot for Intrusion Detection** - Simulates a honeypot server to catch unauthorized access attempts.
4. **Web Vulnerability Scanner** - Scans for common web paths such as `/admin`, `/login`, etc.
5. **Log Analyzer** - Analyzes logs to detect error messages.
6. **Malware Analysis Tool** - Computes the MD5 hash of files to check for tampering.
7. **Keylogger (Simulated)** - Simulates keystroke logging.
8. **Password Strength Checker** - Checks the strength of a password based on length and character composition.
9. **Port Scanner** - Scans a small range of ports on a target machine.
10. **Network Packet Sniffer** - Sniffs and displays IP packets using `scapy`.
11. **Email Header Analyzer** - Parses email headers and displays relevant fields.
12. **Steganography Tool** - Hides and extracts messages using base64 encoding.
13. **Ransomware Simulator** - Simulates a ransomware attack by compressing and deleting the original file.

## Requirements

- Python 2.7 or Python 3.x
- Modules:
  - cryptography
  - pycryptodome
  - requests
  - scapy

Install requirements:
```bash
pip install cryptography pycryptodome requests scapy
```

## Usage

Run the script using:
```bash
python Toolkit.py
```

Follow the on-screen menu to choose a tool.

## License

This project is open-source and created for educational purposes.

**Created by Khalid**  
**Copyright © 2025**
