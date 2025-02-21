# Cybersecurity Toolkit
# Created by Khalid Lawal
# Copyright © 2025

def main_menu():
    print("> Cybersecurity Toolkit")
    print(">> Select a tool:")
    print("1. Encryption & Decryption Tool")
    print("2. Brute Force Attack Simulator")
    print("3. Honeypot for Intrusion Detection")
    print("4. Web Vulnerability Scanner")
    print("5. Log Analyzer")
    print("6. Malware Analysis Tool")
    print("7. Keylogger")
    print("8. Password Strength Checker")
    print("9. Port Scanner")
    print("10. Network Packet Sniffer")
    print("11. Email Header Analyzer")
    print("12. Steganography Tool")
    print("13. Ransomware Simulator")
    print("0. Exit")
    
    choice = input("> Enter your choice: ")
    
    if choice == "0":
        print(">> Exiting...")
        exit()
    else:
        print(">> This feature is coming soon!")

if __name__ == "__main__":
    main_menu()
