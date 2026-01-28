import time
import random
import sys
from scapy.all import IP, TCP, UDP, send

# ✅ TARGET IS YOUR WINDOWS HOST-ONLY IP
TARGET_IP = " "  
BLACKLIST_IP = " "

def simulate_port_scan(target):
    print(f"\n[>>>] Simulating PORT SCAN against {target}...")
    src_ip = " "  # Your Kali IP
    
    # Send 20 packets to different ports
    for i in range(20):
        dport = random.randint(1024, 65535)
        pkt = IP(src=src_ip, dst=target)/TCP(dport=dport, flags="S")
        send(pkt, verbose=0)
        print(f"    Sent SYN to port {dport}")
        time.sleep(0.05)
    print("[✔] Port Scan simulation complete.")

def simulate_dos(target):
    print(f"\n[>>>] Simulating DOS ATTACK against {target}...")
    src_ip = " " # Fake IP for DoS
    
    print("    Sending 250 packets rapidly...")
    for i in range(250):
        pkt = IP(src=src_ip, dst=target)/UDP(dport=80)
        send(pkt, verbose=0)
        if i % 50 == 0:
            sys.stdout.write(".")
            sys.stdout.flush()
    print("\n[✔] DoS simulation complete.")

def simulate_blacklist(target):
    print(f"\n[>>>] Simulating BLACKLIST IP access against {target}...")
    # Rule: Source IP is in BLACKLIST set
    pkt = IP(src=BLACKLIST_IP, dst=target)/TCP(dport=80, flags="S")
    send(pkt, verbose=0)
    print(f"[✔] Sent packet from blacklisted IP: {BLACKLIST_IP}")

def main():
    print(f"=== Kali Attack Simulator (Target: {TARGET_IP}) ===")
    
    while True:
        print("\nChoose an attack:")
        print("1. Port Scan")
        print("2. DoS Attack")
        print("3. Blacklist IP Event")
        print("4. Exit")
        
        choice = input("Select [1-4]: ").strip()
        
        if choice == '1':
            simulate_port_scan(TARGET_IP)
        elif choice == '2':
            simulate_dos(TARGET_IP)
        elif choice == '3':
            simulate_blacklist(TARGET_IP)
        elif choice == '4':
            break

if __name__ == "__main__":
    main()

