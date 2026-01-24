# attack_sim.py
import time
import random
import sys
from scapy.all import IP, TCP, UDP, send, get_if_list

# Configuration matching your rules.py
TARGET_IP = "127.0.0.1"  # Default, we will ask user to confirm
BLACKLIST_IP = "192.0.2.10"

def get_target_ip():
    """Ask user for the IP address the IDS is listening on."""
    print(f"\n[?] Enter the IP address your IDS is listening on.")
    print(f"    (Check the 'IP ADDRESS' shown in your other terminal)")
    ip = input(f"    Target IP [default: {TARGET_IP}]: ").strip()
    return ip if ip else TARGET_IP

def simulate_port_scan(target):
    print(f"\n[>>>] Simulating PORT SCAN against {target}...")
    # Rule: >15 distinct ports in 10s
    src_ip = "10.0.0.66"  # Fake attacker IP
    
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
    # Rule: >200 packets in 5s
    src_ip = "10.0.0.99" # Fake attacker IP
    
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
    print("=== Smart Farm IDS Attack Simulator ===")
    target = get_target_ip()
    
    while True:
        print("\nChoose an attack to simulate:")
        print("1. Port Scan")
        print("2. DoS Attack")
        print("3. Blacklist IP Event")
        print("4. Exit")
        
        choice = input("Select [1-4]: ").strip()
        
        if choice == '1':
            simulate_port_scan(target)
        elif choice == '2':
            simulate_dos(target)
        elif choice == '3':
            simulate_blacklist(target)
        elif choice == '4':
            print("Exiting.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()