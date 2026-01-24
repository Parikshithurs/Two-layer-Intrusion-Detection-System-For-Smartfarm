# src/run_ids.py
"""
Simple runner for SmartFarm IDS Layer 1.

Usage (from project root with venv active, in an *elevated* PowerShell):

  # Interactive mode (Recommended - lets you pick the interface)
  python src/run_ids.py

  # Force a specific interface
  python src/run_ids.py --iface "Ethernet"

  # Replay latest pcap
  python src/run_ids.py replay
"""

import os
import sys
import subprocess
import argparse
from scapy.all import get_if_list, get_if_addr, conf

PY = sys.executable
ROOT = os.path.dirname(__file__)
DATA = os.path.join(ROOT, "data")

def get_valid_interface():
    """
    Helps the user pick a valid interface by showing IP addresses.
    """
    print("\n[?] Scanning for network interfaces...")
    interfaces = get_if_list()
    
    # Try to filter out loopback/empty ones for a cleaner list
    valid_ifaces = []
    for iface in interfaces:
        try:
            ip = get_if_addr(iface)
            # On Windows, Scapy sometimes lists interfaces weirdly. 
            # We want interfaces that have a real IP (not 0.0.0.0 or 127.0.0.1 if possible)
            if ip != "0.0.0.0":
                valid_ifaces.append((iface, ip))
        except:
            pass

    if not valid_ifaces:
        print("[!] No active interfaces found with Scapy. Defaulting to all.")
        valid_ifaces = [(i, "N/A") for i in interfaces]

    print(f"{'INDEX':<8} {'INTERFACE NAME':<40} {'IP ADDRESS':<20}")
    print("-" * 70)
    for idx, (name, ip) in enumerate(valid_ifaces):
        print(f"{idx:<8} {name:<40} {ip:<20}")
    print("-" * 70)

    while True:
        try:
            selection = input("\n[>] Enter the INDEX of the interface to use (e.g., 0): ")
            idx = int(selection)
            if 0 <= idx < len(valid_ifaces):
                chosen_iface = valid_ifaces[idx][0]
                print(f"[+] Selected Interface: {chosen_iface}")
                return chosen_iface
            else:
                print("[!] Invalid index. Try again.")
        except ValueError:
            print("[!] Please enter a number.")

def run_capture_live(iface: str) -> None:
    """Start live capture on given interface."""
    # If no interface provided, force user to pick one
    if not iface:
        iface = get_valid_interface()

    print(f"\n[RUN] Starting IDS on interface: {iface}")
    print("[INFO] Press Ctrl+C to stop.")
    
    # We must quote the interface name for the subprocess command in case it has spaces
    cmd = [PY, "-m", "src.netids.capture", "--iface", iface]
    subprocess.call(cmd)


def run_capture_replay() -> None:
    """Replay latest pcap file from src/data into the IDS."""
    if not os.path.isdir(DATA):
        print(f"[ERROR] Data folder not found: {DATA}")
        return

    pcaps = [
        os.path.join(DATA, f)
        for f in os.listdir(DATA)
        if f.lower().endswith(".pcap")
    ]
    if not pcaps:
        print("[ERROR] No .pcap files found in src/data/.")
        return

    latest = max(pcaps, key=os.path.getmtime)
    print(f"[RUN] Replaying latest PCAP: {latest}\n")
    cmd = [PY, "-m", "src.netids.capture", "--pcap", latest]
    subprocess.call(cmd)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--iface",
        "-i",
        default=None,   # CHANGED: Default is now None to trigger selection
        help="Interface name for live capture (leave empty to select from list)",
    )
    parser.add_argument(
        "mode",
        nargs="?",
        choices=["live", "replay"],
        default="live",
        help="Mode: 'live' (default) or 'replay'",
    )
    args = parser.parse_args()

    if args.mode == "replay":
        run_capture_replay()
    else:
        run_capture_live(args.iface)


if __name__ == "__main__":
    main()