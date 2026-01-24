# src/netids/capture.py
import time
import platform
from scapy.all import sniff, IP, TCP, UDP, get_if_list

# ✅ use relative imports inside the netids package
from .models import SessionLocal, init_db, Alert
from .rules import feed_packet

import argparse
import subprocess
import shlex
import os

init_db()

def make_alert(session, src, dst, alert_type, desc, severity=1):
    a = Alert(src_ip=src, dst_ip=dst, alert_type=alert_type, description=desc, severity=severity)
    session.add(a)
    session.commit()
    print(f"[ALERT] {alert_type} - {desc}")
    return a

# ---------- Windows blocking ----------
def block_ip_windows(ip, alert_id=None):
    """
    Adds a Windows Firewall rule to block inbound traffic from `ip`.
    Requires Administrator privileges.
    The rule's DisplayName is set to include 'SmartFarmIDS' and the alert id for easy cleanup.
    """
    display_name = f"SmartFarmIDS-block-{ip.replace('.', '_')}"
    if alert_id:
        display_name += f"-{alert_id}"
    # PowerShell command to add firewall rule
    ps_cmd = (
        f"New-NetFirewallRule -DisplayName '{display_name}' "
        f"-Direction Inbound -Action Block -RemoteAddress {ip} -Description 'Added by SmartFarmIDS'"
    )
    cmd = ["powershell", "-Command", ps_cmd]
    try:
        subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=False)
        print(f"[ACTION] Windows Firewall rule created: {display_name} (blocks {ip})")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to create Windows Firewall rule: {e.output.decode(errors='ignore')}")
        return False

def unblock_ip_windows(ip=None, display_name_contains=None):
    """
    Remove Windows firewall rules created by SmartFarmIDS.
    You can pass an ip or part of the display name to remove matching rules.
    """
    if ip:
        name_pattern = f"SmartFarmIDS-block-{ip.replace('.', '_')}"
        ps_cmd = f"Get-NetFirewallRule -DisplayName '{name_pattern}*' | Remove-NetFirewallRule -Confirm:$false"
    elif display_name_contains:
        ps_cmd = f"Get-NetFirewallRule | Where-Object {{$_.DisplayName -like '*{display_name_contains}*'}} | Remove-NetFirewallRule -Confirm:$false"
    else:
        ps_cmd = "Get-NetFirewallRule | Where-Object {$_.DisplayName -like 'SmartFarmIDS-block-*'} | Remove-NetFirewallRule -Confirm:$false"
    cmd = ["powershell", "-Command", ps_cmd]
    try:
        subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=False)
        print("[ACTION] Removed matching SmartFarmIDS Windows Firewall rules.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to remove rules: {e.output.decode(errors='ignore')}")
        return False

# ---------- Linux blocking (kept for cross-platform) ----------
def block_ip_linux(ip, reason="blocked-by-ids"):
    try:
        cmd = f"iptables -I INPUT -s {shlex.quote(ip)} -j DROP -m comment --comment {shlex.quote(reason)}"
        subprocess.check_call(cmd, shell=True)
        print(f"[ACTION] iptables rule inserted to DROP {ip}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] failed to insert iptables rule: {e}")
        return False

# ---------- Packet processing ----------
def pkt_callback(pkt):
    if IP not in pkt:
        return
    src = pkt[IP].src
    dst = pkt[IP].dst
    sport = None
    dport = None
    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

    pkt_info = {
        "ts": time.time(),
        "src_ip": src,
        "dst_ip": dst,
        "sport": sport,
        "dport": dport,
        "proto": pkt[IP].proto
    }

    out = feed_packet(pkt_info)
    if out:
        session = SessionLocal()
        a = make_alert(session, src, dst, out["type"], out["desc"], severity=out.get("severity", 1))
        # Optional auto-blocking based on platform and flags set via env
        try:
            if os.environ.get("IDS_AUTOBLOCK", "").lower() in ("1","true","yes"):
                if platform.system() == "Windows":
                    blocked = block_ip_windows(src, alert_id=a.id)
                    if blocked:
                        a.description = a.description + f" [blocked: Windows-FW]"
                        session.add(a); session.commit()
                else:
                    blocked = block_ip_linux(src, reason=f"ids:{a.id}:{out['type']}")
                    if blocked:
                        a.description = a.description + f" [blocked: iptables]"
                        session.add(a); session.commit()
        except Exception as e:
            print("[ERROR] blocking failed:", e)
        session.close()

def start_capture(interface=None, pcap_file=None, count=0):
    if pcap_file:
        print(f"Reading from pcap: {pcap_file}")
        sniff(offline=pcap_file, prn=pkt_callback, store=0)
    else:
        print(f"Sniffing on interface: {interface} (admin/root may be required).")
        sniff(iface=interface, prn=pkt_callback, store=0, filter="ip", count=count)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", "-i", default=None, help="Network interface to sniff (e.g., 'Ethernet')")
    parser.add_argument("--pcap", default=None, help="PCAP file to replay")
    parser.add_argument("--count", type=int, default=0)
    parser.add_argument("--autoblock-windows", action="store_true", help="Enable Windows Firewall blocking (Admin required)")
    parser.add_argument("--autoblock", action="store_true", help="Enable blocking (cross-platform; prefer --autoblock-windows on Windows)")
    args = parser.parse_args()

    # For convenience, set env var so pkt_callback sees it
    if args.autoblock or args.autoblock_windows:
        os.environ["IDS_AUTOBLOCK"] = "true"

    # If user didn't pass --iface on Windows, try to suggest one
    if not args.pcap and not args.iface:
        print("Available interfaces (Scapy):", get_if_list())
        print("Choose an interface using --iface <name>")

    start_capture(interface=args.iface, pcap_file=args.pcap, count=args.count)
