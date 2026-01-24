# src/netids/rules.py
import time
from collections import defaultdict, deque

# Tunable thresholds
PORT_SCAN_WINDOW = 10.0        # seconds
PORT_SCAN_PORT_THRESH = 15     # distinct dst ports => port-scan
DOS_WINDOW = 5.0               # seconds
DOS_PKT_THRESHOLD = 50      # packets in window => possible DoS

# Lightweight state stores (in-memory)
_pkt_history = defaultdict(lambda: deque())
_syn_history = defaultdict(lambda: deque())

# Example blacklist (replace/add real IPs later)
BLACKLIST = {"192.0.2.10"}
INSECURE_PORTS = {23, 21}  # telnet, ftp

def check_blacklist(src_ip):
    if src_ip in BLACKLIST:
        return {"type": "blacklist", "desc": f"Source {src_ip} is in blacklist.", "severity": 5}
    return None

def feed_packet(pkt_info):
    """
    pkt_info: dict with keys: src_ip, dst_ip, sport, dport, proto, ts
    returns: alert dict or None
    """
    now = pkt_info["ts"]
    src = pkt_info["src_ip"]
    dport = pkt_info.get("dport")

    # 1) Blacklist
    bl = check_blacklist(src)
    if bl:
        return bl

    # 2) DoS-like: high packet rate
    ph = _pkt_history[src]
    ph.append(now)
    while ph and now - ph[0] > DOS_WINDOW:
        ph.popleft()
    if len(ph) >= DOS_PKT_THRESHOLD:
        return {"type": "dos", "desc": f"High packet rate from {src} ({len(ph)} pkts in {DOS_WINDOW}s)", "severity": 5}

    # 3) Port-scan: many distinct dports in short window
    if dport is not None:
        sh = _syn_history[src]
        sh.append((now, dport))
        while sh and now - sh[0][0] > PORT_SCAN_WINDOW:
            sh.popleft()
        distinct_ports = {p for (_, p) in sh}
        if len(distinct_ports) >= PORT_SCAN_PORT_THRESH:
            return {"type": "port-scan", "desc": f"{src} probed {len(distinct_ports)} distinct dst ports in {PORT_SCAN_WINDOW}s", "severity": 4}

    # 4) Insecure protocol used
    if dport in INSECURE_PORTS:
        return {"type": "insecure-protocol", "desc": f"Traffic to insecure port {dport} from {src}", "severity": 3}

    return None
