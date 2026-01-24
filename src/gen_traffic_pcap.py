"""
gen_traffic_pcap.py — Generate PCAPs (good / portscan / dos / blacklist / combined)

Usage examples (run from src/ with venv active):

# Generate a "good" pcap (20 MQTT-like flows)
python gen_traffic_pcap.py --mode good --target 10.0.0.100 --count 20

# Generate a port-scan pcap (ports 20..200)
python gen_traffic_pcap.py --mode portscan --target 10.0.0.100 --start-port 20 --end-port 200

# Generate a DoS-like UDP burst pcap (pps * duration packets generated)
python gen_traffic_pcap.py --mode dos --target 10.0.0.100 --pps 500 --duration 5

# Generate traffic from a blacklisted source IP (spoofed src)
python gen_traffic_pcap.py --mode blacklist --target 10.0.0.100 --spoof-src 192.0.2.10 --count 10

# Combined mixed traffic
python gen_traffic_pcap.py --mode combined --target 10.0.0.100 --count 60 --pps 300 --duration 4

Output pcap saved to: data/<mode>_<timestamp>.pcap   (inside src/data)
"""
from scapy.all import IP, TCP, UDP, wrpcap
import argparse
import random
import os
from datetime import datetime


def gen_good_traffic(target, count=20):
    pkts = []
    for i in range(count):
        sport = random.randint(2000, 4000)
        dport = 1883  # MQTT-like benign port
        pkts.append(IP(dst=target) / TCP(sport=sport, dport=dport))
    return pkts


def gen_portscan(target, start_port=1, end_port=1024):
    pkts = []
    for p in range(start_port, end_port + 1):
        sport = random.randint(1024, 65535)
        pkts.append(IP(dst=target) / TCP(sport=sport, dport=p, flags="S"))
    return pkts


def gen_dos_udp(target, pps=200, duration=5):
    pkts = []
    total = max(1, int(pps * duration))
    for _ in range(total):
        sport = random.randint(1024, 65535)
        dst_port = random.randint(1024, 65535)
        pkts.append(IP(dst=target) / UDP(sport=sport, dport=dst_port) / ("X" * 64))
    return pkts


def gen_blacklist_traffic(target, spoof_src="192.0.2.10", count=10):
    pkts = []
    for _ in range(count):
        sport = random.randint(1024, 65535)
        pkts.append(IP(src=spoof_src, dst=target) / TCP(sport=sport, dport=80))
    return pkts


def gen_combined(target, count=60, start_port=20, end_port=200, pps=200, duration=3):
    # Mix of good, portscan, and dos
    pkts = []
    pkts += gen_good_traffic(target, count=max(5, count // 4))
    pkts += gen_portscan(target, start_port=start_port, end_port=min(end_port, start_port + 40))
    pkts += gen_dos_udp(target, pps=pps, duration=max(1, duration // 2))
    return pkts


def write_pcap(pkts, out_path):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    wrpcap(out_path, pkts)
    return out_path, len(pkts)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["good", "portscan", "dos", "blacklist", "combined"], required=True)
    parser.add_argument("--target", required=True, help="Target IP (e.g., gateway or host under test)")
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--start-port", type=int, default=1)
    parser.add_argument("--end-port", type=int, default=1024)
    parser.add_argument("--pps", type=int, default=200)
    parser.add_argument("--duration", type=int, default=5)
    parser.add_argument("--spoof-src", default="192.0.2.10")
    parser.add_argument("--out", default=None, help="Optional output filename (overrides auto name)")
    args = parser.parse_args()

    if args.mode == "good":
        pkts = gen_good_traffic(args.target, count=args.count)
    elif args.mode == "portscan":
        pkts = gen_portscan(args.target, start_port=args.start_port, end_port=args.end_port)
    elif args.mode == "dos":
        pkts = gen_dos_udp(args.target, pps=args.pps, duration=args.duration)
    elif args.mode == "blacklist":
        pkts = gen_blacklist_traffic(args.target, spoof_src=args.spoof_src, count=args.count)
    elif args.mode == "combined":
        pkts = gen_combined(
            args.target,
            count=args.count,
            start_port=args.start_port,
            end_port=args.end_port,
            pps=args.pps,
            duration=args.duration,
        )
    else:
        raise SystemExit("Unknown mode")

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    if args.out:
        out_path = args.out
    else:
        # save under src/data/
        filename = f"{args.mode}_{args.target.replace('.', '_')}_{timestamp}.pcap"
        out_path = os.path.join("data", filename)

    path, n = write_pcap(pkts, out_path)
    print(f"[+] Wrote {n} packets to pcap: {os.path.abspath(path)}")


if __name__ == "__main__":
    main()
