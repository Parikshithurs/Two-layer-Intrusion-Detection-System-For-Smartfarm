# src/tools/test_replay.py
"""
Automated test + replay driver.

What it does (run from src/ with venv active):
1) Generates three pcaps using gen_traffic_pcap.py: good, portscan, blacklist
2) Replays each pcap into the IDS (python -m netids.capture --pcap ...)
3) After each replay, queries the alerts table and prints new alerts (summary)
4) Leaves the dashboard running — run dashboard.app in another terminal

Usage (from src):
    python tools/test_replay.py

Notes:
- Uses the same Python interpreter executing this script so it runs inside venv.
- Assumes gen_traffic_pcap.py is in src/ and netids.capture module works.
"""
import subprocess
import sys
import os
import time
import sqlite3

PY = sys.executable  # use current venv python
TOOLS_DIR = os.path.dirname(__file__)          # src/tools
ROOT = os.path.abspath(os.path.join(TOOLS_DIR, ".."))  # src

DATA_DIR = os.path.join(ROOT, "data")
os.makedirs(DATA_DIR, exist_ok=True)

DB_PATH = os.path.abspath(os.path.join(ROOT, "smartfarm_ids.db"))


def run_cmd(cmd, capture_output=False):
    """Run a command from the src/ folder so 'netids' package can be found."""
    print("> " + " ".join(cmd))
    res = subprocess.run(
        cmd,
        cwd=ROOT,  # <<< IMPORTANT: run from src/
        stdout=subprocess.PIPE if capture_output else None,
        stderr=subprocess.PIPE if capture_output else None,
        text=True,
    )
    if capture_output:
        return res.stdout, res.stderr, res.returncode
    return None, None, res.returncode


def gen_pcap(mode, target="10.0.0.100", **kwargs):
    """Call gen_traffic_pcap.py to generate a pcap and return its path."""
    gen_script = os.path.join(ROOT, "gen_traffic_pcap.py")
    args = [PY, gen_script, "--mode", mode, "--target", target]
    # add optional args
    for k, v in kwargs.items():
        args += [f"--{k.replace('_', '-')}", str(v)]

    stdout, stderr, rc = run_cmd(args, capture_output=True)
    if rc != 0:
        print("Error generating pcap:", stderr)
        raise SystemExit(1)

    # try to extract path from stdout
    for line in stdout.splitlines():
        if "pcap:" in line or line.strip().endswith(".pcap"):
            parts = line.strip().split()
            path = parts[-1]
            if os.path.exists(path):
                return path

    # fallback: newest pcap in data/
    files = sorted(
        [os.path.join(DATA_DIR, f) for f in os.listdir(DATA_DIR) if f.endswith(".pcap")],
        key=os.path.getmtime,
        reverse=True,
    )
    if files:
        return files[0]

    raise SystemExit("Could not find generated pcap")


def replay_pcap(pcap_path):
    """Replay a pcap through netids.capture."""
    cmd = [PY, "-m", "netids.capture", "--pcap", pcap_path]
    print(f"\n=== Replaying {os.path.basename(pcap_path)} ===")
    stdout, stderr, rc = run_cmd(cmd, capture_output=True)
    if rc != 0:
        print("Replay error:", stderr)
    else:
        print(stdout)


def get_current_max_id(db_path=DB_PATH):
    """Return current max alert id so we only show new alerts."""
    if not os.path.exists(db_path):
        return 0
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("SELECT COALESCE(MAX(id), 0) FROM alerts")
    (max_id,) = cur.fetchone()
    con.close()
    return max_id


def print_alert_summary(db_path=DB_PATH, last_seen=0):
    """Print alerts with id > last_seen and return new last_seen."""
    if not os.path.exists(db_path):
        print("[DB] No DB found at", db_path)
        return last_seen

    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute(
        "SELECT id, timestamp, src_ip, dst_ip, alert_type, severity "
        "FROM alerts WHERE id > ? ORDER BY id ASC",
        (last_seen,),
    )
    rows = cur.fetchall()
    if not rows:
        print("[DB] No new alerts.")
    else:
        print(f"[DB] {len(rows)} new alert(s):")
        for r in rows:
            print(f"  id={r[0]} time={r[1]} src={r[2]} dst={r[3]} type={r[4]} sev={r[5]}")
        last_seen = rows[-1][0]
    con.close()
    return last_seen


def main():
    # Ensure generator exists
    if not os.path.exists(os.path.join(ROOT, "gen_traffic_pcap.py")):
        print("Missing gen_traffic_pcap.py in src/ — put that file in src/ first.")
        return

    # Start from current max alert id, so we only see new alerts from this run
    last_seen = get_current_max_id()

    # Step A: generate good pcap
    good = gen_pcap("good", target="10.0.0.100", count=20)
    print("Generated good pcap:", good)
    replay_pcap(good)
    last_seen = print_alert_summary(last_seen=last_seen)

    time.sleep(1)

    # Step B: generate portscan pcap
    ps = gen_pcap("portscan", target="10.0.0.100", start_port=20, end_port=200)
    print("Generated portscan pcap:", ps)
    replay_pcap(ps)
    last_seen = print_alert_summary(last_seen=last_seen)

    time.sleep(1)

    # Step C: generate blacklist pcap
    bl = gen_pcap("blacklist", target="10.0.0.100", spoof_src="192.0.2.10", count=10)
    print("Generated blacklist pcap:", bl)
    replay_pcap(bl)
    last_seen = print_alert_summary(last_seen=last_seen)

    print("\nDone. You can inspect the DB or view the dashboard for live alerts.")
    print("Generated pcaps are in data/ — replay them individually any time.")


if __name__ == "__main__":
    main()
