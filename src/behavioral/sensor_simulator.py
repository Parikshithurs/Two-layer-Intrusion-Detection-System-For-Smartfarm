# src/behavioral/sensor_simulator.py
"""
Sensor simulator for smart-farm behavioral IDS (Layer 2).

- Simulates multiple IoT devices with farm sensors:
    temperature, humidity, soil_moisture, light, ph, co2
- Writes EVERY reading into telemetry.db (for training + detection).
- Each device mostly behaves normally.
- Sometimes, a device randomly enters an anomaly mode (spike/drift/stuck/noisy)
  for a short period, then returns to normal.

Usage (from src/ with venv active):

    python behavioral\sensor_simulator.py

You can optionally change the number of devices or interval:

    python behavioral\sensor_simulator.py --num-devices 8 --interval 2
"""
import os
import time
import random
import sqlite3
import argparse
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(ROOT, "telemetry.db")

# Normal ranges for each sensor
SENSORS = {
    "temperature":   {"min": 15.0, "max": 35.0},    # °C
    "humidity":      {"min": 30.0, "max": 80.0},    # %
    "soil_moisture": {"min": 200.0, "max": 800.0},  # raw units
    "light":         {"min": 100.0, "max": 2000.0}, # lux
    "ph":            {"min": 5.5, "max": 7.5},      # pH
    "co2":           {"min": 300.0, "max": 1200.0}  # ppm
}

ANOMALY_MODES = ["spike", "drift", "stuck", "noisy"]


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            device_id TEXT,
            sensor_type TEXT,
            value REAL
        )
        """
    )
    con.commit()
    con.close()


def insert_reading(device_id: str, sensor_type: str, value: float):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    ts = datetime.now(timezone.utc).isoformat()
    cur.execute(
        "INSERT INTO telemetry (timestamp, device_id, sensor_type, value) VALUES (?, ?, ?, ?)",
        (ts, device_id, sensor_type, float(value)),
    )
    con.commit()
    con.close()


def normal_value(sensor: str) -> float:
    cfg = SENSORS[sensor]
    low, high = cfg["min"], cfg["max"]
    center = (low + high) / 2.0
    # use gaussian noise so most values lie in the normal range
    span = (high - low) / 6.0  # ~99% within range
    return random.gauss(center, span)


def anomalous_value(sensor: str, mode: str, local_tick: int) -> float:
    cfg = SENSORS[sensor]
    low, high = cfg["min"], cfg["max"]
    center = (low + high) / 2.0
    span = (high - low)

    if mode == "spike":
        # sudden big jump far beyond normal
        direction = random.choice([-1, 1])
        return center + direction * random.uniform(1.5 * span, 3.0 * span)
    elif mode == "drift":
        # slowly drifting away from normal as time passes
        direction = random.choice([-1, 1])
        drift = 0.1 * span + 0.03 * span * local_tick
        return center + direction * drift
    elif mode == "stuck":
        # almost constant near one edge
        edge = low if random.random() < 0.5 else high
        return edge + random.uniform(-0.05 * span, 0.05 * span)
    elif mode == "noisy":
        # very noisy compared to normal
        return center + random.gauss(0, 1.5 * span)
    else:
        return normal_value(sensor)


def run_simulator(num_devices: int = 8, interval: float = 2.0):
    """
    Main loop:
    - Devices: dev1..devN
    - Each tick: each device emits one value per sensor into telemetry.db
    - Each device has a small chance to enter anomaly mode for a few ticks.
    """
    init_db()
    device_ids = [f"dev{i+1}" for i in range(num_devices)]
    print(f"[Simulator] Using DB: {DB_PATH}")
    print(f"[Simulator] Devices: {device_ids}, interval={interval}s")
    print("[Simulator] Press Ctrl+C to stop.")

    # per-device anomaly state: {dev: None or {mode, remaining, start_tick}}
    state = {d: None for d in device_ids}
    tick = 0

    try:
        while True:
            for dev in device_ids:
                # randomly start an anomaly if currently normal
                if state[dev] is None:
                    # e.g., 4% chance per tick for this device
                    if random.random() < 0.04:
                        mode = random.choice(ANOMALY_MODES)
                        duration = random.randint(3, 10)  # ticks
                        state[dev] = {
                            "mode": mode,
                            "remaining": duration,
                            "start_tick": tick,
                        }
                        print(f"[ANOMALY START] {dev} mode={mode} duration={duration} ticks")

                cur_state = state[dev]
                cur_mode = cur_state["mode"] if cur_state else None
                local_tick = tick - (cur_state["start_tick"] if cur_state else 0)

                for sensor in SENSORS.keys():
                    if cur_mode:
                        value = anomalous_value(sensor, cur_mode, local_tick)
                    else:
                        value = normal_value(sensor)

                    insert_reading(dev, sensor, value)

                # update anomaly countdown
                if cur_state:
                    cur_state["remaining"] -= 1
                    if cur_state["remaining"] <= 0:
                        print(f"[ANOMALY END] {dev} mode={cur_state['mode']}")
                        state[dev] = None

            tick += 1
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[Simulator] Stopped by user.")
    except Exception as e:
        print("[Simulator] Error:", e)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-devices", type=int, default=8)
    parser.add_argument("--interval", type=float, default=2.0)
    args = parser.parse_args()
    run_simulator(num_devices=args.num_devices, interval=args.interval)
