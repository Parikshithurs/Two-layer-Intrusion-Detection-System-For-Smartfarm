# src/behavioral/realtime_behavioral_ids.py
"""
Real-time Behavioral IDS (Layer 2)

- Reads recent sensor data from telemetry.db
- Builds feature windows per device
- Uses trained Isolation Forest to detect anomalies
- Inserts alerts into smartfarm_ids.db via netids.models.Alert
"""

import os
import time
import sqlite3
from datetime import datetime

import numpy as np
import pandas as pd
import pickle

# import Alert + SessionLocal from Layer-1 models
from src.netids.models import SessionLocal, Alert, init_db

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TEL_DB = os.path.join(ROOT, "telemetry.db")
FEATURE_CSV = os.path.join(ROOT, "behavioral_features.csv")
MODEL_PATH = os.path.join(ROOT, "behavioral_iforest.pkl")

SENSORS = ["temperature", "humidity", "soil_moisture", "light", "ph", "co2"]
WINDOW = 10          # number of readings per window
POLL_SEC = 3         # how often to check telemetry
ALERT_COOLDOWN = 30  # seconds between alerts per device


def load_feature_columns():
    """Read feature column order from the training CSV so we match model input exactly."""
    if not os.path.exists(FEATURE_CSV):
        raise SystemExit(f"Feature CSV not found: {FEATURE_CSV}. Run build_features_iforest.py first.")
    tmp = pd.read_csv(FEATURE_CSV, nrows=1)
    cols = [c for c in tmp.columns if c not in ("device_id", "timestamp")]
    return cols


def build_latest_features():
    """
    Build one feature row per device from the latest WINDOW readings.
    """
    if not os.path.exists(TEL_DB):
        return pd.DataFrame()

    con = sqlite3.connect(TEL_DB)
    df = pd.read_sql_query("SELECT * FROM telemetry ORDER BY timestamp DESC LIMIT 1000", con)
    con.close()

    if df.empty:
        return pd.DataFrame()

    rows = []
    for dev in df["device_id"].unique():
        dev_df = df[df["device_id"] == dev].sort_values("timestamp").tail(WINDOW)
        if len(dev_df) < WINDOW:
            continue

        row = {"device_id": dev}
        for s in SENSORS:
            vals = dev_df[dev_df["sensor_type"] == s]["value"].values
            if len(vals) == 0:
                # If somehow missing, skip this device
                break
            row[f"{s}_mean"] = float(np.mean(vals))
            row[f"{s}_std"]  = float(np.std(vals))
            row[f"{s}_min"]  = float(np.min(vals))
            row[f"{s}_max"]  = float(np.max(vals))
            row[f"{s}_last"] = float(vals[-1])
        else:
            # only append if we didn't break early
            rows.append(row)

    return pd.DataFrame(rows)


def insert_behavioral_alert(device_id: str):
    """
    Insert a behavioral anomaly alert into the same alerts table used by Layer-1.
    """
    session = SessionLocal()
    try:
        ts = datetime.now().isoformat()
        desc = f"Behavioral anomaly detected for device {device_id} (sensor pattern)"
        alert = Alert(
            timestamp=datetime.fromisoformat(ts),
            src_ip=device_id,
            dst_ip="sensor-bus",
            alert_type="behavioral-anomaly",
            description=desc,
            severity=3,
        )
        session.add(alert)
        session.commit()
        print(f"[ALERT-L2] {device_id} -> behavioral-anomaly")
    except Exception as e:
        print("[ERROR] Failed to insert behavioral alert:", e)
        session.rollback()
    finally:
        session.close()


def main():
    # ensure DB + alerts table exist
    init_db()

    if not os.path.exists(MODEL_PATH):
        raise SystemExit(f"Model not found: {MODEL_PATH}. Run train_iforest.py first.")

    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)

    feature_cols = load_feature_columns()
    print("[Behavioral-IDS] Started. Using model:", MODEL_PATH)
    print("[Behavioral-IDS] Poll interval:", POLL_SEC, "sec")

    # keep track of last alert time for each device to avoid flooding
    last_alert_time = {}

    try:
        while True:
            feat_df = build_latest_features()
            if not feat_df.empty:
                try:
                    X = feat_df[feature_cols]
                    preds = model.predict(X)  # -1 = anomaly
                    for i, dev in enumerate(feat_df["device_id"].values):
                        if preds[i] == -1:
                            now = time.time()
                            if dev not in last_alert_time or (now - last_alert_time[dev]) > ALERT_COOLDOWN:
                                insert_behavioral_alert(dev)
                                last_alert_time[dev] = now
                except Exception as e:
                    print("[ERROR] Prediction step failed:", e)

            time.sleep(POLL_SEC)
    except KeyboardInterrupt:
        print("\n[Behavioral-IDS] Stopped by user.")


if __name__ == "__main__":
    main()
