# src/behavioral/build_features_iforest.py
"""
Build feature vectors from telemetry.db for Isolation Forest training.

Each feature window is (device_id, features...)
Window groups recent N readings per sensor
and calculates:
    mean, std, min, max, last_value

Outputs a CSV: behavioral_features.csv
"""

import sqlite3
import pandas as pd
import numpy as np
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(ROOT, "telemetry.db")
OUT_CSV = os.path.join(ROOT, "behavioral_features.csv")

SENSORS = ["temperature", "humidity", "soil_moisture", "light", "ph", "co2"]
WINDOW = 10  # readings per aggregation window


def build_features():
    con = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM telemetry ORDER BY timestamp ASC", con)
    con.close()

    if df.empty:
        print("No telemetry data found!")
        return

    features = []
    for device in df["device_id"].unique():
        dev_df = df[df["device_id"] == device]
        for i in range(WINDOW, len(dev_df)):
            window = dev_df.iloc[i-WINDOW:i]
            row = {"device_id": device}
            for s in SENSORS:
                values = window[window.sensor_type == s]["value"].values
                if len(values) == 0:
                    row[f"{s}_mean"] = np.nan
                    row[f"{s}_std"] = np.nan
                    row[f"{s}_min"] = np.nan
                    row[f"{s}_max"] = np.nan
                    row[f"{s}_last"] = np.nan
                else:
                    row[f"{s}_mean"] = np.mean(values)
                    row[f"{s}_std"] = np.std(values)
                    row[f"{s}_min"] = np.min(values)
                    row[f"{s}_max"] = np.max(values)
                    row[f"{s}_last"] = values[-1]
            row["timestamp"] = window["timestamp"].values[-1]
            features.append(row)

    feat_df = pd.DataFrame(features).dropna()
    feat_df.to_csv(OUT_CSV, index=False)
    print(f"[OK] Saved features: {OUT_CSV}, rows={len(feat_df)}")


if __name__ == "__main__":
    build_features()
