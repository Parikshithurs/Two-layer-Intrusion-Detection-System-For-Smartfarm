# src/behavioral/train_iforest.py
"""
Train Isolation Forest behavioral model and save it.

Model saved → behavioral_iforest.pkl
"""

import pandas as pd
from sklearn.ensemble import IsolationForest
import pickle
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CSV_PATH = os.path.join(ROOT, "behavioral_features.csv")
MODEL_PATH = os.path.join(ROOT, "behavioral_iforest.pkl")

FEATURES = [c for c in pd.read_csv(CSV_PATH).columns if "_mean" in c or "_std" in c or "_min" in c or "_max" in c or "_last" in c]

def train():
    df = pd.read_csv(CSV_PATH)

    X = df[FEATURES]
    model = IsolationForest(n_estimators=200, contamination=0.04, random_state=42)
    model.fit(X)

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)

    print("[OK] Model trained and saved:", MODEL_PATH)
    print("Feature dimensions:", X.shape)


if __name__ == "__main__":
    train()
