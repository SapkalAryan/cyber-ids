import os
import glob
import sys
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from schema import FEATURES, LABEL_COL, BENIGN

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE, "data")
MODEL_DIR = os.path.join(BASE, "models")
os.makedirs(MODEL_DIR, exist_ok=True)

csv_files = sorted(glob.glob(os.path.join(DATA_DIR, "*.csv")))
print(f"Found {len(csv_files)} CSV files.")

frames = []
for p in csv_files:
    d = pd.read_csv(p, low_memory=False)
    d.columns = d.columns.str.strip()
    # Only keep BENIGN traffic and the 10 features
    d = d[d[LABEL_COL].astype(str).str.upper() == BENIGN]
    if all(col in d.columns for col in FEATURES):
        frames.append(d[FEATURES])

df = pd.concat(frames, ignore_index=True)
print(f"Training Isolation Forest on {len(df)} benign flows...")

# Standardize the 10 features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(df.replace([float("inf"), float("-inf")], 0).fillna(0).values)

# Train Isolation Forest (unsupervised anomaly detection)
iso_model = IsolationForest(n_estimators=150, contamination=0.01, random_state=42, n_jobs=-1)
iso_model.fit(X_scaled)

out = os.path.join(MODEL_DIR, "ids_iso.joblib")
joblib.dump({"iso_model": iso_model, "scaler": scaler, "features": FEATURES}, out)
print(f"Model saved to {out}.")