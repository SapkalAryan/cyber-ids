"""
Train IsolationForest (for live zero-day anomalies) AND 
Random Forest (for classifying known attack types).
Run: python src\train.py
"""
import os
import glob
import sys
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from schema import FEATURES, LABEL_COL, BENIGN

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE, "data")
MODEL_DIR = os.path.join(BASE, "models")
os.makedirs(MODEL_DIR, exist_ok=True)

csv_files = sorted(glob.glob(os.path.join(DATA_DIR, "*.csv")))
if not csv_files:
    raise SystemExit("No CSV in data\\. Download MachineLearningCSV.zip and extract into data\\.")

print(f"Found {len(csv_files)} CSV file(s) in data\\")
frames = []
for p in csv_files:
    print(f"  loading {os.path.basename(p)} ...")
    d = pd.read_csv(p, low_memory=False)
    d.columns = d.columns.str.strip()
    missing = [c for c in FEATURES + [LABEL_COL] if c not in d.columns]
    if missing:
        continue
    frames.append(d[FEATURES + [LABEL_COL]])

df = pd.concat(frames, ignore_index=True)
# Clean up label names (sometimes they have leading spaces)
df[LABEL_COL] = df[LABEL_COL].astype(str).str.strip()

print(f"Total rows: {len(df)}")

# --- 1. Train Isolation Forest (Anomaly Detection) ---
benign = df[df[LABEL_COL].str.upper() == BENIGN]
X_benign = benign[FEATURES].replace([float("inf"), float("-inf")], 0).fillna(0)

scaler = StandardScaler()
X_benign_scaled = scaler.fit_transform(X_benign.values)

iso_model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42, n_jobs=-1)
iso_model.fit(X_benign_scaled)
print("IsolationForest trained.")

# --- 2. Train Random Forest (Attack Classification) ---
# We train on a subset to keep it fast (max 100k rows per class)
sampled_df = df.groupby(LABEL_COL).apply(lambda x: x.sample(min(len(x), 100000))).reset_index(drop=True)
X_all = sampled_df[FEATURES].replace([float("inf"), float("-inf")], 0).fillna(0)
y_all = sampled_df[LABEL_COL]

X_train, X_test, y_train, y_test = train_test_split(X_all, y_all, test_size=0.2, random_state=42)

# Random Forest does not need scaling, it's tree-based
rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf_model.fit(X_train, y_train)

preds = rf_model.predict(X_test)
print(f"RandomForest trained. Validation Accuracy: {accuracy_score(y_test, preds)*100:.2f}%")

out = os.path.join(MODEL_DIR, "ids_models.joblib")
joblib.dump({
    "iso_model": iso_model, 
    "rf_model": rf_model, 
    "scaler": scaler, 
    "features": FEATURES
}, out)
print(f"Saved models -> {out}")