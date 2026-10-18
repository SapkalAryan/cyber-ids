# Real-Time Network Threat & Anomaly Detection (BDA Project)

## Overview
This project is a Big Data Analytics (BDA) pipeline designed for real-time network intrusion detection. It uses live packet capture (Scapy), feature extraction, and an unsupervised Machine Learning model (IsolationForest) trained on the CIC-IDS2017 dataset to detect anomalous network behavior and potential cyber threats.

## Architecture
1. **Data Source**: Live network traffic captured via Npcap/Scapy.
2. **Feature Extraction**: Groups packets into 5-tuple flows and extracts 10 key numerical features (duration, bytes, packet sizes, etc.).
3. **Machine Learning**: An IsolationForest model trained strictly on BENIGN traffic from the CIC-IDS2017 dataset. It detects anomalies based on mathematical deviations from normal traffic.
4. **Visualization**: A Streamlit dashboard that reads the `alerts.csv` log in real-time to display metrics and charts.

## Prerequisites
- Windows OS with Npcap installed (WinPcap API-compatible mode).
- Python 3.11+
- CIC-IDS2017 CSVs placed in the `data/` folder.

## Installation
1. Install dependencies:
   `pip install -r requirements.txt`
2. Train the model on the CIC-IDS2017 dataset:
   `python src\train.py`
3. Start the Streamlit dashboard:
   `python -m streamlit run src\dashboard.py`
4. Open an Admin terminal and start the live capture:
   `python src\detect.py "Wi-Fi"`

## Results
The system successfully detects traffic spikes and port scans in real-time, logging them to `alerts.csv` and visualizing them instantly on the dashboard.