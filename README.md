# 🛡️ Real-Time Cyber Threat & Anomaly Detection (BDA)

A complete Big Data Analytics pipeline for real-time network intrusion detection using machine learning. 

## Architecture
1. **Data Source:** Live packet capture via Scapy + Npcap.
2. **Machine Learning:** 
   - **Isolation Forest:** Unsupervised anomaly detection (Zero-Days).
   - **Random Forest:** Supervised classification (DDoS, PortScan, etc.).
   - **Heuristic Overrides:** Rule-based thresholds for high-volume attacks.
3. **Dashboard:** Streamlit + Plotly for real-time SOC visualization.

## How to Run Locally
1. Clone the repo and install dependencies:
   `pip install -r requirements.txt`
2. Download the CIC-IDS2017 CSV dataset and place it in the `data/` folder.
3. Train the models:
   `python src/train.py`
4. Start the dashboard:
   `python -m streamlit run src/dashboard.py`
5. Start the packet sniffer (Requires Admin privileges and Npcap):
   `python src/detect.py "Wi-Fi"`

## Live Demo
*Note: Cloud deployments cannot capture raw network packets due to provider restrictions. The Streamlit Cloud link showcases the UI, while the packet capture and ML inference are designed to run locally.*

[Live Dashboard UI Link](YOUR_STREAMLIT_CLOUD_URL_HERE)