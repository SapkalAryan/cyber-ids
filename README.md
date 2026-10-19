# 🛡️ Real-Time Cyber Threat & Anomaly Detection (BDA)

A complete End-to-End Big Data Analytics (BDA) pipeline for real-time network intrusion detection and classification, utilizing a Cloud-Edge architecture. 

## 📊 System Architecture
This project decouples data ingestion (Edge) from data visualization (Cloud), mimicking enterprise SOC (Security Operations Center) architecture:
1. **Data Ingestion (Edge):** Live packet capture using `Scapy` on the local network interface.
2. **Feature Extraction:** Real-time aggregation of raw packets into 5-tuple network flows (calculating duration, packet rates, etc.).
3. **Machine Learning Inference:** 
   - **Isolation Forest:** Unsupervised anomaly detection trained on the CIC-IDS2017 dataset to flag deviations (Zero-Days).
   - **Heuristics & Simulation:** Real-time injection of simulated DDoS and PortScan signatures to validate pipeline performance.
4. **Cloud Database:** `Supabase` (PostgreSQL) handles high-speed concurrent ingestion of threat logs.
5. **Cloud Dashboard:** `Streamlit` provides a live, asynchronous visualization of the data stream.

## 🚀 How to Run Locally (Edge Node)

### Prerequisites
- Python 3.11+
- **Npcap** installed on Windows (WinPcap API-compatible mode) for Scapy packet capture.

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cyber-ids-local.git
   cd cyber-ids-local
Install dependencies:

bash
pip install -r requirements.txt
Ensure the CIC-IDS2017 CSV files are in the data/ folder.

Execution
1. Train the Model (Optional - Model is already pre-trained)

bash
python src/train.py
2. Start the Live Sniffer (Requires Admin Terminal)

bash
python src/detect.py "Wi-Fi"
This will capture live traffic, run ML inference, and push anomalies to the Cloud Database.

3. Inject Attack Simulator (For Testing)
Open a new terminal and run:

bash
python src/detect.py simulate
This injects 10 high-volume DDoS signatures into the pipeline to test the ML detection and cloud syncing.

🌐 Live Cloud Dashboard
The dashboard is deployed on Streamlit Cloud and connects directly to Supabase.
You can view the live demo here: https://cyber-ids-bda.streamlit.app/

(Note: The dashboard will only update when the local Edge node (your PC) is actively sniffing and sending data to the cloud).
