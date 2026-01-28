🌾 SmartFarm Intrusion Detection System (SmartFarm-IDS)

## 🔐 Overview
SmartFarm-IDS is a **hybrid Intrusion Detection System (IDS)** designed for **smart agriculture and IoT-based farming environments**.  
It combines **network-level attack detection (Layer 1)** and **behavioral anomaly detection on sensor data (Layer 2)** to provide comprehensive security.

The system detects **external cyber attacks** such as port scanning and DoS attacks, as well as **internal anomalies** caused by faulty sensors or insider threats.

## 🧠 System Architecture

### 🔹 Layer 1: Network-based IDS
Monitors live network traffic and detects external attacks.

**Detected Attacks:**
- Port Scanning (SYN scan behavior)
- Denial of Service (DoS)
- Blacklisted IP access
- Suspicious ICMP activity

**Technologies Used:**
- Scapy (packet sniffing)
- Rule-based detection
- SQLite database
- Windows Firewall (optional auto-blocking)
- Kali Linux (attack simulation)

### 🔹 Layer 2: Behavioral IDS
Analyzes sensor telemetry data using Machine Learning.

**Detected Anomalies:**
- Sudden spikes in sensor values
- Gradual drift
- Stuck sensors
- Abnormal frequency patterns
- Insider threats

**Machine Learning Model:**
- Isolation Forest (unsupervised anomaly detection)

**Sensors Simulated:**
- Temperature
- Humidity
- Soil Moisture
- Light
- pH
- CO₂

---
## 📂 Project Structure

```text
smartfarm-ids/
├── src/
│   ├── netids/            # Layer 1 Network IDS
│   ├── behavioral/        # Layer 2 Behavioral IDS
│   ├── dashboard/         # Web Dashboard
│   └── run_ids.py         # Auto IDS runner
│
├── telemetry.db           # Sensor data
├── smartfarm_ids.db       # Alerts DB
├── data/                  # PCAP files
├── venv/                  # Virtual environment
└── README.md




## 🛠️ Technologies & Tools

| Category | Tools |
|------|------|
| Programming Language | Python |
| Network Capture | Scapy |
| Machine Learning | Scikit-learn |
| Data Processing | NumPy, Pandas |
| Model Persistence | Joblib |
| Database | SQLite |
| Dashboard | Flask, Flask-SocketIO |
| System Monitoring | Psutil |
| Attacker OS | Kali Linux |
| Host OS | Windows |

---


---

## 🚀 Installation & Setup

### 1️⃣ Create Virtual Environment
```bash
python -m venv venv
2️⃣ Activate Environment
venv\Scripts\Activate
3️⃣ Install Dependencies
pip install scapy flask flask-socketio sqlalchemy pandas scikit-learn joblib psutil
▶️ How to Run the System
🔹 Run Layer 1 (Network IDS)
python src/run_ids.py
Automatically selects active Wi-Fi interface and starts live packet capture.

🔹 Run Sensor Simulator
python src/behavioral/sensor_simulator.py
Generates realistic farm sensor data with random anomalies.

🔹 Train Behavioral Model
python src/behavioral/build_features_iforest.py
python src/behavioral/train_iforest.py
🔹 Run Layer 2 (Behavioral IDS)
python -m behavioral.realtime_behavioral_ids
🔹 Run Dashboard
python -m src.dashboard.app
Open browser:

http://localhost:5000

🧪 Kali Linux Testing
Run kali linux in virtual box

From Kali:

nmap -sS <IDS_IP>
hping3 -S <IDS_IP> -p 80 --flood


Alerts will appear in:

Terminal

Database

Dashboard

📊 Output
Real-time attack alerts

Unified alerts database

Live dashboard visualization







