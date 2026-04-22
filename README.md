# 🛡️ CogniSOC - Enterprise XDR & SIEM Engine

![CogniSOC Banner](https://img.shields.io/badge/Status-Active-brightgreen) ![Version](https://img.shields.io/badge/Version-1.0_Enterprise-blue) ![Python](https://img.shields.io/badge/Python-3.x-yellow)

## 🚀 Overview
**CogniSOC** is a custom-built, lightweight Extended Detection and Response (XDR) and SIEM dashboard. It integrates network (NIDS) and host-based (HIDS) telemetry to provide real-time threat monitoring, **MITRE ATT&CK** mapping, and an automated Active Response (Auto-Ban) engine.

Designed for security analysts, this project cuts through log noise to deliver high-fidelity, actionable alerts with a zero-glitch, neon-themed dark mode UI.

## ✨ Key Features
* **Real-Time Telemetry:** Instant parsing and visualization of Snort 3 (NIDS) and Wazuh (HIDS) logs.
* **Smart Noise Filter:** Intelligent backend algorithm to drop low-level events and display only High/Critical threats (Level 5+).
* **Automated Threat Containment (Auto-Ban):** Automatically parses threat scores and permanently bans malicious IPs via `iptables` for aggressive network attacks (Port Scans, ICMP Floods, DoS).
* **Dynamic MITRE ATT&CK Analytics:** Maps endpoint events directly to MITRE tactics (e.g., T1200 Hardware Additions) in a real-time visual doughnut chart.
* **Hardware Monitoring:** Custom XML rules injected into Wazuh to instantly detect and alert on unauthorized USB device connections on Windows and Linux endpoints.

## 🏗️ System Architecture & Data Flow

The power of CogniSOC lies in its distributed monitoring architecture. The setup ensures that telemetry from every corner of the network is centralized, analyzed, and acted upon.

### 1. The Deployment Model
* **Central Manager (Kali Linux):** Acts as the 'Brain'. It hosts the Wazuh Manager, Snort 3, and the CogniSOC Python Backend.
* **Endpoints (Agents):** Wazuh Agents are deployed on Windows 10 and Linux machines to monitor local system events, FIM, and hardware changes.

### 2. Data Pipeline
1. **Log Collection:** Wazuh Agents collect system logs and send them to the Manager via an encrypted channel (Port 1514).
2. **Real-Time Processing:** The Wazuh Manager processes these logs against custom rules (like our USB detection rule) and writes alerts to `alerts.json`.
3. **Network Sensing:** Simultaneously, Snort 3 monitors the network interface and logs malicious traffic patterns.
4. **Analysis Engine:** The `alert_analyzer.py` script tail-reads these JSON logs, calculates risk scores, and triggers `iptables` for immediate threat containment.
5. **Visualization:** The Flask-based dashboard fetches this processed data to present a real-time SOC view.

### 📊 Logic Flow Diagram

[ Endpoints ] --------> [ Wazuh Manager ] 
(Win/Linux)    (Logs)   (Rule Engine)
                            |
                            v
[ Snort NIDS ] -------> [ alerts.json ] <------- [ alert_analyzer.py ]
(Net Traffic)  (Alerts)     |                      (Auto-Ban Engine)
                            v
                    [ CogniSOC Dashboard ]
                       (Flask / UI)

## 📸 Dashboard Preview
<img width="1280" height="800" alt="Screenshot From 2026-04-21 18-32-16" src="https://github.com/user-attachments/assets/f21b334e-d172-4313-8d97-283f9e807c42" />


## 🛠️ Technology Stack
* **Backend:** Python 3, Flask
* **Frontend:** HTML5, CSS3, Bootstrap 5, Chart.js
* **Security Engines:** Wazuh (HIDS), Snort (NIDS)
* **OS:** Kali Linux (Server) / Windows 10 (Target Agent)

## ⚙️ Installation & Setup

**1. Clone the repository**
```bash
git clone [https://github.com/yourusername/CogniSOC.git](https://github.com/yourusername/CogniSOC.git)
cd CogniSOC
