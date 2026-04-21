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
