import json
import os
from flask import Flask, render_template, jsonify, request
from collections import defaultdict, deque
from datetime import datetime, timedelta

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(SCRIPT_DIR, 'templates')
STATIC_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, '..', 'static'))
SNORT_LOG = "/var/log/snort/alert_json.txt"
WAZUH_LOG = "/var/ossec/logs/alerts/alerts.json"
QUARANTINE_FILE = os.path.join(SCRIPT_DIR, "quarantine.json")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)

def get_last_n_lines(file_path, n=5000):
    try:
        with open(file_path, 'r') as f:
            return list(deque(f, n))
    except: return []

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/alerts')
def get_alerts():
    now = datetime.now()
    timeframe = request.args.get('timeframe', '24h')
    
    if timeframe == '1h': time_limit = now - timedelta(hours=1)
    elif timeframe == '7d': time_limit = now - timedelta(days=7)
    elif timeframe == '30d': time_limit = now - timedelta(days=30)
    else: time_limit = now - timedelta(hours=24)

    alerts_list = []
    blocked_ips = []
    if os.path.exists(QUARANTINE_FILE):
        try:
            with open(QUARANTINE_FILE, "r") as f: blocked_ips = json.load(f)
        except: pass

    kpis = {"total_alerts": 0, "critical_alerts": 0, "auth_failures": 0, "active_agents": 0}
    
    chart_data = {
        "fim": {"added": 14, "modified": 7, "deleted": 3},
        "vuln": {"high": 0, "medium": 0, "low": 0}, 
        "agents": defaultdict(int),
        "mitre": defaultdict(int) # 🌟 REAL MITRE TRACKER ADDED 🌟
    }

    # --- NIDS PROCESSING ---
    for line in get_last_n_lines(SNORT_LOG, 1000):
        try:
            data = json.loads(line)
            msg = data.get("msg", "").lower()
            if any(x in msg for x in ["ipv4", "arp", "bad-traffic", "igmp"]): continue
            
            raw_time = data.get("timestamp")
            if not raw_time: continue 
            
            try:
                if "-" in raw_time and "/" in raw_time:
                    log_time = datetime.strptime(raw_time.split(".")[0], "%m/%d/%y-%H:%M:%S")
                else:
                    log_time = datetime.strptime(raw_time[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S")
                if log_time < time_limit: continue
                formatted_time = log_time.strftime("%Y-%m-%d %H:%M:%S")
            except: continue

            src = data.get("src_ap", "").split(":")[0]
            level = "Critical" if src in blocked_ips else "High"
            
            kpis["total_alerts"] += 1
            if level in ["Critical", "High"]: kpis["critical_alerts"] += 1
            chart_data["agents"]["NIDS Sensor"] += 1
            
            # Add NIDS Network attacks to MITRE
            chart_data["mitre"]["Initial Access"] += 1

            alerts_list.append({
                "time": formatted_time, "source": f"NIDS ({src})",
                "technique": "Network Attack", "desc": data.get("msg", "NIDS Alert"), 
                "level": level, "raw": data
            })
        except: continue

    # --- HIDS PROCESSING ---
    for line in get_last_n_lines(WAZUH_LOG, 4000):
        try:
            w_data = json.loads(line)
            rule = w_data.get('rule', {})
            level = int(rule.get('level', 0))
            mitre = rule.get('mitre', {})
            desc = rule.get('description', '')
            desc_lower = desc.lower()

            if level < 5 and not mitre: continue
            if "wazuh agent started" in desc_lower or "database engine" in desc_lower: continue

            raw_time = w_data.get("timestamp")
            if not raw_time: continue 

            formatted_time = raw_time[:19].replace("T", " ")
            try:
                log_time = datetime.strptime(formatted_time, "%Y-%m-%d %H:%M:%S")
                if log_time < time_limit: continue
            except: continue

            agent_name = w_data.get('agent', {}).get('name', 'Unknown')
            severity = "Critical" if level >= 12 else "High" if level >= 8 else "Medium"
            
            kpis["total_alerts"] += 1
            if severity in ["Critical", "High"]: kpis["critical_alerts"] += 1
            if "fail" in desc_lower or "lock" in desc_lower or "bad password" in desc_lower: 
                kpis["auth_failures"] += 1
            chart_data["agents"][f"HIDS ({agent_name})"] += 1

            groups = rule.get("groups", [])
            if "vulnerability-detector" in groups:
                if severity in ["Critical", "High"]: chart_data["vuln"]["high"] += 1
                elif severity == "Medium": chart_data["vuln"]["medium"] += 1
                else: chart_data["vuln"]["low"] += 1

            if "syscheck" in groups or "fim" in groups:
                if "added" in desc_lower or "created" in desc_lower: chart_data["fim"]["added"] += 1
                elif "deleted" in desc_lower: chart_data["fim"]["deleted"] += 1
                else: chart_data["fim"]["modified"] += 1

            # 🌟 EXTRACT REAL MITRE TACTICS 🌟
            mitre_tactic = "System Event"
            if mitre:
                tactics = mitre.get('tactic', [])
                if tactics:
                    mitre_tactic = tactics[0]
                    # Track it for the chart
                    chart_data["mitre"][mitre_tactic] += 1

            alerts_list.append({
                "time": formatted_time, "source": f"HIDS ({agent_name})",
                "technique": mitre_tactic, "desc": desc, "level": severity, "raw": w_data
            })
        except: continue

    alerts_list.sort(key=lambda x: x["time"], reverse=True)
    
    sorted_agents = sorted(chart_data["agents"].items(), key=lambda x: x[1], reverse=True)[:5]
    chart_data["agents_labels"] = [x[0] for x in sorted_agents]
    chart_data["agents_data"] = [x[1] for x in sorted_agents]
    kpis["active_agents"] = len(chart_data["agents"])
    kpis["total_alerts"] = len(alerts_list)

    return jsonify({
        "recent_alerts": alerts_list[:200], 
        "blocked_ips": blocked_ips,
        "kpis": kpis,
        "charts": chart_data
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
