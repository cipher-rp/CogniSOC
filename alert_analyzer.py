import time
import json
import threading
import os
from collections import defaultdict

# --- CONFIGURATION & PATHS ---
SNORT_LOG = "/var/log/snort/alert_json.txt"
WAZUH_LOG = "/var/ossec/logs/alerts/alerts.json"
QUARANTINE_FILE = "quarantine.json"

ip_scores = defaultdict(int)
blocked_entities = set()
hard_blocked_entities = set()

# --- NEON TERMINAL COLORS ---
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
MAGENTA = '\033[95m' 
BOLD = '\033[1m'
RESET = '\033[0m'

POINT_SYSTEM = {
    "ICMP Ping Detected": 1,
    "Port Scan": 10,
    "NMAP TCP Scan": 10,
    "ARP Spoofing": 15
}

def save_quarantine_state():
    with open(QUARANTINE_FILE, 'w') as f:
        json.dump(list(blocked_entities | hard_blocked_entities), f)

def evaluate_risk(score):
    if score >= 200: return f"{MAGENTA}{BOLD}💀 HARD BANNED{RESET}"
    elif score >= 100: return f"{RED}{BOLD}🚨 QUARANTINED{RESET}"
    elif score >= 50: return f"{RED}🔴 CRITICAL{RESET}"
    elif score >= 20: return f"{YELLOW}🟡 SUSPICIOUS{RESET}"
    else: return f"{GREEN}🟢 SAFE{RESET}"

def unblock_target(target):
    if target in hard_blocked_entities: hard_blocked_entities.remove(target)
    if target in blocked_entities: blocked_entities.remove(target)
    ip_scores[target] = 0
    save_quarantine_state()
    print("\n" + f"{GREEN}="*65)
    print(f"{GREEN}{BOLD}🔓 [COGNISOC] HARD BLOCK EXPIRED & REMOVED 🔓{RESET}")
    print(f"{GREEN}Target Entity : {CYAN}{target}{RESET} is now unblocked after 10 minutes.")
    print(f"{BLUE}[SYS] Executing: iptables -D INPUT -s {target} -j DROP{RESET}")
    print(f"{GREEN}="*65 + "\n")

def trigger_hard_block(target):
    if target in hard_blocked_entities or target == "Unknown": return
    hard_blocked_entities.add(target)
    save_quarantine_state()
    print("\n" + f"{MAGENTA}="*65)
    print(f"{MAGENTA}{BOLD}💀  [COGNISOC ESCALATION: 10-MIN HARD BLOCK INITIATED] 💀{RESET}")
    print(f"{YELLOW}Target Entity : {CYAN}{target}{RESET}")
    print(f"{YELLOW}Reason        : {RESET}Threat Score 200+ (Persistent Attacks after Quarantine)")
    print(f"{YELLOW}Action        : {MAGENTA}COMPLETE NETWORK BAN FOR 10 MINUTES...{RESET}")
    time.sleep(1)
    print(f"{BLUE}[SYS] Executing: iptables -I INPUT -s {target} -j DROP{RESET}")
    time.sleep(0.5)
    print(f"{RED}{BOLD}🚫 SUCCESS: {target} IS BANNED. TIMER STARTED!{RESET}")
    print(f"{MAGENTA}="*65 + "\n")
    threading.Timer(600, unblock_target, [target]).start()

def trigger_active_response(target, reason):
    if target in blocked_entities or target in hard_blocked_entities or target == "Unknown": return 
    blocked_entities.add(target)
    save_quarantine_state()
    print("\n" + f"{RED}={RESET}"*65)
    print(f"{RED}{BOLD}🛡️  [COGNISOC ACTIVE RESPONSE: QUARANTINE] 🛡️{RESET}")
    print(f"{YELLOW}Target Entity : {CYAN}{target}{RESET}")
    print(f"{YELLOW}Reason        : {RESET}Threat Score reached 100+ ({reason})")
    print(f"{YELLOW}Action        : {RED}Initiating Network Lockdown...{RESET}")
    time.sleep(1)
    print(f"{BLUE}[SYS] Executing: iptables -A INPUT -s {target} -j DROP{RESET}")
    time.sleep(0.5)
    print(f"{GREEN}{BOLD}✅ SUCCESS: {target} HAS BEEN QUARANTINED!{RESET}")
    print(f"{RED}={RESET}"*65 + "\n")

def tail_file(file_path, callback_func):
    try:
        with open(file_path, 'r') as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                callback_func(line)
    except FileNotFoundError:
        pass

# 🌟 SCORING AND BLOCKING ONLY FOR NIDS 🌟
def process_snort_alert(line):
    try:
        data = json.loads(line)
        src = data.get("src_ap", "Unknown").split(":")[0]
        msg = data.get("msg", "General Activity")

        if src == "" or "IPv4 datagram length" in msg or "arp_spoof" in msg:
            return

        points = POINT_SYSTEM.get(msg, 2)
        # NMAP scans get 10 points automatically
        if "Scan" in msg or "NMAP" in msg: points = 10
        elif "Ping" in msg: points = 2

        ip_scores[src] += points
        status = evaluate_risk(ip_scores[src])
        
        print(f"{CYAN}[NIDS]{RESET} IP: {src:<15} | Score: {ip_scores[src]:<3} | {status:<24} | {msg}")
        
        # Threat Threshold Checks
        if ip_scores[src] >= 200: trigger_hard_block(src)
        elif ip_scores[src] >= 100: trigger_active_response(src, "Repeated Network Anomalies")
    except Exception:
        pass

# 🌟 NO SCORING, JUST MONITORING FOR HIDS 🌟
def process_wazuh_alert(line):
    try:
        data = json.loads(line)
        rule = data.get('rule', {})
        desc = rule.get('description', 'Unknown Alert')
        level = int(rule.get('level', 0))
        
        agent_name = data.get('agent', {}).get('name', 'Unknown')

        # HIDS logs are printed beautifully but without any score logic
        if level <= 4:
            # Noise logs - Dim Gray
            print(f"\033[90m[HIDS] Agent: {agent_name:<15} | Lvl {level:<2} | {desc[:80]}...\033[0m")
        elif level <= 9:
            # Medium/High - Blue and Yellow
            print(f"{BLUE}[HIDS]{RESET} Agent: {agent_name:<15} | {YELLOW}Lvl {level:<2}{RESET} | {desc[:80]}...")
        else:
            # Critical - Bright Red (No auto-block, just loud alert)
            print(f"{RED}{BOLD}[HIDS] Agent: {agent_name:<15} | Lvl {level:<2} | CRITICAL: {desc[:70]}...{RESET}")

    except Exception:
        pass

if __name__ == "__main__":
    os.system('clear')
    print(f"{CYAN}{BOLD}")
    print("======================================================================")
    print(" 🧠 CogniSOC: Level-3 XDR Engine (Network Quarantine & Auto-Ban) ")
    print("======================================================================\n")
    print(f"{YELLOW}[*] Initializing Log Pipelines...{RESET}")
    print(f"{GREEN}[*] Engine Active. Auto-Ban is strictly applied to NIDS (Network) only.{RESET}\n")
    
    snort_thread = threading.Thread(target=tail_file, args=(SNORT_LOG, process_snort_alert))
    wazuh_thread = threading.Thread(target=tail_file, args=(WAZUH_LOG, process_wazuh_alert))
    
    snort_thread.daemon = True
    wazuh_thread.daemon = True
    
    snort_thread.start()
    wazuh_thread.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{RED}{BOLD}[!] CogniSOC Active Response Engine Shutting Down...{RESET}")
