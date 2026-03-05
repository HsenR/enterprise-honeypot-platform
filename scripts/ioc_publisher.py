import requests
import os
import base64
import schedule
import time
from datetime import datetime
from dotenv import load_dotenv

load_dotenv('/data/tpot-intel/.env')
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
ES_URL = "http://localhost:64298"
GITHUB_USERNAME = "HsenR"
REPO_NAME = "enterprise-honeypot-platform"
FILE_PATH = "threat-intel/blocklist.txt"

def get_malicious_ips():
    """Pull HIGH and CRITICAL IPs from last 7 days"""
    query = {
        "size": 1000,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": "now-7d"}}},
                    {"terms": {"threat_level.keyword": ["CRITICAL", "HIGH"]}}
                ]
            }
        },
        "sort": [{"threat_score": {"order": "desc"}}]
    }
    try:
        response = requests.post(
            f"{ES_URL}/tpot-enriched-ips/_search",
            json=query,
            headers={"Content-Type": "application/json"},
            timeout=15
        )
        if response.status_code == 200:
            hits = response.json()['hits']['hits']
            return [h['_source'] for h in hits]
    except Exception as e:
        print(f"ES error: {e}")
    return []

def build_blocklist(ips):
    """Build formatted blocklist file"""
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    lines = []
    lines.append(f"# ╔══════════════════════════════════════════════════════╗")
    lines.append(f"# ║     Enterprise Honeypot Threat Intelligence Feed      ║")
    lines.append(f"# ║     by Loki | T-Pot v24.04.1 | AWS eu-central-1      ║")
    lines.append(f"# ╚══════════════════════════════════════════════════════╝")
    lines.append(f"#")
    lines.append(f"# Updated: {now}")
    lines.append(f"# Total IPs: {len(ips)}")
    lines.append(f"# Criteria: HIGH and CRITICAL threat score from live honeypot")
    lines.append(f"# Sources: VirusTotal + AbuseIPDB correlation")
    lines.append(f"# Format: IP | Threat Level | Score | ISP | Country")
    lines.append(f"#")
    lines.append(f"# Usage:")
    lines.append(f"#   iptables: iptables -A INPUT -s <IP> -j DROP")
    lines.append(f"#   firewall: Add to blocklist/blackhole route")
    lines.append(f"#")
    lines.append("")

    # Group by threat level
    critical = [ip for ip in ips if ip.get('threat_level') == 'CRITICAL']
    high = [ip for ip in ips if ip.get('threat_level') == 'HIGH']

    if critical:
        lines.append("# ── CRITICAL THREATS ─────────────────────────────────")
        for ip in critical:
            abuse = ip.get('abuseipdb', {})
            vt = ip.get('virustotal', {})
            isp = (abuse.get('isp') or 'Unknown')[:30]
            country = vt.get('country', 'Unknown')
            score = ip.get('threat_score', 0)
            lines.append(f"{ip['ip']:<20} # CRITICAL | Score:{score:>3} | {isp} | {country}")

    lines.append("")

    if high:
        lines.append("# ── HIGH THREATS ─────────────────────────────────────")
        for ip in high:
            abuse = ip.get('abuseipdb', {})
            vt = ip.get('virustotal', {})
            isp = (abuse.get('isp') or 'Unknown')[:30]
            country = vt.get('country', 'Unknown')
            score = ip.get('threat_score', 0)
            lines.append(f"{ip['ip']:<20} # HIGH     | Score:{score:>3} | {isp} | {country}")

    return '\n'.join(lines)

def get_file_sha():
    """Get current file SHA for GitHub update"""
    try:
        url = f"https://api.github.com/repos/{GITHUB_USERNAME}/{REPO_NAME}/contents/{FILE_PATH}"
        headers = {
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json().get('sha')
    except:
        pass
    return None

def publish_to_github(content):
    """Push blocklist to GitHub"""
    try:
        url = f"https://api.github.com/repos/{GITHUB_USERNAME}/{REPO_NAME}/contents/{FILE_PATH}"
        headers = {
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        encoded = base64.b64encode(content.encode()).decode()
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

        data = {
            "message": f"Update threat intel blocklist - {now}",
            "content": encoded,
            "branch": "main"
        }

        sha = get_file_sha()
        if sha:
            data["sha"] = sha

        response = requests.put(url, json=data, headers=headers, timeout=15)

        if response.status_code in [200, 201]:
            print(f"  ✓ Blocklist published to GitHub ({len(content.splitlines())} lines)")
            return True
        else:
            print(f"  GitHub error: {response.status_code} - {response.text[:100]}")
    except Exception as e:
        print(f"  Publish error: {e}")
    return False

def run_publisher():
    print(f"\n{'='*55}")
    print(f"  IOC Publisher | {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*55}")

    ips = get_malicious_ips()
    print(f"  Malicious IPs found: {len(ips)}")

    if not ips:
        print("  No IPs to publish yet")
        return

    content = build_blocklist(ips)
    publish_to_github(content)

print("""
╔══════════════════════════════════════════╗
║   T-Pot IOC Blocklist Publisher          ║
║   by Loki                                ║
╚══════════════════════════════════════════╝
""")
print(f"  GitHub: {GITHUB_USERNAME}/{REPO_NAME}")
print(f"  File: {FILE_PATH}")
print(f"  Token: {'✓ Loaded' if GITHUB_TOKEN else '✗ Missing'}")

run_publisher()
schedule.every(1).hours.do(run_publisher)

while True:
    schedule.run_pending()
    time.sleep(60)
