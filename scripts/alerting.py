import requests
import os
import time
import schedule
from datetime import datetime
from dotenv import load_dotenv

# ─── Load Config ───
load_dotenv('/data/tpot-intel/.env')
BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
ES_URL = "http://localhost:64298"

# ─── Track already alerted IPs ───
alerted_ips = set()

def send_telegram(message):
    """Send message to Telegram"""
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }
        response = requests.post(url, json=payload, timeout=10)
        return response.status_code == 200
    except Exception as e:
        print(f"Telegram error: {e}")
        return False

def get_critical_attackers():
    """Pull CRITICAL and HIGH threat attackers from enriched index"""
    try:
        query = {
            "size": 50,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": "now-1h"}}},
                        {"terms": {"threat_level.keyword": ["CRITICAL", "HIGH"]}}
                    ]
                }
            },
            "sort": [{"threat_score": {"order": "desc"}}]
        }
        response = requests.post(
            f"{ES_URL}/tpot-enriched-ips/_search",
            json=query,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        if response.status_code == 200:
            hits = response.json()['hits']['hits']
            return [h['_source'] for h in hits]
    except Exception as e:
        print(f"ES error: {e}")
    return []

def get_hourly_summary():
    """Get attack summary for last hour"""
    try:
        query = {
            "size": 0,
            "query": {
                "range": {"@timestamp": {"gte": "now-1h"}}
            },
            "aggs": {
                "total_attacks": {"value_count": {"field": "src_ip.keyword"}},
                "unique_ips": {"cardinality": {"field": "src_ip.keyword"}},
                "top_honeypots": {
                    "terms": {"field": "type.keyword", "size": 3}
                },
                "top_countries": {
                    "terms": {"field": "geoip.country_name.keyword", "size": 3}
                }
            }
        }
        response = requests.post(
            f"{ES_URL}/logstash-*/_search",
            json=query,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"ES summary error: {e}")
    return None

def check_and_alert():
    """Check for critical attackers and send alerts"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Checking for critical attackers...")
    
    attackers = get_critical_attackers()
    new_alerts = [a for a in attackers if a.get('ip') not in alerted_ips]
    
    for attacker in new_alerts:
        ip = attacker.get('ip', 'Unknown')
        score = attacker.get('threat_score', 0)
        level = attacker.get('threat_level', 'Unknown')
        hits = attacker.get('hit_count', 0)
        
        vt = attacker.get('virustotal', {})
        abuse = attacker.get('abuseipdb', {})
        
        # Build alert message
        level_icon = '🔴' if level == 'CRITICAL' else '🟠'
        
        message = f"""
{level_icon} <b>THREAT DETECTED — {level}</b>

🌐 <b>IP:</b> <code>{ip}</code>
📊 <b>Threat Score:</b> {score}/100
💥 <b>Hits on Honeypot:</b> {hits}

🦠 <b>VirusTotal:</b> {vt.get('malicious', 0)} engines flagged
🏢 <b>Owner:</b> {vt.get('owner', 'Unknown')}
🌍 <b>Country:</b> {vt.get('country', 'Unknown')}

⚠️ <b>Abuse Score:</b> {abuse.get('abuse_score', 0)}%
📋 <b>Total Reports:</b> {abuse.get('total_reports', 0)}
🔌 <b>ISP:</b> {abuse.get('isp', 'Unknown')}
{'🧅 <b>TOR EXIT NODE</b>' if abuse.get('is_tor') else ''}

⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC
        """.strip()
        
        if send_telegram(message):
            print(f"  ✓ Alert sent for {ip} (Score: {score})")
            alerted_ips.add(ip)
        
        time.sleep(0.5)

def send_hourly_summary():
    """Send hourly attack summary to Telegram"""
    data = get_hourly_summary()
    if not data:
        return
    
    aggs = data.get('aggregations', {})
    total = aggs.get('total_attacks', {}).get('value', 0)
    unique = aggs.get('unique_ips', {}).get('value', 0)
    
    honeypots = aggs.get('top_honeypots', {}).get('buckets', [])
    honeypot_str = '\n'.join([f"  • {h['key']}: {h['doc_count']}" for h in honeypots]) or '  • None'
    
    countries = aggs.get('top_countries', {}).get('buckets', [])
    country_str = '\n'.join([f"  • {c['key']}: {c['doc_count']}" for c in countries]) or '  • None'
    
    message = f"""
📊 <b>HOURLY THREAT SUMMARY</b>
⏰ {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC

💥 <b>Total Attacks:</b> {total}
🌐 <b>Unique Attackers:</b> {unique}

🍯 <b>Top Honeypots Hit:</b>
{honeypot_str}

🌍 <b>Top Attacking Countries:</b>
{country_str}

🔗 Dashboard: https://51.102.227.255:64297
    """.strip()
    
    if send_telegram(message):
        print(f"  ✓ Hourly summary sent")

# ─── Start ───
print("""
╔══════════════════════════════════════════╗
║   T-Pot Telegram Alerting System         ║
║   by Loki                      ║
╚══════════════════════════════════════════╝
""")
print(f"  Bot Token : {'✓ Loaded' if BOT_TOKEN else '✗ Missing'}")
print(f"  Chat ID   : {'✓ Loaded' if CHAT_ID else '✗ Missing'}")

# Send startup message
send_telegram("""
🚀 <b>T-Pot Alerting System Online</b>

Your enterprise honeypot is active and monitoring.
You will receive alerts for HIGH and CRITICAL threats.
Hourly summaries will be sent every hour.

🍯 T-Pot v24.04.1 | AWS eu-central-1
""".strip())

# Run immediately then schedule
check_and_alert()
send_hourly_summary()

schedule.every(15).minutes.do(check_and_alert)
schedule.every(1).hours.do(send_hourly_summary)

while True:
    schedule.run_pending()
    time.sleep(60)
