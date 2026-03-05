import requests
import json
import os
import schedule
import time
from datetime import datetime
from dotenv import load_dotenv

# ─── Load API Keys ───
load_dotenv('/data/tpot-intel/.env')
VT_KEY = os.getenv('VIRUSTOTAL_API_KEY')
ABUSE_KEY = os.getenv('ABUSEIPDB_API_KEY')

# ─── Config ───
ES_URL = "http://localhost:64298"
ES_INDEX = "logstash-*"
ENRICHED_INDEX = "tpot-enriched-ips"

# ─── Track enriched IPs to avoid duplicate API calls ───
enriched_ips = set()

def es_search(query):
    """Query Elasticsearch directly via HTTP"""
    try:
        response = requests.post(
            f"{ES_URL}/{ES_INDEX}/_search",
            json=query,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        return response.json()
    except Exception as e:
        print(f"ES search error: {e}")
        return None

def es_index(index, doc):
    """Store document in Elasticsearch"""
    try:
        response = requests.post(
            f"{ES_URL}/{index}/_doc",
            json=doc,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        return response.status_code == 201
    except Exception as e:
        print(f"ES index error: {e}")
        return False

def check_virustotal(ip):
    """Query VirusTotal for IP reputation"""
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_KEY}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            attrs = data['data']['attributes']
            stats = attrs['last_analysis_stats']
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'country': attrs.get('country', 'Unknown'),
                'owner': attrs.get('as_owner', 'Unknown'),
                'asn': attrs.get('asn', 'Unknown'),
            }
        elif response.status_code == 404:
            return {'malicious': 0, 'suspicious': 0, 'harmless': 0,
                   'country': 'Unknown', 'owner': 'Unknown', 'asn': 'Unknown'}
    except Exception as e:
        print(f"  VT error: {e}")
    return None

def check_abuseipdb(ip):
    """Query AbuseIPDB for IP abuse score"""
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSE_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()['data']
            return {
                'abuse_score': data.get('abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'last_reported': data.get('lastReportedAt', 'Never'),
                'isp': data.get('isp', 'Unknown'),
                'usage_type': data.get('usageType', 'Unknown'),
                'domain': data.get('domain', 'Unknown'),
                'is_tor': data.get('isTor', False),
            }
    except Exception as e:
        print(f"  AbuseIPDB error: {e}")
    return None

def calculate_threat_score(vt_data, abuse_data):
    """Calculate overall threat score 0-100"""
    score = 0
    if vt_data:
        score += min(vt_data['malicious'] * 5, 50)
        score += min(vt_data['suspicious'] * 2, 10)
    if abuse_data:
        score += abuse_data['abuse_score'] * 0.4
        if abuse_data['is_tor']:
            score += 10
    return min(int(score), 100)

def get_threat_level(score):
    if score >= 75: return 'CRITICAL'
    if score >= 50: return 'HIGH'
    if score >= 25: return 'MEDIUM'
    return 'LOW'

def get_recent_attacker_ips():
    """Pull unique attacker IPs from last 24h"""
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                    {"exists": {"field": "src_ip"}}
                ],
                "must_not": [
                    {"term": {"src_ip.keyword": "185.82.99.123"}}
                ]
            }
        },
        "aggs": {
            "unique_ips": {
                "terms": {
                    "field": "src_ip.keyword",
                    "size": 200
                }
            }
        }
    }
    result = es_search(query)
    if result and 'aggregations' in result:
        buckets = result['aggregations']['unique_ips']['buckets']
        return [(b['key'], b['doc_count']) for b in buckets]
    return []

def enrich_ip(ip, hit_count):
    """Full enrichment pipeline for a single IP"""
    if ip in enriched_ips:
        return
    # Skip private/reserved IPs
    if any(ip.startswith(p) for p in ['10.', '172.', '192.168.', '127.']):
        return

    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Enriching {ip} ({hit_count} hits)...")

    vt_data = check_virustotal(ip)
    time.sleep(0.5)
    abuse_data = check_abuseipdb(ip)

    threat_score = calculate_threat_score(vt_data, abuse_data)
    threat_level = get_threat_level(threat_score)

    # Build enrichment document
    doc = {
        '@timestamp': datetime.utcnow().isoformat(),
        'ip': ip,
        'hit_count': hit_count,
        'threat_score': threat_score,
        'threat_level': threat_level,
        'virustotal': vt_data or {},
        'abuseipdb': abuse_data or {},
        'enriched_at': datetime.utcnow().isoformat()
    }

    # Store in Elasticsearch
    if es_index(ENRICHED_INDEX, doc):
        # Print summary
        level_colors = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
        icon = level_colors.get(threat_level, '⚪')
        print(f"  {icon} {threat_level} | Score: {threat_score}/100 | Hits: {hit_count}")
        if vt_data and vt_data['malicious'] > 0:
            print(f"  🦠 VT: {vt_data['malicious']} engines flagged | Owner: {vt_data['owner']}")
        if abuse_data and abuse_data['abuse_score'] > 0:
            print(f"  ⚠️  Abuse: {abuse_data['abuse_score']}% confidence | {abuse_data['total_reports']} reports | ISP: {abuse_data['isp']}")
        if abuse_data and abuse_data['is_tor']:
            print(f"  🧅 TOR EXIT NODE DETECTED")
    
    enriched_ips.add(ip)
    time.sleep(1)  # Rate limiting

def run_enrichment():
    """Main enrichment job"""
    print(f"\n{'='*55}")
    print(f"  T-Pot Enrichment Pipeline | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}")

    ip_list = get_recent_attacker_ips()
    new_ips = [(ip, count) for ip, count in ip_list if ip not in enriched_ips]

    print(f"  Total unique attackers (24h): {len(ip_list)}")
    print(f"  New IPs to enrich: {len(new_ips)}")

    for ip, count in new_ips:
        enrich_ip(ip, count)

    print(f"\n  ✓ Done. Total enriched: {len(enriched_ips)} IPs")

# ─── Start ───
print("""
╔══════════════════════════════════════════╗
║   T-Pot Attacker Enrichment Pipeline     ║
║   by Loki                      ║
╚══════════════════════════════════════════╝
""")
print(f"  VirusTotal API : {'✓ Loaded' if VT_KEY else '✗ Missing'}")
print(f"  AbuseIPDB API  : {'✓ Loaded' if ABUSE_KEY else '✗ Missing'}")
print(f"  Elasticsearch  : {ES_URL}")

run_enrichment()
schedule.every(1).hours.do(run_enrichment)

while True:
    schedule.run_pending()
    time.sleep(60)
