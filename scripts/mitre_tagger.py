import requests
import os
import time
import schedule
from datetime import datetime
from dotenv import load_dotenv

load_dotenv('/data/tpot-intel/.env')
ES_URL = "http://localhost:64298"

# ─── MITRE ATT&CK Mapping Dictionary ───
# Maps honeypot event patterns to MITRE techniques
MITRE_MAPPINGS = {
    # Cowrie SSH patterns
    "cowrie": {
        "login attempt": {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "subtechnique_id": "T1110.001",
            "subtechnique_name": "Password Guessing"
        },
        "login failed": {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "subtechnique_id": "T1110.001",
            "subtechnique_name": "Password Guessing"
        },
        "login succeeded": {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "tactic": "Initial Access",
            "subtechnique_id": "T1078.004",
            "subtechnique_name": "Cloud Accounts"
        },
        "command": {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "subtechnique_id": "T1059.004",
            "subtechnique_name": "Unix Shell"
        },
        "file download": {
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "subtechnique_id": None,
            "subtechnique_name": None
        },
        "wget": {
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "subtechnique_id": None,
            "subtechnique_name": None
        },
        "curl": {
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "subtechnique_id": None,
            "subtechnique_name": None
        },
        "chmod": {
            "technique_id": "T1222",
            "technique_name": "File and Directory Permissions Modification",
            "tactic": "Defense Evasion",
            "subtechnique_id": "T1222.002",
            "subtechnique_name": "Linux and Mac File and Directory Permissions Modification"
        },
        "crontab": {
            "technique_id": "T1053",
            "technique_name": "Scheduled Task/Job",
            "tactic": "Persistence",
            "subtechnique_id": "T1053.003",
            "subtechnique_name": "Cron"
        },
        "useradd": {
            "technique_id": "T1136",
            "technique_name": "Create Account",
            "tactic": "Persistence",
            "subtechnique_id": "T1136.001",
            "subtechnique_name": "Local Account"
        },
        "passwd": {
            "technique_id": "T1098",
            "technique_name": "Account Manipulation",
            "tactic": "Persistence",
            "subtechnique_id": None,
            "subtechnique_name": None
        },
        "uname": {
            "technique_id": "T1082",
            "technique_name": "System Information Discovery",
            "tactic": "Discovery",
            "subtechnique_id": None,
            "subtechnique_name": None
        },
        "whoami": {
            "technique_id": "T1033",
            "technique_name": "System Owner/User Discovery",
            "tactic": "Discovery",
            "subtechnique_id": None,
            "subtechnique_name": None
        },
        "ifconfig": {
            "technique_id": "T1016",
            "technique_name": "System Network Configuration Discovery",
            "tactic": "Discovery",
            "subtechnique_id": None,
            "subtechnique_name": None
        },
        "cat /etc/passwd": {
            "technique_id": "T1003",
            "technique_name": "OS Credential Dumping",
            "tactic": "Credential Access",
            "subtechnique_id": "T1003.008",
            "subtechnique_name": "/etc/passwd and /etc/shadow"
        },
        "cryptominer": {
            "technique_id": "T1496",
            "technique_name": "Resource Hijacking",
            "tactic": "Impact",
            "subtechnique_id": None,
            "subtechnique_name": None
        },
        "xmrig": {
            "technique_id": "T1496",
            "technique_name": "Resource Hijacking",
            "tactic": "Impact",
            "subtechnique_id": None,
            "subtechnique_name": None
        },
        "minerd": {
            "technique_id": "T1496",
            "technique_name": "Resource Hijacking",
            "tactic": "Impact",
            "subtechnique_id": None,
            "subtechnique_name": None
        }
    },
    # Dionaea malware patterns
    "dionaea": {
        "default": {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "subtechnique_id": None,
            "subtechnique_name": None
        }
    },
    # Redis honeypot patterns
    "redishoneypot": {
        "default": {
            "technique_id": "T1505",
            "technique_name": "Server Software Component",
            "tactic": "Persistence",
            "subtechnique_id": None,
            "subtechnique_name": None
        }
    },
    # HTTP/Web patterns
    "tanner": {
        "default": {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "subtechnique_id": None,
            "subtechnique_name": None
        },
        "sql": {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "subtechnique_id": None,
            "subtechnique_name": None
        },
        "xss": {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "subtechnique_id": "T1059.007",
            "subtechnique_name": "JavaScript"
        }
    },
    # Network scanning
    "heralding": {
        "default": {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "subtechnique_id": "T1110.003",
            "subtechnique_name": "Password Spraying"
        }
    },
    # Port scanning / reconnaissance
    "honeytrap": {
        "default": {
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "tactic": "Discovery",
            "subtechnique_id": None,
            "subtechnique_name": None
        }
    },
    # Industrial control systems
    "conpot": {
        "default": {
            "technique_id": "T0840",
            "technique_name": "Network Connection Enumeration",
            "tactic": "Discovery",
            "subtechnique_id": None,
            "subtechnique_name": None
        }
    },
    # Elasticsearch honeypot
    "elasticpot": {
        "default": {
            "technique_id": "T1213",
            "technique_name": "Data from Information Repositories",
            "tactic": "Collection",
            "subtechnique_id": None,
            "subtechnique_name": None
        }
    }
}

def get_mitre_tag(honeypot_type, event_data):
    """Match event to MITRE ATT&CK technique"""
    honeypot_lower = honeypot_type.lower() if honeypot_type else ""
    event_str = json_to_str(event_data).lower()

    # Find honeypot mapping
    mapping = None
    for key in MITRE_MAPPINGS:
        if key in honeypot_lower:
            mapping = MITRE_MAPPINGS[key]
            break

    if not mapping:
        # Default for unknown honeypots
        return {
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "tactic": "Discovery",
            "subtechnique_id": None,
            "subtechnique_name": None
        }

    # Try to match specific patterns within honeypot
    for pattern, technique in mapping.items():
        if pattern != "default" and pattern in event_str:
            return technique

    # Fall back to default for this honeypot
    return mapping.get("default", {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "subtechnique_id": None,
        "subtechnique_name": None
    })

def json_to_str(data):
    """Convert dict/any to searchable string"""
    if isinstance(data, dict):
        return ' '.join([str(v) for v in data.values()])
    return str(data)

def get_untagged_events():
    """Get recent events that haven't been MITRE tagged yet"""
    query = {
        "size": 200,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": "now-1h"}}},
                    {"exists": {"field": "src_ip"}}
                ],
                "must_not": [
                    {"exists": {"field": "mitre.technique_id"}}
                ]
            }
        }
    }
    try:
        response = requests.post(
            f"{ES_URL}/logstash-*/_search",
            json=query,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()['hits']['hits']
    except Exception as e:
        print(f"ES error: {e}")
    return []

def store_tagged_event(event):
    """Store MITRE-tagged event in dedicated index"""
    try:
        response = requests.post(
            f"{ES_URL}/tpot-mitre-events/_doc",
            json=event,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        return response.status_code == 201
    except Exception as e:
        print(f"Store error: {e}")
        return False

def run_tagger():
    """Main tagging job"""
    print(f"\n{'='*55}")
    print(f"  MITRE ATT&CK Tagger | {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*55}")

    events = get_untagged_events()
    print(f"  Events to tag: {len(events)}")

    tagged = 0
    tactic_counts = {}

    for hit in events:
        source = hit['_source']
        honeypot_type = source.get('type', 'unknown')
        mitre = get_mitre_tag(honeypot_type, source)

        # Build tagged document
        tagged_event = {
            '@timestamp': source.get('@timestamp'),
            'src_ip': source.get('src_ip'),
            'honeypot': honeypot_type,
            'original_index': hit['_index'],
            'mitre': {
                'technique_id': mitre['technique_id'],
                'technique_name': mitre['technique_name'],
                'tactic': mitre['tactic'],
                'subtechnique_id': mitre.get('subtechnique_id'),
                'subtechnique_name': mitre.get('subtechnique_name'),
                'framework': 'MITRE ATT&CK',
                'version': 'v14'
            },
            'tagged_at': datetime.utcnow().isoformat()
        }

        if store_tagged_event(tagged_event):
            tagged += 1
            tactic = mitre['tactic']
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    print(f"  ✓ Tagged {tagged} events")
    if tactic_counts:
        print(f"\n  MITRE Tactic Distribution:")
        for tactic, count in sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"    {tactic}: {count}")

# ─── Start ───
print("""
╔══════════════════════════════════════════╗
║   T-Pot MITRE ATT&CK Auto-Tagger         ║
║   by Loki                      ║
╚══════════════════════════════════════════╝
""")

run_tagger()
schedule.every(30).minutes.do(run_tagger)

while True:
    schedule.run_pending()
    time.sleep(60)
