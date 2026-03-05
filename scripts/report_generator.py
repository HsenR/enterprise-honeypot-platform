import requests
import os
import time
import schedule
from datetime import datetime
from dotenv import load_dotenv
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.units import inch, cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

load_dotenv('/data/tpot-intel/.env')
ES_URL = "http://localhost:64298"
REPORT_DIR = "/data/tpot-intel/reports"
BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')

os.makedirs(REPORT_DIR, exist_ok=True)

# ─── Colors ───
DARK_BG = HexColor('#0d1117')
ACCENT = HexColor('#ff2d55')
ACCENT2 = HexColor('#00d4ff')
CARD_BG = HexColor('#161b22')
TEXT_LIGHT = HexColor('#e6edf3')
TEXT_MUTED = HexColor('#8b949e')
CRITICAL = HexColor('#ff4444')
HIGH = HexColor('#ff8800')
MEDIUM = HexColor('#ffcc00')
LOW = HexColor('#00cc44')
WHITE = HexColor('#ffffff')

def es_query(index, query):
    try:
        response = requests.post(
            f"{ES_URL}/{index}/_search",
            json=query,
            headers={"Content-Type": "application/json"},
            timeout=15
        )
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"ES error: {e}")
    return None

def get_report_data():
    """Pull all data needed for report"""
    data = {}

    # Total attacks last 24h
    result = es_query("logstash-*", {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {
            "total": {"value_count": {"field": "src_ip.keyword"}},
            "unique_ips": {"cardinality": {"field": "src_ip.keyword"}},
            "top_honeypots": {"terms": {"field": "type.keyword", "size": 5}},
            "top_countries": {"terms": {"field": "geoip.country_name.keyword", "size": 5}},
            "top_ports": {"terms": {"field": "dest_port", "size": 5}}
        }
    })
    if result:
        aggs = result.get('aggregations', {})
        data['total_attacks'] = aggs.get('total', {}).get('value', 0)
        data['unique_attackers'] = aggs.get('unique_ips', {}).get('value', 0)
        data['top_honeypots'] = aggs.get('top_honeypots', {}).get('buckets', [])
        data['top_countries'] = aggs.get('top_countries', {}).get('buckets', [])
        data['top_ports'] = aggs.get('top_ports', {}).get('buckets', [])

    # Threat level distribution
    result = es_query("tpot-enriched-ips", {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {
            "threat_levels": {"terms": {"field": "threat_level.keyword"}},
            "avg_score": {"avg": {"field": "threat_score"}},
            "max_score": {"max": {"field": "threat_score"}}
        }
    })
    if result:
        aggs = result.get('aggregations', {})
        data['threat_levels'] = aggs.get('threat_levels', {}).get('buckets', [])
        data['avg_threat_score'] = round(aggs.get('avg_score', {}).get('value', 0) or 0, 1)
        data['max_threat_score'] = round(aggs.get('max_score', {}).get('value', 0) or 0, 1)

    # Top critical attackers
    result = es_query("tpot-enriched-ips", {
        "size": 10,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                    {"terms": {"threat_level.keyword": ["CRITICAL", "HIGH"]}}
                ]
            }
        },
        "sort": [{"threat_score": {"order": "desc"}}]
    })
    if result:
        data['top_threats'] = [h['_source'] for h in result.get('hits', {}).get('hits', [])]

    # MITRE tactic distribution
    result = es_query("tpot-mitre-events", {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {
            "tactics": {"terms": {"field": "mitre.tactic.keyword", "size": 10}},
            "techniques": {"terms": {"field": "mitre.technique_id.keyword", "size": 5}}
        }
    })
    if result:
        aggs = result.get('aggregations', {})
        data['mitre_tactics'] = aggs.get('tactics', {}).get('buckets', [])
        data['mitre_techniques'] = aggs.get('techniques', {}).get('buckets', [])

    return data

def build_pdf(data):
    """Generate professional PDF report"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{REPORT_DIR}/threat_report_{timestamp}.pdf"

    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        rightMargin=1.5*cm,
        leftMargin=1.5*cm,
        topMargin=1.5*cm,
        bottomMargin=1.5*cm
    )

    styles = getSampleStyleSheet()
    elements = []

    # ─── Custom Styles ───
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        textColor=ACCENT,
        spaceAfter=4,
        fontName='Helvetica-Bold',
        alignment=TA_CENTER
    )
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=TEXT_MUTED,
        spaceAfter=2,
        alignment=TA_CENTER
    )
    section_style = ParagraphStyle(
        'Section',
        parent=styles['Heading1'],
        fontSize=13,
        textColor=ACCENT2,
        spaceBefore=14,
        spaceAfter=6,
        fontName='Helvetica-Bold'
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontSize=9,
        textColor=TEXT_LIGHT,
        spaceAfter=4,
        leading=14
    )
    muted_style = ParagraphStyle(
        'Muted',
        parent=styles['Normal'],
        fontSize=8,
        textColor=TEXT_MUTED,
        spaceAfter=2
    )

    # ─── HEADER ───
    elements.append(Spacer(1, 0.3*inch))
    elements.append(Paragraph("🛡 THREAT INTELLIGENCE REPORT", title_style))
    elements.append(Paragraph("Enterprise Honeypot Platform — AWS eu-central-1", subtitle_style))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M UTC')}", subtitle_style))
    elements.append(Paragraph("Author: Hussein Ali Reslan | T-Pot v24.04.1", subtitle_style))
    elements.append(Spacer(1, 0.1*inch))
    elements.append(HRFlowable(width="100%", thickness=2, color=ACCENT))
    elements.append(Spacer(1, 0.15*inch))

    # ─── EXECUTIVE SUMMARY ───
    elements.append(Paragraph("EXECUTIVE SUMMARY", section_style))

    total = data.get('total_attacks', 0)
    unique = data.get('unique_attackers', 0)
    avg_score = data.get('avg_threat_score', 0)
    max_score = data.get('max_threat_score', 0)

    # Count threat levels
    level_counts = {b['key']: b['doc_count'] for b in data.get('threat_levels', [])}
    critical_count = level_counts.get('CRITICAL', 0)
    high_count = level_counts.get('HIGH', 0)

    summary_data = [
        ['METRIC', 'VALUE', 'METRIC', 'VALUE'],
        ['Total Attack Events', f"{total:,}", 'Unique Attackers', f"{unique:,}"],
        ['Critical Threats', str(critical_count), 'High Threats', str(high_count)],
        ['Avg Threat Score', f"{avg_score}/100", 'Max Threat Score', f"{max_score}/100"],
    ]
    summary_table = Table(summary_data, colWidths=[3.5*cm, 3*cm, 3.5*cm, 3*cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), ACCENT),
        ('TEXTCOLOR', (0,0), (-1,0), WHITE),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 9),
        ('BACKGROUND', (0,1), (-1,-1), CARD_BG),
        ('TEXTCOLOR', (0,1), (-1,-1), TEXT_LIGHT),
        ('FONTSIZE', (0,1), (-1,-1), 9),
        ('GRID', (0,0), (-1,-1), 0.5, HexColor('#30363d')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [CARD_BG, HexColor('#1c2128')]),
        ('PADDING', (0,0), (-1,-1), 6),
        ('FONTNAME', (0,1), (0,-1), 'Helvetica-Bold'),
        ('FONTNAME', (2,1), (2,-1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0,1), (0,-1), TEXT_MUTED),
        ('TEXTCOLOR', (2,1), (2,-1), TEXT_MUTED),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.15*inch))

    # ─── TOP THREATS ───
    elements.append(Paragraph("TOP THREAT ACTORS (Last 24 Hours)", section_style))
    top_threats = data.get('top_threats', [])

    if top_threats:
        threat_data = [['IP Address', 'Score', 'Level', 'VT Flags', 'Abuse%', 'ISP']]
        for t in top_threats[:8]:
            level = t.get('threat_level', 'LOW')
            score = t.get('threat_score', 0)
            vt = t.get('virustotal', {})
            abuse = t.get('abuseipdb', {})
            threat_data.append([
                t.get('ip', 'Unknown'),
                str(score),
                level,
                str(vt.get('malicious', 0)),
                f"{abuse.get('abuse_score', 0)}%",
                (abuse.get('isp', 'Unknown') or 'Unknown')[:25]
            ])

        threat_table = Table(threat_data, colWidths=[3.2*cm, 1.5*cm, 2*cm, 1.8*cm, 1.8*cm, 5*cm])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), ACCENT),
            ('TEXTCOLOR', (0,0), (-1,0), WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.5, HexColor('#30363d')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [CARD_BG, HexColor('#1c2128')]),
            ('TEXTCOLOR', (0,1), (-1,-1), TEXT_LIGHT),
            ('PADDING', (0,0), (-1,-1), 5),
            ('FONTNAME', (0,1), (0,-1), 'Helvetica-Bold'),
        ]))
        elements.append(threat_table)
    else:
        elements.append(Paragraph("No high/critical threats detected in last 24 hours.", body_style))

    elements.append(Spacer(1, 0.15*inch))

    # ─── MITRE ATT&CK ───
    elements.append(Paragraph("MITRE ATT&CK FRAMEWORK ANALYSIS", section_style))
    tactics = data.get('mitre_tactics', [])
    techniques = data.get('mitre_techniques', [])

    if tactics:
        mitre_data = [['Tactic', 'Event Count', '% of Total']]
        total_mitre = sum(t['doc_count'] for t in tactics)
        for t in tactics:
            pct = round((t['doc_count'] / total_mitre * 100), 1) if total_mitre > 0 else 0
            mitre_data.append([t['key'], str(t['doc_count']), f"{pct}%"])

        mitre_table = Table(mitre_data, colWidths=[7*cm, 4*cm, 4*cm])
        mitre_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), ACCENT2),
            ('TEXTCOLOR', (0,0), (-1,0), DARK_BG),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, HexColor('#30363d')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [CARD_BG, HexColor('#1c2128')]),
            ('TEXTCOLOR', (0,1), (-1,-1), TEXT_LIGHT),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        elements.append(mitre_table)
    elements.append(Spacer(1, 0.1*inch))

    # Top techniques
    if techniques:
        elements.append(Paragraph("Top MITRE Techniques Observed:", body_style))
        tech_data = [['Technique ID', 'Count']]
        for t in techniques:
            tech_data.append([t['key'], str(t['doc_count'])])
        tech_table = Table(tech_data, colWidths=[7*cm, 4*cm])
        tech_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), HexColor('#21262d')),
            ('TEXTCOLOR', (0,0), (-1,0), ACCENT2),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, HexColor('#30363d')),
            ('TEXTCOLOR', (0,1), (-1,-1), TEXT_LIGHT),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        elements.append(tech_table)

    elements.append(Spacer(1, 0.15*inch))

    # ─── TOP COUNTRIES ───
    elements.append(Paragraph("GEOGRAPHIC ATTACK DISTRIBUTION", section_style))
    countries = data.get('top_countries', [])
    if countries:
        country_data = [['Country', 'Attack Count']]
        for c in countries:
            country_data.append([c.get('key', 'Unknown'), str(c['doc_count'])])
        country_table = Table(country_data, colWidths=[8*cm, 4*cm])
        country_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), ACCENT),
            ('TEXTCOLOR', (0,0), (-1,0), WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, HexColor('#30363d')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [CARD_BG, HexColor('#1c2128')]),
            ('TEXTCOLOR', (0,1), (-1,-1), TEXT_LIGHT),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        elements.append(country_table)

    elements.append(Spacer(1, 0.15*inch))

    # ─── TOP HONEYPOTS ───
    elements.append(Paragraph("HONEYPOT SERVICE TARGETING", section_style))
    honeypots = data.get('top_honeypots', [])
    if honeypots:
        hp_data = [['Honeypot Service', 'Hits']]
        for h in honeypots:
            hp_data.append([h.get('key', 'Unknown'), str(h['doc_count'])])
        hp_table = Table(hp_data, colWidths=[8*cm, 4*cm])
        hp_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), ACCENT2),
            ('TEXTCOLOR', (0,0), (-1,0), DARK_BG),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, HexColor('#30363d')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [CARD_BG, HexColor('#1c2128')]),
            ('TEXTCOLOR', (0,1), (-1,-1), TEXT_LIGHT),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        elements.append(hp_table)

    elements.append(Spacer(1, 0.2*inch))
    elements.append(HRFlowable(width="100%", thickness=1, color=HexColor('#30363d')))
    elements.append(Spacer(1, 0.1*inch))

    # ─── FOOTER ───
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=7,
        textColor=TEXT_MUTED,
        alignment=TA_CENTER
    )
    elements.append(Paragraph(
        f"CONFIDENTIAL — Hussein Ali Reslan Enterprise Honeypot Platform | {datetime.now().strftime('%Y-%m-%d')} | T-Pot v24.04.1 AWS",
        footer_style
    ))

    doc.build(elements)
    print(f"  ✓ Report saved: {filename}")
    return filename

def send_report_telegram(filename):
    """Send PDF report to Telegram"""
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument"
        with open(filename, 'rb') as f:
            response = requests.post(url, data={
                "chat_id": CHAT_ID,
                "caption": f"📊 Daily Threat Intelligence Report\n{datetime.now().strftime('%Y-%m-%d %H:%M UTC')}"
            }, files={"document": f}, timeout=30)
        if response.status_code == 200:
            print("  ✓ Report sent to Telegram")
        else:
            print(f"  Telegram error: {response.text}")
    except Exception as e:
        print(f"  Send error: {e}")

def generate_report():
    print(f"\n{'='*55}")
    print(f"  Generating Threat Report | {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*55}")
    data = get_report_data()
    filename = build_pdf(data)
    send_report_telegram(filename)
    print(f"  ✓ Report complete")

# ─── Start ───
print("""
╔══════════════════════════════════════════╗
║   T-Pot PDF Report Generator             ║
║   by Loki                      ║
╚══════════════════════════════════════════╝
""")

generate_report()
schedule.every(24).hours.do(generate_report)

while True:
    schedule.run_pending()
    time.sleep(60)
