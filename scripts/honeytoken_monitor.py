import os
import time
import requests
import schedule
from datetime import datetime
from dotenv import load_dotenv

load_dotenv('/data/tpot-intel/.env')
BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')

# Files to monitor
HONEYFILES = [
    '/home/ubuntu/.aws/credentials',
    '/var/www/app/config/database.yml',
    '/home/ubuntu/backup/keys/prod-server.pem',
    '/home/ubuntu/.bash_history_backup'
]

# Store last access times
last_access = {}

def send_telegram(message):
    try:
        requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            json={"chat_id": CHAT_ID, "text": message, "parse_mode": "HTML"},
            timeout=10
        )
    except Exception as e:
        print(f"Telegram error: {e}")

def check_honeyfiles():
    """Check if any honeytoken files have been accessed"""
    for filepath in HONEYFILES:
        if not os.path.exists(filepath):
            continue
        try:
            stat = os.stat(filepath)
            atime = stat.st_atime
            filename = os.path.basename(filepath)

            if filepath not in last_access:
                last_access[filepath] = atime
                continue

            if atime > last_access[filepath]:
                access_time = datetime.fromtimestamp(atime).strftime('%Y-%m-%d %H:%M:%S')
                print(f"[ALERT] Honeytoken accessed: {filepath} at {access_time}")

                send_telegram(f"""
🍯 <b>HONEYTOKEN ACCESSED</b>

⚠️ Someone read a sensitive file on your server

📁 <b>File:</b> <code>{filepath}</code>
⏰ <b>Access Time:</b> {access_time}

<b>This means an attacker may have gained shell access to your honeypot.</b>
Check your Cowrie logs immediately for successful logins.
                """.strip())

                last_access[filepath] = atime
        except Exception as e:
            print(f"Error checking {filepath}: {e}")

print("""
╔══════════════════════════════════════════╗
║   T-Pot Honeytoken Monitor               ║
║   by Loki                                ║
╚══════════════════════════════════════════╝
""")
print(f"Monitoring {len(HONEYFILES)} honeytoken files...")

check_honeyfiles()
schedule.every(1).minutes.do(check_honeyfiles)

while True:
    schedule.run_pending()
    time.sleep(30)
