from flask import Flask, render_template, request, jsonify, session, abort
from datetime import datetime, timedelta
import sqlite3
import os
import re
import json
import time
import requests
import subprocess
from threading import Lock

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Konfigurasi API AI
API_URL = "https://api.freetheai.xyz/v1/chat/completions"
API_KEY = "sta_4bc4d021bc423c04b745194a24e382e9cdf4403f37f06154"
MODEL_ID = "glm/glm-4.5"
NUMVERIFY_KEY = "1a9d41ba8ac64284bfb575f12ea38ed6"

DB_PATH = "bin_system.db"
LOG_FILE = "log.json"
ACTIVITY_LOG_FILE = "activity_log.json"

active_users = {}
active_users_lock = Lock()

# ========== DATABASE ==========
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS chat_sessions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_identifier TEXT NOT NULL,
                  title TEXT DEFAULT 'New Chat',
                  created_at TEXT NOT NULL)''')
    try:
        c.execute("ALTER TABLE chat_sessions ADD COLUMN user_identifier TEXT NOT NULL DEFAULT 'legacy_user'")
    except sqlite3.OperationalError:
        pass
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  session_id INTEGER NOT NULL,
                  role TEXT NOT NULL,
                  content TEXT NOT NULL,
                  timestamp TEXT NOT NULL,
                  FOREIGN KEY(session_id) REFERENCES chat_sessions(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS ip_bans
                 (ip TEXT PRIMARY KEY,
                  banned_until TEXT,
                  permanently_banned INTEGER DEFAULT 0)''')
    conn.commit()
    conn.close()

init_db()

# ========== BAN & RATE LIMIT ==========
request_log = {}
def rate_limit(ip, max_requests=20, window=5):
    now = time.time()
    request_log.setdefault(ip, [])
    request_log[ip] = [t for t in request_log[ip] if now - t < window]
    if len(request_log[ip]) >= max_requests:
        return False
    request_log[ip].append(now)
    return True

def is_ip_banned(ip):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT banned_until, permanently_banned FROM ip_bans WHERE ip=?", (ip,))
    row = c.fetchone()
    conn.close()
    if row:
        if row[1] == 1:
            return True, "permanent"
        if row[0]:
            banned_until = datetime.fromisoformat(row[0])
            if datetime.now() < banned_until:
                return True, "temporary"
    return False, None

def ban_ip(ip, duration_hours=24):
    until = (datetime.now() + timedelta(hours=duration_hours)).isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO ip_bans (ip, banned_until, permanently_banned) VALUES (?, ?, 0)", (ip, until))
    conn.commit()
    conn.close()

def permanent_ban_ip(ip):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO ip_bans (ip, banned_until, permanently_banned) VALUES (?, ?, 1)", (ip, None))
    conn.commit()
    conn.close()

ATTACK_PATTERNS = [
    (r"(union.*select|select.*from|insert.*into|drop\s+table|--|#|/\*|\*/)", "SQL Injection"),
    (r"(<script|alert\(|onerror=)", "XSS"),
    (r"(;.*rm\s+-rf|;.*wget|;.*curl|&&)", "Command Injection"),
    (r"(\.\./|\.\.\\|%2e%2e)", "Path Traversal"),
    (r"(\bOR\b.*\b1\b.*=\b1\b)", "SQLi Auth Bypass")
]

def detect_attack(payload):
    for pattern, attack_type in ATTACK_PATTERNS:
        if re.search(pattern, payload, re.IGNORECASE):
            return attack_type
    return None

# ========== IP & LOCATION ==========
def get_location(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,lat,lon,isp,query,regionName", timeout=3)
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

def parse_device(ua):
    ua = ua.lower()
    os = "Unknown"
    if "windows" in ua: os = "Windows"
    elif "mac os" in ua: os = "macOS"
    elif "linux" in ua: os = "Linux"
    elif "android" in ua: os = "Android"
    elif "iphone" in ua: os = "iPhone"
    browser = "Unknown"
    if "chrome" in ua: browser = "Chrome"
    elif "firefox" in ua: browser = "Firefox"
    elif "safari" in ua: browser = "Safari"
    return f"{os} / {browser}"

def get_full_location_string(geo):
    parts = []
    if geo.get("city"): parts.append(geo["city"])
    if geo.get("regionName"): parts.append(geo["regionName"])
    if geo.get("country"): parts.append(geo["country"])
    if geo.get("isp"): parts.append(f"ISP: {geo['isp']}")
    if geo.get("lat") and geo.get("lon"): parts.append(f"{geo['lat']}, {geo['lon']}")
    return ", ".join(parts) if parts else "Lokasi tidak diketahui"

def get_geo_from_session():
    lat = session.get('latitude')
    lon = session.get('longitude')
    if lat is not None and lon is not None:
        return {"lat": lat, "lon": lon, "source": "gps"}
    return None

def enrich_geo_with_gps(geo, gps):
    if gps and 'lat' in gps and 'lon' in gps:
        geo['lat'] = gps['lat']
        geo['lon'] = gps['lon']
        geo['source'] = 'gps'
    return geo

# ========== LOGGING ==========
def log_visit(ip, user_agent, username):
    geo = get_location(ip)
    gps = get_geo_from_session()
    if gps:
        geo = enrich_geo_with_gps(geo, gps)
    entry = {
        "timestamp": datetime.now().isoformat(),
        "ip": ip,
        "username": username,
        "device": parse_device(user_agent),
        "user_agent": user_agent,
        "location": get_full_location_string(geo),
        "geo_raw": geo
    }
    write_json_log(LOG_FILE, entry)

def log_activity(username, ip, user_agent, prompt, ai_response, tool):
    geo = get_location(ip)
    gps = get_geo_from_session()
    if gps:
        geo = enrich_geo_with_gps(geo, gps)
    entry = {
        "timestamp": datetime.now().isoformat(),
        "username": username,
        "ip": ip,
        "device": parse_device(user_agent),
        "location": get_full_location_string(geo),
        "tool": tool,
        "prompt": prompt,
        "response": ai_response[:500] + ("..." if len(ai_response) > 500 else ""),
        "geo_raw": geo
    }
    write_json_log(ACTIVITY_LOG_FILE, entry)

def write_json_log(filename, entry):
    try:
        with open(filename, "r") as f:
            logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []
    logs.append(entry)
    if len(logs) > 2000:
        logs = logs[-2000:]
    with open(filename, "w") as f:
        json.dump(logs, f, indent=2)

# ========== HEARTBEAT ==========
@app.route('/api/heartbeat', methods=['POST'])
def heartbeat():
    username = session.get('username')
    if not username:
        return jsonify({"error": "No username"}), 401
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', 'Unknown')
    now = datetime.now()
    geo = get_location(ip)
    gps = get_geo_from_session()
    if gps:
        geo = enrich_geo_with_gps(geo, gps)
    with active_users_lock:
        active_users[username] = {
            "username": username,
            "ip": ip,
            "user_agent": ua,
            "device": parse_device(ua),
            "last_seen": now.isoformat(),
            "location": get_full_location_string(geo)
        }
    return jsonify({"status": "ok"})

@app.route('/api/set-location', methods=['POST'])
def set_location():
    data = request.json
    lat = data.get('latitude')
    lon = data.get('longitude')
    if lat is not None and lon is not None:
        session['latitude'] = lat
        session['longitude'] = lon
        return jsonify({"status": "ok"})
    return jsonify({"error": "Invalid coordinates"}), 400

# ========== BEFORE REQUEST ==========
@app.before_request
def before_request():
    ip = request.remote_addr
    banned, ban_type = is_ip_banned(ip)
    if banned:
        if ban_type == "permanent":
            abort(403, description="Akses Anda diblokir permanen karena aktivitas berbahaya.")
        else:
            abort(429, description="Anda sedang diblokir sementara karena spam/serangan.")
    if not request.path.startswith('/static') and request.endpoint != 'static':
        if not rate_limit(ip, max_requests=20, window=5):
            ban_ip(ip, duration_hours=1)
            abort(429, description="Terlalu banyak permintaan, Anda diblokir sementara.")
    if request.endpoint not in ('static', None, 'admin') and not request.path.startswith('/api') and request.method == 'GET':
        user_agent = request.headers.get('User-Agent', 'Unknown')
        username = session.get('username')
        if username:
            log_visit(ip, user_agent, username)

# ========== FUNGSI TRACKING (OSINT) ==========
LEAKED_DB = {
    "track": {
        "082113456789": {"nama": "Andi Pratama", "nik": "3275091802830005", "alamat": "Jl. Mawar No. 12, Bandung", "tgl_lahir": "18-02-1983", "gmail": "andi.pratama83@gmail.com", "fb": "fb.com/andi.pratama.9", "ig": "instagram.com/andipratama83"},
        "085812345678": {"nama": "Siti Nurhaliza", "nik": "3174015505840003", "alamat": "Jl. Melati No. 55, Jakarta Pusat", "tgl_lahir": "15-05-1984", "gmail": "siti.nurhaliza84@gmail.com", "fb": "fb.com/sitinurhaliza", "ig": "instagram.com/sitinurhaliza_real"}
    },
    "gmail": {
        "andi.pratama83@gmail.com": "082113456789",
        "siti.nurhaliza84@gmail.com": "085812345678"
    },
    "nik": {
        "3275091802830005": "Andi Pratama | 082113456789",
        "3174015505840003": "Siti Nurhaliza | 085812345678"
    }
}

def validate_number(key, phone):
    url = f"http://apilayer.net/api/validate?access_key={key}&number={phone}&country_code=&format=1"
    try:
        resp = requests.get(url)
        data = resp.json()
        if data.get('valid'):
            return {"valid": True, "number": data.get('international_format'), "country": data.get('country_name'), "location": data.get('location'), "carrier": data.get('carrier'), "line_type": data.get('line_type')}
        return {"valid": False, "error": "Nomor tidak valid"}
    except:
        return {"valid": False, "error": "Gagal validasi"}

def track_number_logic(query):
    clean = re.sub(r'\D', '', query)
    result = {"query": query, "type": "phone", "source": "numverify + leak_db"}
    result['numverify'] = validate_number(NUMVERIFY_KEY, clean)
    result['leaked_data'] = LEAKED_DB['track'].get(clean, None)
    result['dorks'] = [
        f'site:*.id "{clean}" filetype:xls OR filetype:csv OR filetype:pdf',
        f'intitle:"index of" "{clean}" password OR db OR backup',
        f'inurl:admin "{clean}" login'
    ]
    return result

def track_gmail_logic(email):
    result = {"query": email, "type": "email", "source": "breach_db + leak_lookup"}
    linked_phone = LEAKED_DB['gmail'].get(email.lower())
    if linked_phone and linked_phone in LEAKED_DB['track']:
        result['leaked_data'] = LEAKED_DB['track'][linked_phone]
        result['leaked_data']['phone'] = linked_phone
    elif linked_phone:
        result['leaked_data'] = {"phone": linked_phone}
    else:
        result['leaked_data'] = None
    try:
        resp = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", headers={"hibp-api-key":"no-key","user-agent":"BIN-Agent"})
        if resp.status_code == 200:
            result['haveibeenpwned'] = [b['Name'] for b in resp.json()]
        else:
            result['haveibeenpwned'] = []
    except:
        result['haveibeenpwned'] = "Error HIBP"
    result['dorks'] = [
        f'"{email}" filetype:txt OR filetype:sql OR filetype:bak',
        f'site:pastebin.com "{email}"',
        f'intitle:"{email}" password'
    ]
    return result

def scrape_facebook_logic(username):
    clean_user = username.replace('fb.com/', '').replace('facebook.com/', '').strip('/')
    try:
        resp = requests.get(f"https://www.facebook.com/{clean_user}", headers={"User-Agent": "Mozilla/5.0"}, timeout=5)
        if resp.status_code == 200:
            # Parsing sederhana (bisa gunakan BeautifulSoup jika tersedia)
            title_match = re.search(r'<title>(.*?)</title>', resp.text)
            name = title_match.group(1) if title_match else "Tidak diketahui"
            return {
                "query": username,
                "type": "facebook",
                "name": name,
                "possible_id": f"ID{abs(hash(clean_user))%10000000000}",
                "dork": f'site:facebook.com "{clean_user}" email OR phone'
            }
    except:
        pass
    return {"query": username, "type": "facebook", "note": "Gagal mengakses profil (mungkin tidak publik)"}

def nik_lookup(nik):
    clean = re.sub(r'\D', '', nik)
    if clean in LEAKED_DB['nik']:
        return {"nik": clean, "data": LEAKED_DB['nik'][clean]}
    if len(clean) == 16:
        kode_wilayah = clean[:6]
        tgl_lahir_code = int(clean[6:12])
        # Parsing tanggal lahir ala Dukcapil
        day = tgl_lahir_code // 10000
        month = (tgl_lahir_code // 100) % 100
        year = tgl_lahir_code % 100
        if day > 40:  # Wanita
            day -= 40
            gender = "Perempuan"
        else:
            gender = "Laki-laki"
        return {
            "nik": clean,
            "analysis": {
                "kode_wilayah": kode_wilayah,
                "tanggal_lahir": f"{day:02d}-{month:02d}-19{year:02d}",
                "jenis_kelamin": gender
            }
        }
    return {"nik": clean, "data": "Format NIK tidak valid"}

# ========== SYSTEM PROMPT ==========
def get_system_prompt():
    try:
        with open('system_prompt.txt', 'r', encoding='utf-8') as f:
            content = f.read().strip()
            return content if content else "You are a helpful assistant."
    except FileNotFoundError:
        return "You are a helpful assistant."

# ========== TOOL EXECUTION ==========
def execute_tool(command, timeout=30):
    try:
        # Hanya izinkan beberapa command yang terdaftar
        allowed = ['nmap', 'nikto', 'sqlmap', 'nuclei', 'subfinder', 'amass', 'ffuf', 'searchsploit']
        if not any(command.startswith(cmd) for cmd in allowed):
            return "Perintah tidak diizinkan."
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
        output = result.stdout + result.stderr
        if len(output) > 2000:
            output = output[:2000] + "\n... (output dipotong)"
        return output.strip()
    except subprocess.TimeoutExpired:
        return "Perintah timeout."
    except FileNotFoundError:
        return "Tool tidak terinstall di server."
    except Exception as e:
        return f"Gagal: {str(e)}"

# ========== ROUTES ==========
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/identity')
def get_identity():
    username = session.get('username')
    if not username:
        return jsonify({"error": "no_username"}), 401
    return jsonify({"username": username})

@app.route('/api/set-username', methods=['POST'])
def set_username():
    data = request.json
    username = data.get('username', '').strip()
    if not username or len(username) < 2:
        return jsonify({"error": "Username minimal 2 karakter"}), 400
    session['username'] = username
    return jsonify({"success": True, "username": username})

@app.route('/api/sessions', methods=['GET', 'POST'])
def handle_sessions():
    username = session.get('username')
    if not username:
        return jsonify({"error": "Set username dulu"}), 401
    if request.method == 'GET':
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, title, created_at FROM chat_sessions WHERE user_identifier=? ORDER BY created_at DESC", (username,))
        sessions = [{"id": row[0], "title": row[1], "created_at": row[2]} for row in c.fetchall()]
        conn.close()
        return jsonify(sessions)
    else:
        title = request.json.get('title', 'New Chat')
        now = datetime.now().isoformat()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO chat_sessions (user_identifier, title, created_at) VALUES (?, ?, ?)", (username, title, now))
        session_id = c.lastrowid
        conn.commit()
        conn.close()
        return jsonify({"id": session_id, "title": title, "created_at": now})

@app.route('/api/sessions/<int:session_id>', methods=['DELETE'])
def delete_session(session_id):
    username = session.get('username')
    if not username:
        return jsonify({"error": "Set username dulu"}), 401
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM messages WHERE session_id=?", (session_id,))
    c.execute("DELETE FROM chat_sessions WHERE id=? AND user_identifier=?", (session_id, username))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route('/api/messages/<int:session_id>')
def get_messages(session_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT role, content FROM messages WHERE session_id=? ORDER BY timestamp ASC", (session_id,))
    msgs = [{"role": r[0], "content": r[1]} for r in c.fetchall()]
    conn.close()
    return jsonify(msgs)

def save_message(session_id, role, content):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute("INSERT INTO messages (session_id, role, content, timestamp) VALUES (?, ?, ?, ?)", (session_id, role, content, now))
    if role == "user":
        c.execute("UPDATE chat_sessions SET title=? WHERE id=? AND title='New Chat'", (content[:50], session_id))
    conn.commit()
    conn.close()

@app.route('/api/generate', methods=['POST'])
def generate_response():
    username = session.get('username')
    if not username:
        return jsonify({"error": "Username belum diatur"}), 401

    data = request.json
    prompt = data.get('prompt', '')
    active_tool = data.get('tool', 'core')
    session_id = data.get('session_id')

    attack = detect_attack(prompt)
    if attack:
        ip = request.remote_addr
        permanent_ban_ip(ip)
        abort(403, description=f"Aktivitas berbahaya terdeteksi ({attack}). Anda diblokir permanen.")

    if not prompt:
        return jsonify({"error": "Prompt kosong."}), 400

    if session_id:
        save_message(session_id, "user", prompt)

    ai_reply = ""

    # --- REAL TOOLS EXECUTION (Pentest, Hacker, Burp, Recon, DeepExploit) ---
    if active_tool in ("pentest", "hacker", "burp", "recon", "deepexploit"):
        # Deteksi perintah tool
        if prompt.startswith("nmap "):
            output = execute_tool(prompt)
            ai_reply = f"**Nmap Output:**\n```\n{output}\n```"
        elif prompt.startswith("nikto "):
            output = execute_tool(prompt)
            ai_reply = f"**Nikto Output:**\n```\n{output}\n```"
        elif prompt.startswith("sqlmap "):
            output = execute_tool(prompt, timeout=60)
            ai_reply = f"**SQLMap Output:**\n```\n{output}\n```"
        elif prompt.startswith("nuclei "):
            output = execute_tool(prompt, timeout=60)
            ai_reply = f"**Nuclei Output:**\n```\n{output}\n```"
        elif prompt.startswith("subfinder "):
            output = execute_tool(prompt)
            ai_reply = f"**Subfinder Output:**\n```\n{output}\n```"
        elif prompt.startswith("amass "):
            output = execute_tool(prompt, timeout=60)
            ai_reply = f"**Amass Output:**\n```\n{output}\n```"
        elif prompt.startswith("ffuf "):
            output = execute_tool(prompt)
            ai_reply = f"**FFUF Output:**\n```\n{output}\n```"
        # Untuk perintah lain, lanjut ke AI

    # --- OSINT Tracker (real APIs) ---
    if active_tool == "osint" and not ai_reply:
        tracking_result = None
        prompt_lower = prompt.lower().strip()
        phone_match = re.search(r'(\+62|62|08)\d{8,12}', prompt)
        if phone_match:
            tracking_result = track_number_logic(phone_match.group())
        elif re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', prompt.strip()):
            tracking_result = track_gmail_logic(prompt.strip())
        elif re.match(r'^\d{16}$', prompt.strip().replace(' ', '')):
            tracking_result = nik_lookup(prompt.strip())
        elif 'fb.com' in prompt_lower or 'facebook.com' in prompt_lower:
            tracking_result = scrape_facebook_logic(prompt.strip())

        if tracking_result:
            ai_reply = f"```json\n{json.dumps(tracking_result, indent=2, ensure_ascii=False)}\n```\n\n**Rekomendasi:** Gunakan dork di atas untuk pencarian lanjutan."

    # --- Jika tidak ada real action, gunakan AI API (Core, WormGPT, Agent, dll) ---
    if not ai_reply:
        headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
        system_instruction = get_system_prompt()
        payload = {
            "model": MODEL_ID,
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt}
            ]
        }
        try:
            resp = requests.post(API_URL, headers=headers, json=payload, timeout=60)
            resp.raise_for_status()
            result = resp.json()
            ai_reply = result.get('choices', [{}])[0].get('message', {}).get('content', '')
        except Exception as e:
            return jsonify({"error": f"API error: {str(e)}"}), 500

    if session_id:
        save_message(session_id, "assistant", ai_reply)

    user_agent = request.headers.get('User-Agent', 'Unknown')
    log_activity(username, request.remote_addr, user_agent, prompt, ai_reply, active_tool)
    return jsonify({"response": ai_reply})

# ========== ADMIN ROUTES ==========
@app.route('/admin')
def admin():
    return render_template('admin.html')

@app.route('/api/admin/live-data')
def admin_live_data():
    access_logs = []
    activity_logs = []
    try:
        with open(LOG_FILE, "r") as f:
            access_logs = json.load(f)
    except:
        pass
    try:
        with open(ACTIVITY_LOG_FILE, "r") as f:
            activity_logs = json.load(f)
    except:
        pass

    combined = []
    for entry in access_logs:
        entry['source'] = 'halaman'
        combined.append(entry)
    for entry in activity_logs:
        entry['source'] = 'chat'
        combined.append(entry)
    combined.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

    recent_logs = combined[:500]

    now = datetime.now()
    active = []
    with active_users_lock:
        for uname, data in list(active_users.items()):
            try:
                last_seen = datetime.fromisoformat(data['last_seen'])
                if (now - last_seen) < timedelta(minutes=2):
                    active.append(data)
                else:
                    del active_users[uname]
            except:
                pass

    return jsonify({
        "logs": recent_logs,
        "active_users": active
    })

@app.errorhandler(403)
def forbidden(e):
    return render_template('banned.html', message=e.description), 403

@app.errorhandler(429)
def too_many(e):
    return render_template('banned.html', message=e.description), 429

if __name__ == '__main__':
    port = int(os.environ.get("SERVER_PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
