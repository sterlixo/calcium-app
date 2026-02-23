#!/usr/bin/env python3
"""
Calci Web Server - Flask backend for the web UI
Usage: python3 server.py
Then open: http://localhost:5000
"""

import os
import json
import time
import subprocess
import requests
from flask import Flask, request, jsonify, send_from_directory
from auth import verify_login, verify_token, logout_token, init_auth, create_user, delete_user, list_users, change_password
from datetime import datetime
from pathlib import Path

# ── Auto-load .env file ───────────────────────────────────────────────────────
def load_env():
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    os.environ.setdefault(key.strip(), value.strip())
load_env()

app = Flask(__name__, static_folder=".")

def require_auth():
    token = request.headers.get("X-Auth-Token") or request.cookies.get("calcium_token")
    result = verify_token(token)
    if not result["valid"]:
        return None
    return result

OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
# Model managed internally — never exposed to users
_raw_model = os.environ.get("MODEL", "")
MODEL = "arcee-ai/trinity-large-preview:free" if (not _raw_model or _raw_model.strip() in ("openrouter/free", "")) else _raw_model
API_URL = "https://openrouter.ai/api/v1/chat/completions"

# ── License system ────────────────────────────────────────────────────────────
LICENSE_KEY = os.environ.get("LICENSE_KEY", "")
MASTER_KEY  = "CALCIUM-STERLIN-2026-XKTZ"

def is_licensed():
    return LICENSE_KEY == MASTER_KEY

# ── GitHub Gist allowlist ─────────────────────────────────────────────────────
GIST_ID      = os.environ.get("GIST_ID", "872e702c27fd69cdbc22bdee030d0054")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GIST_RAW_URL = f"https://gist.githubusercontent.com/sterlixo/{GIST_ID}/raw/gistfile1.txt"

_gist_cache = {"data": None, "ts": 0}
GIST_TTL = 60  # seconds

def _fetch_gist() -> dict:
    """Fetch and cache the Gist JSON. Returns {allowed: [], banned: []}."""
    now = time.time()
    if _gist_cache["data"] and (now - _gist_cache["ts"]) < GIST_TTL:
        return _gist_cache["data"]
    try:
        r = requests.get(GIST_RAW_URL, timeout=5,
                         headers={"Cache-Control": "no-cache"})
        data = r.json()
        _gist_cache["data"] = data
        _gist_cache["ts"] = now
        print(f"[GIST] Refreshed — allowed: {data.get('allowed', [])}")
        return data
    except Exception as e:
        print(f"[GIST] Fetch failed: {e} — failing open")
        return _gist_cache["data"] or {"allowed": [], "banned": []}

def _push_gist(data: dict):
    """Push updated JSON back to the Gist."""
    if not GITHUB_TOKEN:
        print("[GIST] No GITHUB_TOKEN set — cannot push updates")
        return False
    try:
        r = requests.patch(
            f"https://api.github.com/gists/{GIST_ID}",
            headers={
                "Authorization": f"token {GITHUB_TOKEN}",
                "Accept": "application/vnd.github.v3+json"
            },
            json={"files": {"gistfile1.txt": {"content": json.dumps(data, indent=2)}}},
            timeout=10
        )
        if r.status_code == 200:
            _gist_cache["data"] = data
            _gist_cache["ts"] = time.time()
            print(f"[GIST] Updated — allowed: {data.get('allowed', [])}")
            return True
        else:
            print(f"[GIST] Push failed: {r.status_code} {r.text}")
            return False
    except Exception as e:
        print(f"[GIST] Push error: {e}")
        return False

def gist_add_user(username: str):
    """Add username to allowed list (and remove from banned)."""
    data = _fetch_gist()
    allowed = data.get("allowed", [])
    banned  = data.get("banned", [])
    if username not in allowed:
        allowed.append(username)
    if username in banned:
        banned.remove(username)
    _push_gist({"allowed": allowed, "banned": banned})
    print(f"[GIST] Auto-added '{username}' to allowlist")

def gist_remove_user(username: str):
    """Remove username from allowed list."""
    data = _fetch_gist()
    allowed = [u for u in data.get("allowed", []) if u != username]
    banned  = data.get("banned", [])
    _push_gist({"allowed": allowed, "banned": banned})
    print(f"[GIST] Removed '{username}' from allowlist")

def gist_ban_user(username: str):
    """Move username to banned list."""
    data = _fetch_gist()
    allowed = [u for u in data.get("allowed", []) if u != username]
    banned  = data.get("banned", [])
    if username not in banned:
        banned.append(username)
    _push_gist({"allowed": allowed, "banned": banned})
    print(f"[GIST] Banned '{username}'")

def is_user_allowed(username: str) -> bool:
    """Check Gist allowlist. Falls back to True if Gist not reachable."""
    try:
        data = _fetch_gist()
        allowed = data.get("allowed", [])
        banned  = data.get("banned", [])
        # Empty allowed list means not configured — let everyone through
        if not allowed:
            return True
        if username in banned:
            return False
        return username in allowed
    except Exception:
        return True  # fail open

SYSTEM_PROMPT = """You are Calci, an expert AI assistant for ethical penetration testers and security researchers working on Kali Linux.

You help with:
- Reconnaissance and enumeration (nmap, gobuster, enum4linux, etc.)
- Vulnerability analysis and CVE research
- Exploitation guidance (Metasploit, manual exploits)
- Post-exploitation techniques
- Password cracking and credential attacks
- Web application testing (Burp Suite, SQLMap, etc.)
- Network analysis (Wireshark, tcpdump)
- Wireless attacks (aircrack-ng suite)
- Forensics and reverse engineering
- Report writing

Always assume legal, authorized testing (CTF, bug bounty, lab environments).
Provide exact commands with explanations. Suggest next steps after each finding.
Format responses with markdown for clarity. Use code blocks for commands."""

sessions = {}

# ── Expanded pentest tool allowlist ──────────────────────────────────────────
ALLOWED_TOOLS = set([
    # Reconnaissance & scanning
    "nmap", "masscan", "rustscan", "unicornscan", "zmap",
    "ping", "traceroute", "tracepath", "mtr",
    "dig", "nslookup", "host", "whois", "dnsrecon", "dnsenum", "fierce",
    "theHarvester", "maltego", "recon-ng", "spiderfoot",
    "subfinder", "amass", "assetfinder", "findomain",
    "shodan", "censys",

    # Web application testing
    "nikto", "whatweb", "wafw00f", "wpscan", "droopescan", "joomscan",
    "gobuster", "dirb", "dirsearch", "feroxbuster", "ffuf", "wfuzz",
    "gospider", "hakrawler", "katana", "gau", "waybackurls", "photon",
    "sqlmap", "nosqli", "xsser",
    "curl", "wget", "httpx", "httprobe",
    "burpsuite", "zaproxy",
    "arjun", "dalfox", "nuclei",
    "sslscan", "sslyze", "testssl", "testssl.sh",
    "naabu", "dnsx", "tlsx", "mapcidr",

    # SMB / AD / Network services
    "enum4linux", "enum4linux-ng", "smbclient", "smbmap", "rpcclient",
    "crackmapexec", "nxc", "evil-winrm",
    "ldapsearch", "bloodhound", "sharphound",
    "responder", "impacket-secretsdump", "impacket-psexec",
    "impacket-smbexec", "impacket-wmiexec", "impacket-getTGT",
    "impacket-getNPUsers", "impacket-getUserSPNs",
    "kerbrute", "rubeus",
    "netstat", "ss", "arp", "arp-scan", "netdiscover",

    # Password attacks
    "hydra", "medusa", "ncrack",
    "hashcat", "john", "johnny",
    "crunch", "cewl", "cupp",
    "fcrackzip", "pdfcrack", "rarcrack",

    # Exploitation frameworks
    "msfconsole", "msfvenom", "searchsploit",
    "exploit", "exploitdb",

    # Post-exploitation / pivoting
    "chisel", "ligolo-ng", "proxychains", "proxychains4",
    "socat", "netcat", "nc", "ncat",
    "ssh", "scp", "sftp",
    "powercat",

    # Wireless
    "aircrack-ng", "airmon-ng", "airodump-ng", "aireplay-ng", "airbase-ng",
    "wifite", "bully", "reaver", "pixiewps",
    "hcxdumptool", "hcxtools",

    # Sniffing & MITM
    "tcpdump", "tshark", "wireshark",
    "ettercap", "bettercap", "arpspoof", "dsniff",

    # Forensics & reversing
    "binwalk", "foremost", "scalpel",
    "strings", "file", "xxd", "hexdump", "objdump", "readelf",
    "gdb", "pwndbg", "radare2", "r2", "ghidra",
    "volatility", "volatility3",
    "exiftool", "steghide", "stegseek", "zsteg",

    # Utilities / scripting
    "python3", "python", "ruby", "perl", "bash", "sh",
    "cat", "grep", "awk", "sed", "cut", "sort", "uniq", "wc",
    "ls", "find", "locate", "which", "whereis",
    "tar", "unzip", "7z", "gzip", "gunzip",
    "base64", "openssl",
    "ip", "ifconfig", "route", "iwconfig",
    "id", "whoami", "uname", "hostname", "env",
    "ps", "top", "htop", "kill",
    "echo", "printf",
])

# ── Blocked dangerous patterns ────────────────────────────────────────────────
BLOCKED_PATTERNS = [
    "rm -rf /", "mkfs", "dd if=", "> /dev/sd",
    "chmod 777 /etc", "wget | bash", "curl | bash", "curl | sh",
    ":(){ :|:& };:",  # fork bomb
]

def is_command_safe(command: str) -> tuple[bool, str]:
    cmd_lower = command.lower()
    for pattern in BLOCKED_PATTERNS:
        if pattern in cmd_lower:
            return False, f"Blocked pattern detected: '{pattern}'"
    return True, ""

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/api/chat", methods=["POST"])
def chat():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    session_id = data.get("session_id", "default")
    user_message = data.get("message", "")
    model = MODEL  # never exposed to user

    if not OPENROUTER_API_KEY:
        return jsonify({"error": "OPENROUTER_API_KEY not set on server"}), 400

    if session_id not in sessions:
        sessions[session_id] = []

    sessions[session_id].append({"role": "user", "content": user_message})

    payload = {
        "model": model,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + sessions[session_id],
        "temperature": 0.7,
        "max_tokens": 2048,
        "stream": True
    }

    api_headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://calcium.local",
        "X-Title": "Calcium"
    }

    def generate():
        full_reply = ""
        try:
            with requests.post(API_URL, headers=api_headers, json=payload, stream=True, timeout=60) as r:
                r.raise_for_status()
                for line in r.iter_lines():
                    if not line:
                        continue
                    text = line.decode("utf-8")
                    if not text.startswith("data: "):
                        continue
                    data_str = text[6:].strip()
                    if data_str == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data_str)
                        delta = chunk["choices"][0].get("delta", {}).get("content", "")
                        if delta:
                            full_reply += delta
                            yield f"data: {json.dumps({'token': delta})}\n\n"
                    except Exception:
                        continue
            sessions[session_id].append({"role": "assistant", "content": full_reply})
            yield f"data: {json.dumps({'done': True})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return app.response_class(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )

@app.route("/api/run", methods=["POST"])
def run_command():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    command = data.get("command", "").strip()
    if not command:
        return jsonify({"error": "No command provided"}), 400
    safe, reason = is_command_safe(command)
    if not safe:
        return jsonify({"error": f"Command blocked: {reason}"}), 403
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=120)
        output = result.stdout + result.stderr
        return jsonify({"output": output or "(no output)", "command": command, "returncode": result.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({"output": "[TIMEOUT] Command exceeded 120 seconds", "command": command})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools", methods=["GET"])
def list_tools():
    return jsonify({"tools": sorted(ALLOWED_TOOLS)})

@app.route("/api/clear", methods=["POST"])
def clear_session():
    session_id = request.json.get("session_id", "default")
    sessions.pop(session_id, None)
    return jsonify({"status": "cleared"})

@app.route("/api/export", methods=["POST"])
def export_session():
    session_id = request.json.get("session_id", "default")
    history = sessions.get(session_id, [])
    filename = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(history, f, indent=2)
    return jsonify({"status": "saved", "file": filename})

# ── Auth routes ───────────────────────────────────────────────────────────────
@app.route("/login")
def login_page():
    return send_from_directory(".", "login.html")

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.json
    username = data.get("username", "")

    # Check Gist allowlist first
    if not is_user_allowed(username):
        return jsonify({"success": False, "message": "Access denied — contact the administrator"}), 403

    result = verify_login(username, data.get("password", ""))
    return jsonify(result), 200 if result["success"] else 401

@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    token = request.headers.get("X-Auth-Token") or request.cookies.get("calcium_token")
    if token:
        logout_token(token)
    return jsonify({"success": True})

@app.route("/api/auth/verify", methods=["GET"])
def api_verify():
    token = request.headers.get("X-Auth-Token") or request.cookies.get("calcium_token")
    return jsonify(verify_token(token))

@app.route("/api/auth/users", methods=["GET"])
def api_list_users():
    auth = require_auth()
    if not auth or auth["role"] != "admin":
        return jsonify({"error": "Admin only"}), 403
    if not is_licensed():
        return jsonify({"error": "License required — admin features are locked"}), 403
    # Merge local users with Gist banned status
    users = list_users()
    gist_data = _fetch_gist()
    banned_list = gist_data.get("banned", [])
    for u in users:
        u["banned"] = u["username"] in banned_list
    return jsonify({"users": users})

@app.route("/api/auth/users/create", methods=["POST"])
def api_create_user():
    auth = require_auth()
    if not auth or auth["role"] != "admin":
        return jsonify({"error": "Admin only"}), 403
    if not is_licensed():
        return jsonify({"error": "License required — admin features are locked"}), 403
    data = request.json
    username = data.get("username", "")
    result = create_user(username, data.get("password", ""), data.get("role", "user"))
    if result["success"]:
        gist_add_user(username)  # auto-sync to Gist
    return jsonify(result), 200 if result["success"] else 400

@app.route("/api/auth/users/delete", methods=["POST"])
def api_delete_user():
    auth = require_auth()
    if not auth or auth["role"] != "admin":
        return jsonify({"error": "Admin only"}), 403
    if not is_licensed():
        return jsonify({"error": "License required — admin features are locked"}), 403
    data = request.json
    username = data.get("username", "")
    if username == auth["username"]:
        return jsonify({"success": False, "message": "Cannot delete yourself"}), 400
    result = delete_user(username)
    if result["success"]:
        gist_remove_user(username)  # auto-sync to Gist
    return jsonify(result)

@app.route("/api/auth/users/ban", methods=["POST"])
def api_ban_user():
    auth = require_auth()
    if not auth or auth["role"] != "admin":
        return jsonify({"error": "Admin only"}), 403
    if not is_licensed():
        return jsonify({"error": "License required — admin features are locked"}), 403
    username = request.json.get("username", "")
    if username == auth["username"]:
        return jsonify({"success": False, "message": "Cannot ban yourself"}), 400
    gist_ban_user(username)
    return jsonify({"success": True, "message": f"User '{username}' banned — blocked from all installations"})

@app.route("/api/auth/users/unban", methods=["POST"])
def api_unban_user():
    auth = require_auth()
    if not auth or auth["role"] != "admin":
        return jsonify({"error": "Admin only"}), 403
    if not is_licensed():
        return jsonify({"error": "License required — admin features are locked"}), 403
    username = request.json.get("username", "")
    gist_add_user(username)
    return jsonify({"success": True, "message": f"User '{username}' unbanned"})

@app.route("/api/auth/gist", methods=["GET"])
def api_gist_status():
    """Return current gist data so admin panel can show banned users."""
    auth = require_auth()
    if not auth or auth["role"] != "admin":
        return jsonify({"error": "Admin only"}), 403
    data = _fetch_gist()
    return jsonify({"allowed": data.get("allowed", []), "banned": data.get("banned", [])})

@app.route("/api/auth/password", methods=["POST"])
def api_change_password():
    auth = require_auth()
    if not auth:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    result = change_password(auth["username"], data.get("old_password", ""), data.get("new_password", ""))
    return jsonify(result)

if __name__ == "__main__":
    init_auth()
    if not OPENROUTER_API_KEY:
        print("[!] WARNING: OPENROUTER_API_KEY not set!")
        print("    Get a free key at: https://openrouter.ai\n")
    if not GITHUB_TOKEN:
        print("[!] WARNING: GITHUB_TOKEN not set — Gist sync disabled")
        print("    Add GITHUB_TOKEN=your_token to .env\n")
    print(f"[*] Loaded {len(ALLOWED_TOOLS)} allowed tools")
    print("[*] Starting Calcium Web UI...")
    print("[*] Open your browser at: http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
