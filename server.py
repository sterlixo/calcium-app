#!/usr/bin/env python3
"""
Calci Web Server - Flask backend for the web UI
Usage: python3 server.py
Then open: http://localhost:5000
"""

import os
import json
import subprocess
import requests
from flask import Flask, request, jsonify, send_from_directory, redirect
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
    """Check auth token from header or cookie."""
    token = request.headers.get("X-Auth-Token") or request.cookies.get("calcium_token")
    result = verify_token(token)
    if not result["valid"]:
        return None
    return result

OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
MODEL = os.environ.get("MODEL", "openrouter/free")
API_URL = "https://openrouter.ai/api/v1/chat/completions"

# ── License system ────────────────────────────────────────────────────────────
LICENSE_KEY = os.environ.get("LICENSE_KEY", "")
MASTER_KEY  = "CALCIUM-STERLIN-2026-XKTZ"

def is_licensed():
    return LICENSE_KEY == MASTER_KEY

# ── Supabase user management ──────────────────────────────────────────────────
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")

def is_user_allowed(username: str) -> bool:
    """Check if username is allowed in Supabase. Falls back to True if Supabase not configured."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        return True  # no Supabase configured — allow everyone
    try:
        resp = requests.get(
            f"{SUPABASE_URL}/rest/v1/allowed_users",
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": "application/json"
            },
            params={"username": f"eq.{username}", "allowed": "eq.true"},
            timeout=5
        )
        data = resp.json()
        return len(data) > 0
    except Exception as e:
        print(f"[SUPABASE] Check failed for {username}: {e}")
        return True  # fail open — don't lock users out if Supabase is down

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
    """Check command against blocked patterns."""
    cmd_lower = command.lower()
    for pattern in BLOCKED_PATTERNS:
        if pattern in cmd_lower:
            return False, f"Blocked pattern detected: '{pattern}'"
    return True, ""

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
    model = data.get("model", MODEL)

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
    }

    payload["stream"] = True
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

    # All tools allowed — only block dangerous patterns below

    # Check for destructive patterns
    safe, reason = is_command_safe(command)
    if not safe:
        return jsonify({"error": f"Command blocked: {reason}"}), 403

    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=120
        )
        output = result.stdout + result.stderr
        return jsonify({
            "output": output or "(no output)",
            "command": command,
            "returncode": result.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({"output": "[TIMEOUT] Command exceeded 120 seconds", "command": command})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools", methods=["GET"])
def list_tools():
    """Return the list of allowed tools."""
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
    username = data.get("username","")

    # Check Supabase allowlist first
    if not is_user_allowed(username):
        return jsonify({"success": False, "message": "Access denied — contact the administrator"}), 403

    result = verify_login(username, data.get("password",""))
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
    return jsonify({"users": list_users()})

@app.route("/api/auth/users/create", methods=["POST"])
def api_create_user():
    auth = require_auth()
    if not auth or auth["role"] != "admin":
        return jsonify({"error": "Admin only"}), 403
    if not is_licensed():
        return jsonify({"error": "License required — admin features are locked"}), 403
    data = request.json
    result = create_user(data.get("username",""), data.get("password",""), data.get("role","user"))
    return jsonify(result), 200 if result["success"] else 400

@app.route("/api/auth/users/delete", methods=["POST"])
def api_delete_user():
    auth = require_auth()
    if not auth or auth["role"] != "admin":
        return jsonify({"error": "Admin only"}), 403
    if not is_licensed():
        return jsonify({"error": "License required — admin features are locked"}), 403
    data = request.json
    if data.get("username") == auth["username"]:
        return jsonify({"success": False, "message": "Cannot delete yourself"}), 400
    result = delete_user(data.get("username",""))
    return jsonify(result)

@app.route("/api/auth/password", methods=["POST"])
def api_change_password():
    auth = require_auth()
    if not auth:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    result = change_password(auth["username"], data.get("old_password",""), data.get("new_password",""))
    return jsonify(result)

if __name__ == "__main__":
    init_auth()
    if not OPENROUTER_API_KEY:
        print("[!] WARNING: OPENROUTER_API_KEY not set!")
        print("    Set it with: export OPENROUTER_API_KEY=your_key_here")
        print("    Get a free key at: https://openrouter.ai\n")
    print(f"[*] Loaded {len(ALLOWED_TOOLS)} allowed tools")
    print("[*] Starting Calci Web UI...")
    print("[*] Open your browser at: http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
