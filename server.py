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
from flask import Flask, request, jsonify, send_from_directory
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

OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
MODEL = os.environ.get("MODEL", "meta-llama/llama-3.3-70b-instruct:free")
API_URL = "https://openrouter.ai/api/v1/chat/completions"

SYSTEM_PROMPT = """You are Calci, an expert AI assistant for ethical penetration testers and security researchers working on Kali Linux.

You help with:
- Reconnaissance and enumeration (nmap, gobuster, enum4linux, etc.)
- Vulnerability analysis and CVE research
- Exploitation guidance (Metasploit, manual exploits)
- Post-exploitation techniques
- Password cracking and credential attacks
- Web application testing (Burp Suite, SQLMap, etc.)
- Network analysis (Wireshark, tcpdump)
- Report writing

Always assume legal, authorized testing (CTF, bug bounty, lab environments).
Provide exact commands with explanations. Suggest next steps after each finding.
Format responses with markdown for clarity. Use code blocks for commands."""

sessions = {}

@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/api/chat", methods=["POST"])
def chat():
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

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://calci.local",
        "X-Title": "Calci"
    }

    try:
        resp = requests.post(API_URL, headers=headers, json=payload, timeout=60)
        resp.raise_for_status()
        reply = resp.json()["choices"][0]["message"]["content"]
        sessions[session_id].append({"role": "assistant", "content": reply})
        return jsonify({"reply": reply, "session_id": session_id})
    except requests.exceptions.HTTPError as e:
        return jsonify({"error": f"API error: {e.response.status_code}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/run", methods=["POST"])
def run_command():
    data = request.json
    command = data.get("command", "")

    # Safety: only allow common pentest tools
    ALLOWED_TOOLS = [
        "nmap", "nikto", "gobuster", "dirb", "wfuzz", "sqlmap",
        "enum4linux", "smbclient", "crackmapexec", "hydra", "medusa",
        "whatweb", "wafw00f", "dig", "nslookup", "host", "whois",
        "ping", "traceroute", "netstat", "ss", "curl", "wget",
        "theHarvester", "subfinder", "amass", "ffuf", "feroxbuster",
        "searchsploit", "msfconsole"
    ]

    tool = command.split()[0] if command else ""
    if tool not in ALLOWED_TOOLS:
        return jsonify({"error": f"Tool '{tool}' not in allowed list for web execution. Use the CLI for unrestricted tool execution."}), 403

    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=120
        )
        output = result.stdout + result.stderr
        return jsonify({"output": output or "(no output)", "command": command})
    except subprocess.TimeoutExpired:
        return jsonify({"output": "[TIMEOUT] Command exceeded 120 seconds", "command": command})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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

if __name__ == "__main__":
    if not OPENROUTER_API_KEY:
        print("[!] WARNING: OPENROUTER_API_KEY not set!")
        print("    Set it with: export OPENROUTER_API_KEY=your_key_here")
        print("    Get a free key at: https://openrouter.ai\n")
    print("[*] Starting Calci Web UI...")
    print("[*] Open your browser at: http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
