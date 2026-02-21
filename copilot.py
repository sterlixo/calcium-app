#!/usr/bin/env python3
"""
Calci CLI - AI-powered pentesting assistant via OpenRouter
Usage: python3 copilot.py
"""

import os
import sys
import json
import subprocess
import requests
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

# ── Config ────────────────────────────────────────────────────────────────────
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
- Report writing and documentation

Guidelines:
- Always assume legal, authorized testing (CTF, bug bounty, lab environments)
- Provide exact commands with explanations
- Suggest next steps after each finding
- Flag critical findings clearly
- Be concise but thorough

When a user shares tool output, analyze it and recommend next steps."""

BANNER = """
\033[1;32m
 ██╗  ██╗ █████╗ ██╗     ██╗      ██████╗ ██████╗ ██████╗ ██╗██╗      ██████╗ ████████╗
 ██║ ██╔╝██╔══██╗██║     ██║     ██╔════╝██╔═══██╗██╔══██╗██║██║     ██╔═══██╗╚══██╔══╝
 █████╔╝ ███████║██║     ██║     ██║     ██║   ██║██████╔╝██║██║     ██║   ██║   ██║   
 ██╔═██╗ ██╔══██║██║     ██║     ██║     ██║   ██║██╔═══╝ ██║██║     ██║   ██║   ██║   
 ██║  ██╗██║  ██║███████╗██║     ╚██████╗╚██████╔╝██║     ██║███████╗╚██████╔╝   ██║   
 ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝    ╚═╝   
\033[0m
\033[1;31m  [ AI-Powered Pentesting Copilot | OpenRouter + Llama 3 | Kali Linux ]\033[0m
\033[0;90m  Type 'help' for commands | 'run <command>' to execute tools | 'exit' to quit\033[0m
"""

# ── Colors ────────────────────────────────────────────────────────────────────
class C:
    RED    = "\033[1;31m"
    GREEN  = "\033[1;32m"
    YELLOW = "\033[1;33m"
    BLUE   = "\033[1;34m"
    CYAN   = "\033[1;36m"
    WHITE  = "\033[1;37m"
    GRAY   = "\033[0;90m"
    RESET  = "\033[0m"

# ── Chat history ───────────────────────────────────────────────────────────────
history = []

def chat(user_message):
    """Send message to OpenRouter and get response."""
    if not OPENROUTER_API_KEY:
        return f"{C.RED}[ERROR]{C.RESET} OPENROUTER_API_KEY not set. Run: export OPENROUTER_API_KEY=your_key_here"

    history.append({"role": "user", "content": user_message})

    payload = {
        "model": MODEL,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + history,
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
        data = resp.json()
        reply = data["choices"][0]["message"]["content"]
        history.append({"role": "assistant", "content": reply})
        return reply
    except requests.exceptions.Timeout:
        return f"{C.RED}[ERROR]{C.RESET} Request timed out. Check your internet connection."
    except requests.exceptions.HTTPError as e:
        return f"{C.RED}[ERROR]{C.RESET} API error: {e.response.status_code} - {e.response.text}"
    except Exception as e:
        return f"{C.RED}[ERROR]{C.RESET} {str(e)}"

def run_tool(command):
    """Execute a shell command and return output."""
    print(f"\n{C.YELLOW}[*] Running:{C.RESET} {command}\n")
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=120
        )
        output = result.stdout + result.stderr
        if not output.strip():
            output = "(no output)"
        return output
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] Command took too long (>120s)"
    except Exception as e:
        return f"[ERROR] {str(e)}"

def save_session():
    """Save chat history to file."""
    filename = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(history, f, indent=2)
    print(f"{C.GREEN}[+] Session saved to {filename}{C.RESET}")

def print_help():
    print(f"""
{C.CYAN}━━━ Calci Commands ━━━{C.RESET}
  {C.GREEN}run <cmd>{C.RESET}     Execute a tool and analyze output with AI
                  e.g. run nmap -sV -p 80,443 192.168.1.1
  {C.GREEN}analyze{C.RESET}       Paste tool output for AI analysis (end with END)
  {C.GREEN}save{C.RESET}          Save current session to JSON file
  {C.GREEN}clear{C.RESET}         Clear conversation history
  {C.GREEN}model <name>{C.RESET}  Switch AI model (default: llama-3.3-70b-instruct:free)
  {C.GREEN}help{C.RESET}          Show this help
  {C.GREEN}exit{C.RESET}          Quit

{C.CYAN}━━━ Example Prompts ━━━{C.RESET}
  "I found port 8080 open running Tomcat 9.0.1, what should I try?"
  "Explain how to enumerate SMB shares on Windows targets"
  "Generate a nmap command for full port scan with service detection"
  "run nmap -sC -sV -p- 10.10.10.1"
""")

def print_response(text):
    """Pretty print AI response."""
    print(f"\n{C.CYAN}┌─ Calci ─────────────────────────────────────────{C.RESET}")
    # Simple markdown-like formatting
    for line in text.split("\n"):
        if line.startswith("```"):
            print(f"{C.GRAY}{line}{C.RESET}")
        elif line.startswith("#"):
            print(f"{C.YELLOW}{line}{C.RESET}")
        elif line.strip().startswith("*") or line.strip().startswith("-"):
            print(f"{C.GREEN}{line}{C.RESET}")
        else:
            print(f"{C.WHITE}{line}{C.RESET}")
    print(f"{C.CYAN}└───────────────────────────────────────────────────────{C.RESET}\n")

def main():
    global MODEL

    print(BANNER)

    if not OPENROUTER_API_KEY:
        print(f"{C.YELLOW}[!] No API key found. Set it with:{C.RESET}")
        print(f"    export OPENROUTER_API_KEY=your_key_here\n")
        print(f"    Get a free key at: {C.CYAN}https://openrouter.ai{C.RESET}\n")

    print(f"{C.GRAY}    Model: {MODEL}{C.RESET}")
    print(f"{C.GRAY}    Type 'help' for available commands\n{C.RESET}")

    while True:
        try:
            user_input = input(f"{C.RED}calci{C.RESET}{C.GRAY}>{C.RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{C.GRAY}[*] Exiting. Stay ethical.{C.RESET}")
            break

        if not user_input:
            continue

        cmd = user_input.lower()

        if cmd == "exit" or cmd == "quit":
            print(f"{C.GRAY}[*] Exiting. Stay ethical.{C.RESET}")
            break

        elif cmd == "help":
            print_help()

        elif cmd == "clear":
            history.clear()
            print(f"{C.GREEN}[+] Conversation history cleared.{C.RESET}")

        elif cmd == "save":
            save_session()

        elif cmd == "analyze":
            print(f"{C.YELLOW}[*] Paste your tool output below. Type 'END' on a new line when done:{C.RESET}")
            lines = []
            while True:
                line = input()
                if line.strip() == "END":
                    break
                lines.append(line)
            tool_output = "\n".join(lines)
            prompt = f"Analyze this tool output and suggest next steps:\n\n```\n{tool_output}\n```"
            print(f"\n{C.YELLOW}[*] Analyzing...{C.RESET}")
            response = chat(prompt)
            print_response(response)

        elif cmd.startswith("model "):
            MODEL = user_input[6:].strip()
            print(f"{C.GREEN}[+] Model switched to: {MODEL}{C.RESET}")

        elif cmd.startswith("run "):
            command = user_input[4:].strip()
            output = run_tool(command)
            print(f"{C.GRAY}{output}{C.RESET}")
            print(f"\n{C.YELLOW}[*] Sending output to AI for analysis...{C.RESET}")
            prompt = f"I ran the following command:\n`{command}`\n\nOutput:\n```\n{output}\n```\n\nAnalyze this and suggest next steps."
            response = chat(prompt)
            print_response(response)

        else:
            print(f"{C.YELLOW}[*] Thinking...{C.RESET}")
            response = chat(user_input)
            print_response(response)

if __name__ == "__main__":
    main()
