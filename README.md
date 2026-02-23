# ⚡ Calcium — AI Pentesting Assistant for Kali Linux

An AI-powered security research assistant for Kali Linux, built as a native desktop app using Electron + Flask + free OpenRouter AI models.

---

## Features

- **AI Chat** — Ask anything about tools, techniques, CVEs, and workflows
- **Built-in Terminal** — Run Kali tools directly from the UI
- **120+ Tools Reference** — Organized by category with one-click commands
- **Multi-user Login** — Admin panel to manage users
- **Session Export** — Save your full session to JSON
- **Desktop App** — Native Electron window for Kali Linux

---

## Requirements

- Kali Linux (recommended) or any Debian-based Linux
- Python 3.8+
- Node.js 16+
- Free API key from [openrouter.ai](https://openrouter.ai)

---

## Quick Setup

### Step 1 — Clone the repo
```bash
git clone https://github.com/sterlixo/calci.git
cd calci
```

### Step 2 — Run setup script
```bash
chmod +x setup-electron.sh
./setup-electron.sh
```

This automatically installs:
- Node.js and Electron
- Python dependencies (Flask, requests, bcrypt)
- Adds Calcium to your Kali app menu

### Step 3 — Get a free API key

1. Go to [openrouter.ai](https://openrouter.ai)
2. Sign up — completely free, no credit card needed
3. Go to **Keys** → **Create Key** → copy it

### Step 4 — Create your `.env` file
```bash
nano .env
```

Add these two lines:
```
OPENROUTER_API_KEY=sk-or-your-key-here
MODEL=meta-llama/llama-3.3-70b-instruct:free
```

Save with `Ctrl+X` → `Y` → `Enter`

### Step 5 — Launch
```bash
npm start
```

Or find **Calcium** in your Kali applications menu.

### Step 6 — Login

Default credentials on first launch:
```
Username: admin
Password: calcium123
```

> ⚠️ Change the default password after first login via the Admin panel.

---

## Free AI Models

Change the `MODEL` in your `.env` file to switch models:

| Model | Notes |
|-------|-------|
| `meta-llama/llama-3.3-70b-instruct:free` | Best quality (recommended) |
| `mistralai/mistral-7b-instruct:free` | Fast and lightweight |
| `google/gemma-3-27b-it:free` | Good for analysis |
| `deepseek/deepseek-r1:free` | Strong reasoning |
| `qwen/qwen-2.5-72b-instruct:free` | Large context window |

---

## Tool Categories

`Recon` · `Web` · `Exploit` · `Password` · `Network` · `Wireless` · `Post` · `Forensics` · `Misc`

120+ tools including nmap, rustscan, gobuster, ffuf, sqlmap, hydra, hashcat, msfconsole, bloodhound, aircrack-ng, volatility, and more.

---

## Troubleshooting

**App won't start / blank screen:**
```bash
cd ~/calci
python3 server.py
```
Check the error output, then restart with `npm start`.

**AI says "No response. Check MODEL in .env":**
- Make sure your `.env` has a valid model name with `:free` at the end
- Check your API key is correct at openrouter.ai

**After a Kali upgrade:**
```bash
sudo apt install spice-vdagent -y
cd ~/calci
npm install
npm start
```

**Permission denied on setup:**
```bash
chmod +x setup-electron.sh
./setup-electron.sh
```

---

## Project Structure

```
calci/
├── index.html          # Frontend UI
├── server.py           # Flask backend
├── auth.py             # Multi-user authentication
├── main.js             # Electron app wrapper
├── package.json        # Node dependencies
├── copilot.py          # CLI mode (optional)
├── setup.sh            # Python-only setup
├── setup-electron.sh   # Full desktop app setup
├── calcium.desktop     # Kali app menu shortcut
├── .env                # Your API key (not committed)
└── README.md
```

---

## Ethical Use

For authorized testing only — CTFs, bug bounties, your own lab, or systems you have **explicit written permission** to test.
