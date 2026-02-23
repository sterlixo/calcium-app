# ⚡ Calcium — AI Pentesting Assistant for Kali Linux

An AI-powered security research assistant for Kali Linux, built as a native desktop app using Electron + Flask.

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

## Installation

### Step 1 — Clone the repo
```bash
git clone https://github.com/sterlixo/calcium-app.git
cd calcium-app
```

### Step 2 — Run setup
```bash
chmod +x setup.sh
./setup.sh
```

This automatically installs all Python and Node dependencies and asks for your API key.

### Step 3 — Get a free API key

1. Go to [openrouter.ai](https://openrouter.ai)
2. Sign up — completely free, no credit card needed
3. Go to **Keys** → **Create Key** → copy it

### Step 4 — Create your `.env` file
```bash
nano .env
```

Add:
```
OPENROUTER_API_KEY=sk-or-your-key-here
```

Save with `Ctrl+X` → `Y` → `Enter`

### Step 5 — Launch
```bash
npm start
```

Or find **Calcium** in your Kali applications menu.

### Step 6 — Login

> Contact the administrator to get your login credentials.

---

## Tool Categories

`Recon` · `Web` · `Exploit` · `Password` · `Network` · `Wireless` · `Post` · `Forensics` · `Misc`

120+ tools including nmap, rustscan, gobuster, ffuf, sqlmap, hydra, hashcat, msfconsole, bloodhound, aircrack-ng, volatility, and more.

---

## Troubleshooting

**App won't start / blank screen:**
```bash
cd ~/calcium-app
python3 server.py
```
Check the terminal output for errors, then restart with `npm start`.

**AI says "No response":**
- Check your API key is correct at openrouter.ai
- Make sure your `.env` file exists and has `OPENROUTER_API_KEY` set

**Permission denied on setup:**
```bash
chmod +x setup.sh
./setup.sh
```

**After a Kali upgrade:**
```bash
cd ~/calcium-app
npm install
npm start
```

---

## Project Structure

```
calcium-app/
├── index.html          # Frontend UI
├── server.py           # Flask backend
├── auth.py             # Multi-user authentication
├── main.js             # Electron app wrapper
├── package.json        # Node dependencies
├── copilot.py          # CLI mode (optional)
├── setup.sh            # Setup script
├── setup-electron.sh   # Full desktop app setup
├── calcium.desktop     # Kali app menu shortcut
├── .env                # Your API key (not committed)
└── README.md
```

---

## Ethical Use

For authorized testing only — CTFs, bug bounties, your own lab, or systems you have **explicit written permission** to test.
