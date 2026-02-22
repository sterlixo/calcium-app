# ⚡ Calcium — AI Assistant for Kali Linux

An AI-powered security research assistant for Kali Linux, built as a native desktop app using Electron + Flask + OpenRouter free models.

## Features

- **AI Chat** — Ask anything about tools, techniques, CVEs, and workflows
- **Built-in Terminal** — Run security tools directly from the UI with output display
- **Activity Log** — Live timestamped log of every command run and AI interaction
- **Kali Tools Reference** — 120+ tools organized by category with one-click AI explanations
- **Session Export** — Save your full session to JSON
- **Desktop App** — Runs as a native Electron window, not just a browser tab

## Setup

### 1. Clone the repo
```bash
git clone https://github.com/yourusername/calci.git
cd calci
```

### 2. Run setup
```bash
chmod +x setup-electron.sh
./setup-electron.sh
```

This installs Node.js, Electron, Python dependencies, and adds Calcium to your Kali app menu.

### 3. Get a free API key
Sign up at https://openrouter.ai — completely free, no credit card needed.

### 4. Set your API key
```bash
echo 'OPENROUTER_API_KEY=sk-or-your-key-here' > .env
```

### 5. Launch
```bash
npm start
```

Or find **Calcium** in your Kali applications menu.

---

## After a Kali Upgrade

If anything breaks after `sudo apt upgrade`, run:
```bash
~/fix-after-upgrade.sh
```

Or manually:
```bash
sudo apt install spice-vdagent -y
cd ~/calci && npm install
npm start
```

---

## Free AI Models (via OpenRouter)

| Model | Notes |
|-------|-------|
| `meta-llama/llama-3.3-70b-instruct:free` | Default — best quality |
| `mistralai/mistral-7b-instruct:free` | Fast and lightweight |
| `google/gemma-3-27b-it:free` | Good for analysis |
| `deepseek/deepseek-r1:free` | Strong reasoning |
| `qwen/qwen-2.5-72b-instruct:free` | Large context |

---

## Tool Categories

`Recon` · `Web` · `Exploit` · `Password` · `Network` · `Wireless` · `Post` · `Forensics` · `Misc`

120+ tools including nmap, rustscan, gobuster, ffuf, gospider, sqlmap, hydra, hashcat, msfconsole, bloodhound, aircrack-ng, volatility, and more.

---

## Project Structure

```
calci/
├── index.html          # Frontend UI
├── server.py           # Flask backend + tool allowlist
├── main.js             # Electron app wrapper
├── package.json        # Node dependencies
├── copilot.py          # CLI mode (optional)
├── setup.sh            # Python-only setup
├── setup-electron.sh   # Full desktop app setup
├── calcium.desktop     # Kali app menu shortcut
├── .env                # API key (not committed)
└── README.md
```

---

## Ethical Use

For authorized testing only — CTFs, bug bounties, your own lab, or systems you have explicit written permission to test.
