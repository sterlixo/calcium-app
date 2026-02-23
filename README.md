# ⚡ Calcium — AI Pentesting Assistant for Kali Linux

An AI-powered security research assistant for Kali Linux.

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

### Step 6 — Login

> Contact the administrator to get your login credentials.

---

## Troubleshooting

**App won't start:**
```bash
cd ~/calcium-app
python3 server.py
```
Check the terminal output for errors, then restart with `npm start`.

**AI says "No response":**
- Check your API key is correct at openrouter.ai
- Make sure your `.env` file has `OPENROUTER_API_KEY` set

**Permission denied:**
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

## Ethical Use

For authorized testing only — CTFs, bug bounties, your own lab, or systems you have **explicit written permission** to test.
