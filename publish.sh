#!/bin/bash
# ─────────────────────────────────────────────────────────────
#  Calcium — Publish Script
#  Obfuscates private code and pushes to public repo
#  Run from your private repo: ~/calci/
#  Usage: ./publish.sh
# ─────────────────────────────────────────────────────────────

set -e

# ── Config ────────────────────────────────────────────────────
PRIVATE_DIR="$HOME/calci"
PUBLIC_DIR="$HOME/calcium-app"
PUBLIC_REPO="https://github.com/sterlixo/calcium-app.git"

C="\033[1;36m"
G="\033[1;32m"
Y="\033[1;33m"
R="\033[1;31m"
W="\033[0m"

echo ""
echo -e "${C}  ╔══════════════════════════════════════╗"
echo -e "  ║   CALCIUM — PUBLISH TO PUBLIC REPO   ║"
echo -e "  ╚══════════════════════════════════════╝${W}"
echo ""

# ── Check tools ───────────────────────────────────────────────
echo -e "${C}[1/6] Checking tools...${W}"

if ! command -v pyarmor &> /dev/null; then
  echo -e "${Y}[*] Installing pyarmor...${W}"
  pip3 install pyarmor --break-system-packages -q
fi

if ! command -v javascript-obfuscator &> /dev/null; then
  echo -e "${Y}[*] Installing javascript-obfuscator...${W}"
  npm install -g javascript-obfuscator --silent
fi

echo -e "${G}[✓] Tools ready${W}"

# ── Clone or pull public repo ─────────────────────────────────
echo -e "${C}[2/6] Preparing public repo...${W}"

if [ ! -d "$PUBLIC_DIR" ]; then
  echo -e "${Y}[*] Cloning public repo...${W}"
  git clone "$PUBLIC_REPO" "$PUBLIC_DIR"
else
  echo -e "${Y}[*] Pulling latest public repo...${W}"
  cd "$PUBLIC_DIR" && git pull origin main 2>/dev/null || true
fi

# Clean old build files (keep .git)
cd "$PUBLIC_DIR"
find . -not -path './.git*' -not -name '.' -delete 2>/dev/null || true

echo -e "${G}[✓] Public repo ready${W}"

# ── Obfuscate Python files ────────────────────────────────────
echo -e "${C}[3/6] Obfuscating Python files...${W}"

cd "$PRIVATE_DIR"

# Obfuscate all Python files together
pyarmor gen \
  server.py \
  auth.py \
  copilot.py \
  --output "$PUBLIC_DIR" \
  --no-runtime 2>/dev/null || \
pyarmor gen \
  server.py \
  auth.py \
  copilot.py \
  --output "$PUBLIC_DIR"

echo -e "${G}[✓] Python files obfuscated${W}"

# ── Obfuscate JavaScript (index.html) ────────────────────────
echo -e "${C}[4/6] Obfuscating JavaScript in index.html...${W}"

cd "$PRIVATE_DIR"

# Extract JS from index.html, obfuscate, re-inject
python3 << 'PYEOF'
import re, subprocess, os, sys

src = open('index.html', 'r').read()

# Find all <script>...</script> blocks (not src= ones)
def obfuscate_js(js_code):
    # Write to temp file
    with open('/tmp/ca_temp.js', 'w') as f:
        f.write(js_code)
    result = subprocess.run([
        'javascript-obfuscator', '/tmp/ca_temp.js',
        '--output', '/tmp/ca_temp_out.js',
        '--compact', 'true',
        '--string-array', 'true',
        '--string-array-encoding', 'rc4',
        '--identifier-names-generator', 'hexadecimal',
        '--dead-code-injection', 'false',
        '--self-defending', 'false'
    ], capture_output=True, text=True)
    if result.returncode == 0:
        return open('/tmp/ca_temp_out.js').read()
    return js_code  # fallback: keep original if obfuscation fails

# Replace inline script blocks
def replace_script(match):
    js = match.group(1)
    # Skip very short scripts or external ones
    if len(js.strip()) < 50:
        return match.group(0)
    obfuscated = obfuscate_js(js)
    return f'<script>{obfuscated}</script>'

result = re.sub(r'<script>([\s\S]*?)</script>', replace_script, src)

out_path = os.path.expanduser('~/calcium-app/index.html')
with open(out_path, 'w') as f:
    f.write(result)
print('  index.html processed')
PYEOF

echo -e "${G}[✓] JavaScript obfuscated${W}"

# ── Copy non-obfuscated files ─────────────────────────────────
echo -e "${C}[5/6] Copying remaining files...${W}"

cd "$PRIVATE_DIR"

# Copy files that don't need obfuscation
cp login.html       "$PUBLIC_DIR/login.html"
cp main.js          "$PUBLIC_DIR/main.js"
cp package.json     "$PUBLIC_DIR/package.json"
cp calcium.desktop  "$PUBLIC_DIR/calcium.desktop"
cp setup-electron.sh "$PUBLIC_DIR/setup-electron.sh"

# Copy agent.py (obfuscated version already in PUBLIC_DIR from pyarmor)
# If not there, copy plain
if [ ! -f "$PUBLIC_DIR/agent.py" ] && [ -f "$PRIVATE_DIR/agent.py" ]; then
  cp "$PRIVATE_DIR/agent.py" "$PUBLIC_DIR/agent.py"
fi

# Write a clean setup.sh for users (no private info)
cat > "$PUBLIC_DIR/setup.sh" << 'EOF'
#!/bin/bash
echo ""
echo "  ⚡ Calcium — AI Pentesting Assistant"
echo "  Setup starting..."
echo ""

# Install Node.js if needed
if ! command -v node &> /dev/null; then
  echo "[*] Installing Node.js..."
  sudo apt install nodejs npm -y
fi

# Install Python deps
echo "[*] Installing Python dependencies..."
pip3 install flask requests bcrypt pyarmor --break-system-packages 2>/dev/null || \
pip3 install flask requests bcrypt pyarmor

# Install Electron
echo "[*] Installing Electron..."
npm install

echo ""
echo "[✓] Setup complete!"
echo ""
echo "  1. Get a free API key at: https://openrouter.ai"
echo "  2. Add your key:"
echo "     echo 'OPENROUTER_API_KEY=sk-or-xxxx' > .env"
echo "     echo 'MODEL=meta-llama/llama-3.3-70b-instruct:free' >> .env"
echo "  3. Launch:"
echo "     npm start"
echo ""
EOF
chmod +x "$PUBLIC_DIR/setup.sh"

# Write a clean README for public repo
cat > "$PUBLIC_DIR/README.md" << 'EOF'
# ⚡ Calcium — AI Pentesting Assistant

AI-powered security research assistant for Kali Linux.
Built with Electron + Flask + OpenRouter free AI models.

## Quick Install

```bash
git clone https://github.com/sterlixo/calcium-app.git
cd calcium-app
chmod +x setup.sh && ./setup.sh
```

## Setup

1. Get a free API key at [openrouter.ai](https://openrouter.ai)
2. Create your `.env` file:
```
OPENROUTER_API_KEY=sk-or-your-key-here
MODEL=meta-llama/llama-3.3-70b-instruct:free
```
3. Launch:
```bash
npm start
```

## Features

- AI Chat — Ask anything about tools, techniques, CVEs
- Built-in Terminal — Run commands directly from the UI
- 120+ Kali Tools — Organized by category with one-click commands
- Multi-user — Login system with admin panel
- Session Export — Save your full session

## Free AI Models

| Model | Notes |
|-------|-------|
| `meta-llama/llama-3.3-70b-instruct:free` | Best quality |
| `mistralai/mistral-7b-instruct:free` | Fast |
| `deepseek/deepseek-r1:free` | Strong reasoning |

## Ethical Use

For authorized testing only — CTFs, bug bounties, your own lab.
EOF

echo -e "${G}[✓] Files copied${W}"

# ── Push to public repo ───────────────────────────────────────
echo -e "${C}[6/6] Pushing to public repo...${W}"

cd "$PUBLIC_DIR"
git add -A

# Get version from package.json
VERSION=$(python3 -c "import json; print(json.load(open('$PRIVATE_DIR/package.json'))['version'])" 2>/dev/null || echo "2.0")
TIMESTAMP=$(date '+%Y-%m-%d %H:%M')

git commit -m "Release v${VERSION} — ${TIMESTAMP}" 2>/dev/null || \
git commit -m "Update — ${TIMESTAMP}" || true

git push origin main

echo ""
echo -e "${G}  ╔══════════════════════════════════════╗"
echo -e "  ║         PUBLISH COMPLETE ✓           ║"
echo -e "  ╚══════════════════════════════════════╝${W}"
echo ""
echo -e "  Public repo: ${C}https://github.com/sterlixo/calcium-app${W}"
echo -e "  Version:     ${C}v${VERSION}${W}"
echo ""
echo -e "  Users install with:"
echo -e "  ${Y}git clone https://github.com/sterlixo/calcium-app.git${W}"
echo -e "  ${Y}cd calcium-app && ./setup.sh${W}"
echo ""
