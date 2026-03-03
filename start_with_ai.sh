#!/bin/bash
# ========================================================
# BKI Network Portal - راه‌اندازی با AI آفلاین (Qwen2.5)
# ========================================================

cd "$(dirname "$0")"

# ---- تنظیمات AI ----
export AI_PROVIDER=openai
export AI_BASE_URL=http://localhost:11434/v1
export AI_MODEL=qwen2.5:7b
# برای مدل‌های دیگر:
#   export AI_MODEL=llama3.2
#   export AI_MODEL=qwen2.5:14b   (بهتر، نیاز به 10GB RAM)

# ---- راه‌اندازی Ollama ----
if ! pgrep -x "ollama" > /dev/null 2>&1; then
    echo "▶ Starting Ollama..."
    ollama serve &>/tmp/ollama_bki.log &
    sleep 3
fi

# ---- بررسی مدل ----
if ! ollama list 2>/dev/null | grep -q "$AI_MODEL"; then
    echo "▶ Downloading model $AI_MODEL (one-time, ~5GB)..."
    ollama pull "$AI_MODEL"
fi

echo "✅ Ollama running on http://localhost:11434"
echo "✅ AI Model: $AI_MODEL"
echo ""
echo "▶ Starting BKI Portal..."
python3 server_database.py
