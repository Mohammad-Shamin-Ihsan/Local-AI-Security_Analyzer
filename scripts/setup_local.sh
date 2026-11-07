#!/usr/bin/env bash
set -euo pipefail

model="${OLLAMA_MODEL:-qwen3:8b}"
tokenizer_path="${TOKENIZER_PATH:-./data/qwen3-tokenizer.json}"

if ! command -v ollama >/dev/null 2>&1; then
    echo "Ollama is required. Install it from https://ollama.com/download." >&2
    exit 1
fi

ollama pull "$model"
mkdir -p "$(dirname "$tokenizer_path")"
curl --fail --location --silent --show-error \
    "https://huggingface.co/Qwen/Qwen3-8B/resolve/main/tokenizer.json" \
    --output "$tokenizer_path"

echo "Local model and Qwen tokenizer are ready."
