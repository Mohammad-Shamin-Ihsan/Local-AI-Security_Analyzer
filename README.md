# Local AI Security Log Analyzer

A local web app that analyzes `.log` and `.txt` files with Ollama's `qwen3:8b`.
The backend sends one bounded chunk at a time, saves each successful result to
SQLite, and merges related evidence across the file.

## Requirements

- Python 3.10+
- Ollama
- `qwen3:8b` pulled into Ollama
- `curl` for downloading the tokenizer during setup

> **Memory limit:** the installed Qwen3 8B Q4_K_M model is about 5.2 GB on disk
> and needs more than 4 GB of RAM to run. The app limits inference to one active
> analysis, 2 CPU threads, and a 2,048-token context, but it cannot make this
> model fit inside a 4 GB total-RAM limit. Use a larger-memory machine (8 GB or
> more recommended), or change `OLLAMA_MODEL` to a smaller local model if the
> 4 GB limit is mandatory.

## Setup and run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
bash scripts/setup_local.sh
set -a
source .env
set +a
uvicorn src.api.main:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}"
```

Open <http://127.0.0.1:8000/dashboard>. `setup_local.sh` pulls the Ollama
model and downloads the small Qwen tokenizer file. Those downloads are setup
only; the application sends inference to the local Ollama server and does not
use a cloud AI API. Once the model and tokenizer are installed, log analysis
works offline.

Environment settings are read from the process environment. The `.env` file
is not loaded automatically; the `source` commands above export it for the
server process.

Useful settings:

| Variable | Default | Purpose |
|---|---:|---|
| `OLLAMA_HOST` | `http://localhost:11434` | Local Ollama endpoint |
| `OLLAMA_MODEL` | `qwen3:8b` | Installed local model tag |
| `OLLAMA_TIMEOUT` | `180` | Per-call timeout in seconds |
| `MAX_CONTEXT_TOKENS` | `2048` | Ollama context limit |
| `MAX_CHUNK_TOKENS` | `1200` | Maximum log payload tokens in one chunk |
| `MAX_OUTPUT_TOKENS` | `320` | Maximum generated reply tokens |
| `TOKENIZER_PATH` | `./data/qwen3-tokenizer.json` | Local Qwen tokenizer JSON |

`GET /health` reports Ollama availability, memory, and whether exact Qwen
tokenization is active. If the tokenizer file is missing, a character-based
estimate is used and the health response identifies that reduced-accuracy mode.
Run `bash scripts/setup_local.sh` before analysis for the exact tokenizer.

## Processing and report behavior

- Uploads are streamed to disk and limited to `.log` / `.txt` and 100 MB by
  default.
- The chunker reads line by line, preserves original line numbers, and groups
  complete entries up to the configured token budget. An exceptionally long
  single line is represented as ordered text fragments with the same source
  line number; fragments are never silently dropped.
- Each prompt is checked against the context budget, including system/task
  instructions, prior evidence, output allowance, and safety margin.
- Chunks run sequentially. A second analysis request receives `409` while one
  is running. Findings and chunk status are persisted after each response,
  including successful empty responses; failed chunks are reported without
  deleting completed findings. Deterministic findings remain saved and visible
  in the partial report when a model response fails.
- Local rule checks complement the model for repeated login failures followed
  by success, SQL-injection payload indicators, sensitive-path scanning, and
  bursts of 30 or more requests in 60 seconds. A `401`/`404` alone is not
  treated as a confirmed attack.
- The final report merges findings by attack type and source identity, dedupes
  evidence line numbers, escalates a matching login sequence on success, and
  includes severity, evidence, reason, and recommended action.
- The dashboard supports upload, analysis progress, cancellation, findings,
  and JSON report download.

## Tests

```bash
PYTHONPATH=. pytest -q
```

Tests use local mocks for model inference; no model download is needed to run
the unit and API test suite.

## Known limits

- Qwen3 8B is incompatible with a strict 4 GB total-RAM ceiling. This project
  honors the requested model, not that hardware ceiling.
- If an oversized physical line needs multiple fragments, context between
  fragments may be imperfect; the original line number is retained.
- Rule checks are conservative and do not replace incident response or a
  human review. They detect evidence of attempts, not successful exploitation,
  unless the logs explicitly support that conclusion.
- This workspace does not include a recorded walkthrough video. Record the
  short submission video separately; the dashboard is served at `/dashboard`.
