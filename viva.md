# Viva and Video Guide: Local AI Security Log Analyzer

This document is a walkthrough of the project: what it does, how it was built,
how to demonstrate it, and how to explain its design choices and limitations.

## 1. Short project introduction

> This is a local web application for reviewing server logs for possible
> security attacks. A user uploads a `.log` or `.txt` file, the backend splits
> it into token-bounded chunks, and a locally running Ollama `qwen3:8b` model
> analyzes the chunks. Deterministic checks complement the model for selected
> patterns. Findings are saved to SQLite, correlated across chunks, and shown
> as one consolidated report with severity, line-number evidence, reasons, and
> recommended actions. Log text is treated as untrusted data and is never
> executed.

The application uses a browser dashboard, a Python/FastAPI backend, SQLite for
persisted results, and Ollama for local inference. Log content is not sent to a
cloud AI API.

## 2. Important hardware note

The requested `qwen3:8b` model was installed in the original development
environment. The setup script pulls it if it is missing in a new environment.
The model is approximately 5.2 GB on disk and requires more than the brief's
4 GB total-RAM limit to run. The app limits inference to one active analysis,
two CPU threads, and a 2,048-token context, but those settings do not make an
8B model fit in 4 GB of RAM. Use a machine with more memory (8 GB or more is
recommended), or select a smaller local Ollama model if the 4 GB limit is
strict.

## 3. How to run the application

### First-time setup

Requirements: Python 3.10+, Ollama, and `curl`. From the project directory:

```bash
cd /home/ihsan/Projects/cultive8
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
bash scripts/setup_local.sh
```

The setup script pulls the configured Ollama model and downloads the Qwen
tokenizer file. These setup downloads require internet. After setup, model
inference is local and can run offline.

In another terminal, start Ollama if it is not already running:

```bash
ollama serve
```

Back in the project terminal, export the environment settings and start the
web server:

```bash
set -a
source .env
set +a
uvicorn src.api.main:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}"
```

Open <http://127.0.0.1:8000/dashboard>. The `.env` file is not loaded
automatically by the application; the export commands make its values
available to the server process.

### Existing development environment

The project workspace already has a `venv`. To run it there, activate that
environment instead:

```bash
cd /home/ihsan/Projects/cultive8
source venv/bin/activate
ollama serve
```

Run `ollama serve` in a separate terminal if needed; then start Uvicorn in the
project terminal as above.

## 4. Suggested video walkthrough

Aim for about 3–5 minutes. Explain the goal and design first, then demonstrate
one upload and its report.

### A. Introduction

Show the dashboard and say:

> The key challenge was that the log is larger than the model's context. I
> address that by chunking the file, preserving source line numbers, analyzing
> chunks sequentially, persisting results, and consolidating related findings.

Mention that inference is local through Ollama, not a cloud service. Be
transparent that `qwen3:8b` exceeds the brief's 4 GB RAM limit.

### B. Explain the processing flow

Use the source files as visual anchors:

1. [public/index.html](./public/index.html) is the upload and report dashboard.
2. [src/api/routes/upload.py](./src/api/routes/upload.py) validates and saves
   uploaded log files.
3. [src/services/log_chunker.py](./src/services/log_chunker.py) parses log
   entries, groups them into token-limited chunks, and preserves original line
   numbers. Exceptionally long physical lines are split into fragments that
   retain the original line number.
4. [src/services/prompt_builder.py](./src/services/prompt_builder.py) builds a
   compact prompt and checks the full request against the configured token
   budget. It tells the model to treat log entries as data, ignore embedded
   instructions, and return structured JSON.
5. [src/services/ollama_client.py](./src/services/ollama_client.py) sends the
   prompt to the local Ollama model. Calls are made sequentially; concurrent
   analyses are prevented by the API.
6. [src/services/analysis_engine.py](./src/services/analysis_engine.py)
   retries failed model calls, normalizes and validates model output, runs
   deterministic checks, and coordinates each chunk.
7. [src/models/database.py](./src/models/database.py) stores findings and
   per-chunk status in SQLite so completed work is retained.
8. [src/services/correlation_engine.py](./src/services/correlation_engine.py)
   and [src/services/report_generator.py](./src/services/report_generator.py)
   merge findings into a consolidated report with evidence lines, severity,
   reasoning, and recommendations.

### C. Demonstrate a finding

For a reliable demo, use a small synthetic log with several failed logins from
one IP and account, followed by a successful login from the same IP/account.
Upload it and start analysis. Point out that the report should link the events
and cite their original line numbers, rather than producing unrelated
per-chunk summaries.

Explain the finding cautiously:

> Repeated failures followed by a success are evidence consistent with a
> possible brute-force attempt followed by account compromise. The report
> identifies the evidence and recommends verification; it does not prove
> intent or compromise beyond what the logs show.

The actual local smoke test used synthetic events and produced one consolidated
Critical brute-force finding across lines 1–4. A real log may produce different
results based on its format and evidence.

### D. Explain failure handling

Show or describe the error behavior:

- Invalid upload formats and oversized uploads are rejected.
- Model timeouts and malformed JSON are retried and then reported as failed
  chunks rather than crashing the entire analysis.
- Successful findings are persisted as the analysis proceeds.
- Deterministic findings are still retained for a chunk if its model output
  fails; the overall result is marked partial.
- Empty model findings are saved as a successful completed chunk.
- The dashboard can display progress, partial results, and failures.

### E. Close

Summarize what is complete and the tradeoffs:

> The app demonstrates local AI analysis, token-aware chunking, cross-chunk
> correlation, evidence-linked reporting, and persistence. It is a triage aid,
> not a replacement for a security analyst. The 8B model needs more than the
> stated 4 GB RAM, and model output can be imperfect, so findings need review.

## 5. Token and chunk budget

The configured context limit is 2,048 tokens. Current defaults are:

| Budget item | Tokens |
|---|---:|
| Maximum log payload per chunk | 1,200 |
| Maximum generated reply | 320 |
| Reserved prompt overhead | 400 |
| Safety margin | 96 |
| **Total** | **2,016** |

The full system and user prompt are measured with the local Qwen tokenizer
before the request is sent. The remaining difference to 2,048 is additional
headroom. The tokenizer file is installed by `scripts/setup_local.sh`; without
it, the app can use an explicitly reported character-estimate fallback, which
is less accurate.

The output allowance was increased after a live Qwen response was cut off
mid-JSON at the original 192-token cap. The log payload was adjusted to keep
the total request within the context limit, and the prompt now asks for concise
text fields.

## 6. Detection and correlation

The language model reviews each bounded chunk for supported evidence of
security issues such as login attacks, SQL injection, scanning, and unusual
request rates. Deterministic checks supplement the model for selected patterns:

- Repeated login failures and a later successful login for the same IP/account.
- SQL-injection-like syntax in a request.
- Requests to multiple sensitive paths returning 404.
- At least 30 timestamped requests from an IP within a 60-second window.

An ordinary `401` or `404` by itself is not treated as a confirmed attack. The
deterministic checks and model output are normalized and correlated so repeated
evidence can be combined. Evidence line numbers are merged; successful login
evidence after failures escalates the matching brute-force pattern.

## 7. Persistence, concurrency, and reliability

- SQLite stores finding details and chunk processing status.
- Chunks are sent to the model sequentially; only one analysis is active at a
  time through the API.
- Completed chunk findings are saved and are not discarded if a later call
  fails.
- A retry is attempted for model failures; an exhausted failure is visible in
  progress and the final status is partial.
- The response parser accepts valid JSON (including fenced JSON) and rejects
  incomplete or invalid responses without crashing.
- Model line references are constrained to actual source lines in the chunk.
- The dashboard supports cancellation and report download.

## 8. Security decisions

- Log entries are untrusted input. The system prompt explicitly instructs the
  model not to follow instructions or commands embedded in logs.
- The application never executes log contents.
- Inference is sent to the configured local Ollama server; no cloud AI API is
  used for log analysis.
- Model claims are treated as possible findings, not proof. Reports include
  supporting lines and defensive recommendations.

## 9. Testing and verification

Run the automated suite from the project root:

```bash
PYTHONPATH=. pytest -q
```

The completed implementation was verified with **83 passing tests**. Tests
cover chunking, output parsing, finding persistence, malformed model responses,
cross-chunk login correlation, API behavior, and report generation. A separate
live Ollama smoke test analyzed a synthetic login sequence with `qwen3:8b` and
verified that the final report had one consolidated finding with lines 1–4.

Tests use model mocks and do not require downloading or loading Qwen.

## 10. Known limitations and honest answers

1. **The 4 GB RAM limit is not met with Qwen3 8B.** The model is larger than
   this limit. A smaller local model is required if the limit is mandatory.
2. **The parser reads the file line by line, but builds a list of chunks.** This
   avoids sending the whole file in a single model request, but the current
   implementation retains parsed chunks in memory for analysis. It is not a
   strict constant-memory streaming pipeline.
3. **Very long individual lines are fragmented.** Original line numbers are
   retained, but splitting an entry can lose some of its surrounding context.
4. **Rules are intentionally conservative and limited.** A pattern match can
   be a false positive; absence of a finding does not prove a system is safe.
5. **The model can return malformed or inaccurate findings.** The app retries,
   validates responses, preserves deterministic checks, and exposes evidence,
   but a person should review conclusions.
6. **A walkthrough video still needs to be recorded.** This document is a
   speaking and demonstration guide, not a recorded video.

## 11. Likely viva questions

### Why use a local model?

The brief requires offline analysis and no cloud AI APIs. Ollama provides a
local model endpoint, so the backend can analyze logs without sending them to
an external AI service.

### Why split the file?

The model has a fixed context limit. Splitting keeps each request within the
2,048-token budget and allows analysis of files larger than one prompt.

### How are line numbers preserved?

The chunker assigns each non-empty source line its original 1-based line
number. Entries and fragments carry that number through prompts and findings.
The analysis engine filters model-provided line numbers against the lines
actually present in the chunk.

### How do you find a pattern spanning chunks?

The analysis engine maintains compact state and deterministic histories across
the ordered chunks. The correlation engine then merges findings by normalized
attack type and identity, combines evidence line numbers, and escalates the
login sequence when later success evidence exists.

### What if the model returns invalid JSON?

The parser rejects incomplete or malformed JSON. The engine retries, then
marks the chunk failed if needed. The analysis is partial rather than a crash,
and deterministic findings for that chunk are still preserved.

### Does a 401 prove brute force?

No. A single unauthorized response is not enough. The deterministic login
check requires repeated failures for the same source/account; a subsequent
successful login adds stronger evidence and raises severity.

### Does the implementation meet every resource limit?

No. It bounds request context and limits concurrency and CPU threads, but the
requested Qwen3 8B model itself exceeds the stated 4 GB RAM limit. This is
called out in the README and should be disclosed in the presentation.

### How would you improve it next?

Use a smaller quantized model to meet the memory limit, change parsing and
analysis to process chunks incrementally instead of retaining the entire chunk
list, expand test coverage against varied real-world log formats, and measure
latency and memory usage on the target hardware.

## 12. Useful project references

- [README.md](./README.md) — setup, configuration, behavior, and limits.
- [AI_USAGE.md](./AI_USAGE.md) — coding/model prompts, token budget, and
  development notes.
- [src/config.py](./src/config.py) — model and token budget defaults.
- [scripts/setup_local.sh](./scripts/setup_local.sh) — model/tokenizer setup.
- [public/index.html](./public/index.html) — dashboard.
- [src/services/analysis_engine.py](./src/services/analysis_engine.py) — core
  chunk analysis, retries, rules, and correlation flow.
