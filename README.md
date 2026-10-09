# llm-safe-log-check

A small CLI that redacts secrets and personal data from logs before you paste them into an LLM.

It combines a local LLM (via [Ollama](https://ollama.com)) for context-aware detection with deterministic regex checks, so nothing leaves your machine.

## What it detects

- **LLM pass:** API keys, passwords, tokens, private keys, connection strings, identifiable PII
- **IPv4 addresses** → `REDACTED_IP_A`, `REDACTED_IP_B`, … (loopback/broadcast skipped)
- **Estonian personal ID codes** (with checksum validation, optional `EE` prefix) → `REDACTED_EE_ID_A`, …

Repeated values map to the same label, so the redacted log stays readable.

## Requirements

- Rust (2024 edition)
- Ollama running locally, with a model pulled:

```sh
ollama pull qwen3.5:2b
```

## Usage

```sh
# Redact a file → writes app.redacted.log next to it
cargo run --release -- app.log

# Or paste from stdin (Ctrl+D to finish), redacted output goes to stdout
cargo run --release
```

A summary of what was redacted is printed to stderr.

## Configuration

| Variable       | Default                  |
| -------------- | ------------------------ |
| `OLLAMA_URL`   | `http://localhost:11434` |
| `OLLAMA_MODEL` | `qwen3.5:2b`             |

## Disclaimer

Detection is best-effort. Always review the output before sharing it.

## License

[MIT](LICENSE)
