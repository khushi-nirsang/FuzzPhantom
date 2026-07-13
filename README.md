# FuzzPhantom

FuzzPhantom is an async web reconnaissance and URL fuzzing toolkit for authorized security testing. It is built to cover practical ffuf and DirBuster-style workflows while also keeping crawler, API discovery, parameter fuzzing, and bug bounty reporting in one tool.

## Status

Release candidate: feature-complete for serious local and authorized target testing.

Use it only on systems you own or have explicit permission to test.

## Key Features

| Area | Capability |
|---|---|
| Directory fuzzing | Recursive async brute force, extensions, live rows, progress, resume |
| Request fuzzing | Raw Burp-style requests, `FUZZ`, named placeholders, sniper/pitchfork/clusterbomb |
| Match/filter logic | Status, size, words, lines, time, body regex, header regex, content type |
| False-positive control | Auto-calibration with strict/balanced/relaxed profiles |
| Traffic control | Rate limit, delay, jitter, timeout, HTTP/SOCKS proxy, replay proxy |
| Discovery | Subdomains, crawler, JS/API discovery, smart wordlist generation |
| Output | JSON, JSONL, CSV, PDF, HackerOne, Bugcrowd, Intigriti |
| Operations | CLI, GUI backend support, tests, local benchmark harness, installable command |

## Installation

```bash
cd FuzzPhantom
pip install -r requirements.txt
pip install -e .
```

Optional NLP data for smart wordlists:

```bash
python -c "import nltk; nltk.download('stopwords')"
```

After editable install, you can use either:

```bash
python main.py --help
fuzzphantom --help
```

On Windows, if `fuzzphantom` is not found after install, add Python's user `Scripts` directory to PATH or run `python main.py` from the project directory.

## Quick Start

```bash
# Full scan
python main.py -d example.com --all --output json jsonl csv pdf

# Directory brute force
python main.py -d example.com --dir --dir-wordlist wordlists/directories.txt -e php,txt,bak

# Follow redirects
python main.py -d example.com --dir --follow-redirects

# WAF-aware pacing with resume
python main.py -d example.com --dir --delay 100 --jitter 250 --resume

# Bigger discovery pass with mutations and controlled recursion
python main.py -d example.com --dir --mutate-wordlist --mutate-depth 2 --recursion-status 200,301-308

# Raw Burp request fuzzing
python main.py --request request.txt --dir-wordlist wordlists/params.txt --output jsonl csv

# Professional PDF report
python main.py -d example.com --dir --output pdf

# Named placeholders with pitchfork mode
python main.py --request login.txt -W users.txt:USER -W passwords.txt:PASS --fuzz-mode pitchfork

# Proxy all traffic through Burp/ZAP
python main.py -d example.com --dir --proxy http://127.0.0.1:8080

# Replay only confirmed hits through Burp/ZAP
python main.py -d example.com --dir --replay-proxy http://127.0.0.1:8080
```

## Important Options

| Flag | Default | Description |
|---|---|---|
| `-d DOMAIN` | none | Primary target domain or URL |
| `-D FILE` | none | Domain list |
| `-U FILE` | none | URL list |
| `--request FILE` | none | Raw HTTP request file |
| `--dir` | off | Enable directory/request fuzzing |
| `--crawl` | off | Enable crawler |
| `--fuzz` | off | Enable parameter fuzzer |
| `--api` | off | Enable API and JS discovery |
| `--all` | off | Enable all modules |
| `--dir-wordlist FILE` | built-in | Directory wordlist |
| `-e EXTS` | none | Extension expansion, comma-separated |
| `-W FILE:KEY` | none | Named placeholder wordlist |
| `--fuzz-mode MODE` | sniper | `sniper`, `pitchfork`, or `clusterbomb` |
| `--mutate-wordlist` | off | Add case, slash, backup, numeric, and tech variants |
| `--mutate-depth N` | 1 | Mutation intensity, `1` or `2` |
| `--rate N` | 50 | Requests per second |
| `--threads N` | 20 | Concurrent workers |
| `--timeout SEC` | 10 | HTTP timeout |
| `--delay MS` | 0 | Fixed delay before requests |
| `--jitter MS` | 0 | Random extra delay before requests |
| `--max-errors N` | 0 | Stop directory fuzzing after N request errors |
| `--max-hits N` | 0 | Stop directory fuzzing after N confirmed hits |
| `--no-calibration` | off | Disable auto-calibration |
| `--calibration-profile PROFILE` | balanced | `strict`, `balanced`, or `relaxed` |
| `-mc/-fc CODES` | built-in | Match/filter status codes |
| `-ms/-fs SIZES` | none | Match/filter byte size |
| `-mw/-fw WORDS` | none | Match/filter word count |
| `-ml/-fl LINES` | none | Match/filter line count |
| `-mt/-ft MS` | none | Match/filter response time |
| `-mr/-fr REGEX` | none | Match/filter body regex |
| `-mh/-fh REGEX` | none | Match/filter header regex |
| `-mct/-fct REGEX` | none | Match/filter content type |
| `--recursion-status CODES` | none | Only recurse into matching status codes |
| `--recursion-match REGEX` | none | Only recurse into matching URLs |
| `--recursion-filter REGEX` | none | Skip recursion into matching URLs |
| `--proxy URL` | none | HTTP/SOCKS proxy or proxy list/file |
| `--proxy-max-failures N` | 3 | Quarantine rotating HTTP proxies after N failures |
| `--replay-proxy URL` | none | Replay confirmed hits through proxy |
| `-r, --follow-redirects` | off | Follow redirects |
| `--resume` | off | Resume directory fuzzing from saved state |
| `--resume-file FILE` | auto | Custom resume file |
| `--only-urls` | off | Live output only matched URLs |
| `--silent` / `-q` | off | Suppress live output |
| `--version` | n/a | Print version |

## Testing

```bash
python -m compileall core modules gui reporting main.py tests
python -m pytest -q
python main.py --help
python main.py --version
```

## Local Benchmark

FuzzPhantom includes a local benchmark harness that starts a tiny HTTP target and runs a controlled directory fuzzing pass. It does not touch the internet.

```bash
python scripts/local_benchmark.py
```

If `ffuf` is installed and available on PATH, the script also runs a comparable ffuf command and prints both timings.

## Project Structure

```text
FuzzPhantom/
  main.py
  pyproject.toml
  requirements.txt
  core/
  modules/
  reporting/
  gui/
  payloads/
  wordlists/
  tests/
  scripts/
```

## Release Checklist

1. Run compile checks.
2. Run tests.
3. Run the local benchmark.
4. Run one authorized staging target scan.
5. Review generated JSONL/CSV/PDF reports.
6. Confirm `fuzzphantom --help` works after install.

## Legal Disclaimer

FuzzPhantom is intended only for authorized security testing and bug bounty programs. Always obtain explicit written permission before testing any system you do not own. The authors accept no liability for misuse.
