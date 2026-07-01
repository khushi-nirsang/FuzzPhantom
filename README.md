# FuzzPhantom 👻

> **A modular Python-based offensive security toolkit for URL fuzzing and web reconnaissance. Built for bug bounty hunters.**

---

## ⚡ Features

| Module | Description |
|---|---|
| 🔍 **Subdomain Discovery** | Wordlist brute-force, Certificate Transparency logs (crt.sh), DNS zone transfer |
| 🕷️ **URL Crawler** | Async BFS crawler extracting links, forms, JS routes, parameterized URLs |
| 💉 **Parameter Fuzzer** | Injects SQLi, XSS, LFI, and generic payloads; detects status/length/error anomalies |
| 🔌 **API Discovery** | JS source analysis (fetch/axios), API path probing, credential leak detection |
| 🧠 **Smart Wordlist** | TF-IDF NLP wordlist generation from site content |
| 📋 **Bug Bounty Reports** | Exports to **HackerOne**, **Bugcrowd**, **Intigriti**, and **JSON** formats |

---

## 📦 Installation

```bash
# Clone the repo
cd FuzzPhantom

# Install dependencies
pip install -r requirements.txt

# Optional: download NLTK stopwords for NLP wordlist generation
python -c "import nltk; nltk.download('stopwords')"
```

---

## 🚀 Quick Start

```bash
# Full scan — all modules enabled
python main.py -d example.com --all --output json hackerone

# Subdomain discovery only
python main.py -d example.com --subdomains --wordlist wordlists/subdomains.txt

# Crawl + fuzz with custom payloads
python main.py -d example.com --crawl --fuzz --payloads payloads/sqli.txt payloads/xss.txt

# Route traffic through Burp Suite
python main.py -d example.com --crawl --fuzz --proxy http://127.0.0.1:8080

# Multiple output formats
python main.py -d example.com --all --output json hackerone bugcrowd intigriti

# Dry run (no real requests)
python main.py -d example.com --subdomains --crawl --dry-run

# Verbose mode
python main.py -d example.com --crawl --fuzz -v
```

---

## 🎛️ CLI Reference

```
usage: fuzzphantom [-h] [-d DOMAIN] [-D FILE] [--subdomains] [--crawl]
                   [--fuzz] [--api] [--smart-wordlist] [--all]
                   [-w FILE] [-p FILE [FILE ...]]
                   [-o FORMAT [FORMAT ...]] [--output-dir DIR]
                   [--depth N] [--rate N] [--threads N] [--timeout SEC]
                   [--proxy URL] [--user-agent UA]
                   [--dry-run] [-v] [--no-banner]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `-d DOMAIN` | — | Target domain |
| `-D FILE` | — | File with list of domains |
| `--subdomains` | off | Enable subdomain discovery |
| `--crawl` | off | Enable URL crawler |
| `--fuzz` | off | Enable parameter fuzzer |
| `--api` | off | Enable API + JS discovery |
| `--smart-wordlist` | off | Generate NLP wordlist |
| `--all` | off | Enable all modules |
| `-w FILE` | built-in | Subdomain wordlist |
| `-p FILE...` | built-in | Payload files |
| `-o FORMAT...` | `json` | Output: `json` `hackerone` `bugcrowd` `intigriti` |
| `--output-dir DIR` | `reports/` | Output directory |
| `--depth N` | `3` | Crawler depth |
| `--rate N` | `50` | Requests/second |
| `--threads N` | `20` | Concurrent workers |
| `--timeout SEC` | `10` | HTTP timeout |
| `--proxy URL` | None | HTTP/SOCKS5 proxy |
| `--dry-run` | off | Simulate without sending requests |
| `-v` | off | Verbose output |

---

## 📁 Project Structure

```
FuzzPhantom/
├── main.py                    # CLI entry point
├── requirements.txt
├── core/
│   ├── context.py             # ScanContext shared dataclass
│   ├── session.py             # Async HTTP session + rate limiter
│   └── logger.py              # Rich-based logger
├── modules/
│   ├── subdomain.py           # Subdomain discovery
│   ├── crawler.py             # URL crawler
│   ├── fuzzer.py              # Parameter fuzzer
│   ├── api_discovery.py       # API + JS analysis
│   └── wordlist_gen.py        # Smart wordlist generator
├── reporting/
│   ├── reporter.py            # Report orchestrator
│   ├── json_export.py
│   └── formats/
│       ├── hackerone.py
│       ├── bugcrowd.py
│       └── intigriti.py
├── wordlists/
│   ├── subdomains.txt         # ~200 subdomain prefixes
│   ├── params.txt             # ~100 parameter names
│   └── api_paths.txt          # ~150 API routes
└── payloads/
    ├── sqli.txt               # 40+ SQL injection payloads
    ├── xss.txt                # 35+ XSS payloads
    ├── lfi.txt                # 40+ LFI/traversal payloads
    └── generic.txt            # SSTI, cmd injection, null bytes
```

---

## 🔌 Extending FuzzPhantom

### Adding Custom Payloads
Simply create a new `.txt` file in `payloads/` and pass it with `-p`:
```bash
python main.py -d example.com --fuzz -p payloads/my_custom.txt
```

### Adding a New Module
1. Create `modules/my_module.py`
2. Implement an `async def run_my_module(ctx: ScanContext) -> None:` function
3. Import and call it in `main.py`'s `run()` function

### Adding a Report Format
1. Create `reporting/formats/my_platform.py`
2. Implement `def export_my_platform(ctx: ScanContext, output_dir: str) -> str:`
3. Register it in `reporting/reporter.py`'s `FORMAT_DISPATCH` dict

---

## ⚠️ Legal Disclaimer

> **FuzzPhantom is intended exclusively for authorized security testing and bug bounty programs.**
> Always obtain explicit written permission before testing any system you do not own.
> The authors accept no liability for misuse of this tool.

---

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.
