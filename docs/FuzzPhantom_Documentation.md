# FuzzPhantom Professional Documentation

Version: 1.0.0 release candidate  
Audience: security engineers, bug bounty hunters, penetration testers, and maintainers  
Purpose: authorized reconnaissance, URL fuzzing, directory discovery, parameter testing, API discovery, and report generation

## 1. Overview

FuzzPhantom is a modular Python-based offensive security toolkit designed for authorized web application reconnaissance and fuzzing. It combines several workflows commonly handled by tools such as ffuf, DirBuster, assetfinder, subfinder, crawlers, and report generators.

The tool can be used from:

- CLI: fast repeatable scans and automation.
- GUI: visual dashboard, live logs, tabs, reports, and downloadable artifacts.

FuzzPhantom is intended only for systems where you have explicit permission to test.

## 2. Core Goals

FuzzPhantom is designed to:

- Discover subdomains using passive and active methods.
- Crawl web applications and extract URLs, forms, JavaScript, and parameters.
- Brute-force hidden directories and files.
- Fuzz raw HTTP requests using `FUZZ` placeholders.
- Fuzz named placeholders using sniper, pitchfork, and clusterbomb modes.
- Discover API endpoints through JavaScript analysis and route probing.
- Identify interesting response behavior through matchers and filters.
- Generate professional reports in JSON, JSONL, CSV, PDF, and bug bounty formats.
- Support GUI usage for analysts who prefer a visual workflow.

## 3. Architecture

```text
FuzzPhantom/
  main.py                     CLI entry point
  run_gui.py                  GUI launcher
  core/
    context.py                Shared scan context and result storage
    session.py                Async HTTP session, rate limiting, proxy support
    matchers.py               ffuf-style matcher/filter helpers
    raw_request.py            Burp-style raw HTTP request parser
    logger.py                 Rich console logging
  modules/
    subdomain.py              Passive + active subdomain discovery
    crawler.py                Async crawler and JS route extraction
    dir_fuzzer.py             ffuf/DirBuster-style directory/request fuzzer
    fuzzer.py                 Parameter recon fuzzer
    api_discovery.py          API endpoint and JS credential discovery
    wordlist_gen.py           Smart wordlist generation
  reporting/
    reporter.py               Report dispatcher
    json_export.py            JSON export
    flat_exports.py           JSONL and CSV export
    pdf_export.py             Professional PDF report export
    formats/                  HackerOne, Bugcrowd, Intigriti exports
  gui/
    app.py                    FastAPI backend
    scanner.py                GUI scan runner
    static/                   HTML, CSS, JS dashboard
  wordlists/                  Directory, subdomain, API, demo wordlists
  payloads/                   SQLi, XSS, LFI, generic payloads
  tests/                      Regression/unit tests
  scripts/                    Local benchmark harness
```

## 4. Installation

### 4.1 Standard Install

```bash
cd FuzzPhantom
pip install -r requirements.txt
```

### 4.2 Editable Install

This installs the `fuzzphantom` command:

```bash
pip install -e .
```

After install:

```bash
fuzzphantom --help
```

On Windows, if `fuzzphantom` is not found, add Python's user `Scripts` directory to PATH or continue using:

```bash
python main.py --help
```

## 5. CLI Usage

### 5.1 Basic Help

```bash
python main.py --help
python main.py --version
```

### 5.2 Full Scan

```bash
python main.py -d https://example.com --all --output json jsonl csv pdf
```

This enables:

- Subdomain discovery
- Crawling
- Directory fuzzing
- Parameter fuzzing
- API discovery
- Smart wordlist generation

### 5.3 Directory Fuzzing

```bash
python main.py -d https://example.com --dir --dir-wordlist wordlists/directories.txt
```

With extensions:

```bash
python main.py -d https://example.com --dir -e php,txt,bak
```

With mutation:

```bash
python main.py -d https://example.com --dir --mutate-wordlist --mutate-depth 2
```

### 5.4 Polite Scan

```bash
python main.py -d https://example.com --dir --rate 5 --threads 5 --delay 100 --jitter 250
```

### 5.5 Fast Scan

```bash
python main.py -d https://example.com --dir --rate 500 --threads 200
```

Use fast settings only when authorized and appropriate.

### 5.6 Matchers and Filters

Match only selected status codes:

```bash
python main.py -d https://example.com --dir -mc 200,302,403
```

Filter status codes:

```bash
python main.py -d https://example.com --dir -fc 404,500
```

Match by response size:

```bash
python main.py -d https://example.com --dir -ms 1000-5000
```

Filter by body regex:

```bash
python main.py -d https://example.com --dir -fr "not found|invalid"
```

Supported matcher/filter families:

- Status: `-mc`, `-fc`
- Size: `-ms`, `-fs`
- Words: `-mw`, `-fw`
- Lines: `-ml`, `-fl`
- Time: `-mt`, `-ft`
- Body regex: `-mr`, `-fr`
- Header regex: `-mh`, `-fh`
- Content-Type regex: `-mct`, `-fct`

### 5.7 Recursion Control

```bash
python main.py -d https://example.com --dir --dir-depth 2 --recursion-status 200,301-308
```

Only recurse into URLs matching a regex:

```bash
python main.py -d https://example.com --dir --recursion-match "/admin|/api"
```

Skip recursion into selected URLs:

```bash
python main.py -d https://example.com --dir --recursion-filter "logout|delete"
```

### 5.8 Auto-Calibration

Auto-calibration filters soft-404 and catch-all responses.

```bash
python main.py -d https://example.com --dir --calibration-profile strict
```

Profiles:

- `strict`: less tolerant, keeps more edge cases.
- `balanced`: default behavior.
- `relaxed`: more tolerant, filters noisy wildcard responses more aggressively.

Disable calibration:

```bash
python main.py -d https://example.com --dir --no-calibration
```

### 5.9 Resume Support

```bash
python main.py -d https://example.com --dir --resume
```

Custom resume file:

```bash
python main.py -d https://example.com --dir --resume --resume-file reports/example_resume.json
```

### 5.10 Raw Burp Request Fuzzing

Create a file such as `request.txt`:

```http
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=FUZZ
```

Run:

```bash
python main.py --request request.txt --dir-wordlist wordlists/params.txt --output jsonl pdf
```

### 5.11 Named Placeholder Fuzzing

```bash
python main.py --request login.txt -W users.txt:USER -W passwords.txt:PASS --fuzz-mode pitchfork
```

Modes:

- `sniper`: fuzz one placeholder at a time.
- `pitchfork`: pair payloads by index.
- `clusterbomb`: all combinations.

### 5.12 Proxy Support

Proxy all traffic:

```bash
python main.py -d https://example.com --dir --proxy http://127.0.0.1:8080
```

SOCKS proxy:

```bash
python main.py -d https://example.com --dir --proxy socks5://127.0.0.1:9050
```

Replay only confirmed hits:

```bash
python main.py -d https://example.com --dir --replay-proxy http://127.0.0.1:8080
```

### 5.13 Output Formats

```bash
python main.py -d https://example.com --dir --output json jsonl csv pdf hackerone bugcrowd intigriti
```

Supported formats:

- `json`: complete structured data.
- `jsonl`: streaming-friendly line format.
- `csv`: flat automation-friendly table.
- `pdf`: professional executive/technical report.
- `hackerone`: bug bounty markdown report.
- `bugcrowd`: bug bounty markdown report.
- `intigriti`: bug bounty markdown report.

## 6. GUI Usage

Start the GUI:

```bash
python run_gui.py
```

Open:

```text
http://localhost:8080
```

If port 8080 is busy, FuzzPhantom uses the next free port and prints the URL.

### 6.1 Recommended GUI Demo Setup

Target:

```text
http://testfire.net
```

Modules:

- Directory Fuzzer: ON
- Other modules: optional for demo

Advanced settings:

- Rate: `2`
- Threads: `2`
- Dir Depth: `1`
- Dir Wordlist: `wordlists/demo_testfire.txt`
- Match Status: `200,301,302,403`

Report formats:

- JSONL
- CSV
- PDF

Click `Start Scan`.

### 6.2 GUI Tabs

- Overview: severity and high-level scan summary.
- Live Log: streaming scan logs.
- Subdomains: discovered subdomains.
- URLs: crawled URLs.
- Directories: directory fuzzing hits.
- API Endpoints: discovered API endpoints.
- Findings: security findings.
- Reports: generated report files and downloads.

### 6.3 GUI Advanced Controls

The GUI supports:

- Rate
- Threads
- Crawl depth
- Directory depth
- Timeout
- Delay
- Jitter
- Proxy
- Replay proxy
- Directory wordlist
- Extensions
- Match status
- Recursion status
- Calibration profile
- Max hits
- Follow redirects
- Mutate wordlist
- Resume scan

## 7. Module Details

### 7.1 Subdomain Discovery

Subdomain discovery includes:

- Certificate Transparency via crt.sh.
- HackerTarget host search.
- AlienVault OTX passive DNS.
- RapidDNS passive scraping.
- DNS brute-force.
- DNS zone transfer checks.

The module normalizes full GUI/CLI URLs such as:

```text
https://www.example.com/path
```

into:

```text
example.com
```

This prevents invalid brute-force attempts against full URLs.

### 7.2 URL Crawler

The crawler:

- Performs async BFS crawling.
- Extracts links.
- Extracts form actions and input names.
- Finds parameterized URLs.
- Finds JavaScript files.
- Extracts JavaScript routes.
- Keeps crawling within the registered root domain.
- Handles redirects and path-scoped targets.

### 7.3 Directory Fuzzer

The directory fuzzer supports:

- Async workers.
- Rate limiting.
- Extensions.
- Recursive fuzzing.
- Auto-calibration.
- Matchers and filters.
- Live ffuf-style rows.
- Resume state.
- Stop limits.
- Replay proxy.
- Wordlist mutation.
- Context-learned words from crawled URLs/API endpoints.

### 7.4 Parameter Fuzzer

The parameter fuzzer:

- Tests existing parameterized URLs.
- Generates synthetic hidden-parameter candidates when needed.
- Uses canary values to identify reflection.
- Detects status-code behavior deltas.
- Caps synthetic probing to avoid runaway scans.

### 7.5 API Discovery

API discovery:

- Analyzes JavaScript files.
- Extracts fetch, axios, XHR, and route-like strings.
- Probes common API paths.
- Detects potential credentials in JavaScript.
- Adds endpoints to the API tab and reports.

### 7.6 Smart Wordlist

Smart wordlist generation:

- Uses crawled text.
- Extracts meaningful terms.
- Builds target-specific wordlist candidates.
- Feeds better discovery in later scans.

## 8. Professional PDF Report

PDF reporting is designed for professional handoff.

Generate a PDF:

```bash
python main.py -d https://example.com --dir --output pdf
```

The PDF includes:

- Cover header with target and generation time.
- Summary metric cards.
- Severity distribution.
- Executive overview.
- Priority findings.
- Discovered subdomains.
- Crawled URLs.
- Parameterized URLs.
- API endpoints.
- JavaScript files.
- Methodology snapshot.
- Recommended next actions.
- Page numbers and footer.

In the GUI, select `PDF` under Report Formats before starting a scan.

## 9. Testing and Validation

Run compile checks:

```bash
python -m compileall core modules gui reporting main.py tests scripts
```

Run tests:

```bash
python -m pytest -q
```

Run local benchmark:

```bash
python scripts/local_benchmark.py
```

## 10. Demo Targets

Use only intentionally vulnerable/demo targets or targets where you have permission.

Known demo:

```bash
python main.py -d http://testfire.net --dir --dir-wordlist wordlists/demo_testfire.txt --dir-depth 1 --rate 2 --threads 2 --no-calibration --output jsonl csv pdf --match-status 200,301,302,403
```

## 11. Performance Guidance

For speed:

```bash
python main.py -d https://example.com --dir --rate 500 --threads 200
```

For safety:

```bash
python main.py -d https://example.com --dir --rate 5 --threads 5 --delay 100 --jitter 250
```

For noisy wildcard targets:

```bash
python main.py -d https://example.com --dir --calibration-profile relaxed
```

For deeper discovery:

```bash
python main.py -d https://example.com --crawl --dir --mutate-wordlist --mutate-depth 2 --dir-depth 2
```

## 12. Security and Legal Usage

FuzzPhantom must only be used:

- On systems you own.
- On systems where you have explicit written authorization.
- Inside bug bounty program scope.
- In lab or training environments.

Do not use this tool for unauthorized scanning.

## 13. Troubleshooting

### GUI shows counts but empty tab

Hard refresh the browser:

```text
Ctrl + F5
```

Restart GUI:

```bash
python run_gui.py
```

### PDF option does not work

Install dependencies:

```bash
pip install reportlab
```

### `fuzzphantom` command not found

Use:

```bash
python main.py
```

Or install editable:

```bash
pip install -e .
```

Then add Python Scripts directory to PATH.

### Subdomains not found

Try:

```bash
python main.py -d https://www.example.com --subdomains --threads 200 --timeout 5
```

Subdomain discovery depends on:

- Passive source availability.
- DNS resolver behavior.
- Target's public DNS footprint.
- Network access from your machine.

### Scan too slow

Increase:

```bash
--rate
--threads
```

Reduce:

```bash
--delay
--jitter
--dir-depth
```

Use narrower wordlists for first pass.

## 14. Release Checklist

Before releasing:

1. Run compile checks.
2. Run tests.
3. Run local benchmark.
4. Run GUI smoke test.
5. Generate JSON, JSONL, CSV, and PDF reports.
6. Verify reports download from GUI.
7. Verify `python main.py --help`.
8. Verify `python run_gui.py`.
9. Commit and push to GitHub.

