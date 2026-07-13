from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class BenchmarkHandler(BaseHTTPRequestHandler):
    server_version = "FuzzPhantomBench/1.0"
    interesting = {
        "/admin": (200, b"admin panel"),
        "/api": (200, b'{"status":"ok"}'),
        "/hidden": (403, b"forbidden"),
        "/redirect": (302, b""),
    }

    def do_GET(self) -> None:
        status, body = self.interesting.get(self.path, (404, b"not found"))
        self.send_response(status)
        if self.path == "/redirect":
            self.send_header("Location", "/admin")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def run_command(command: list[str], cwd: Path) -> tuple[int, float, str]:
    started = time.perf_counter()
    proc = subprocess.run(
        command,
        cwd=str(cwd),
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return proc.returncode, time.perf_counter() - started, proc.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a local FuzzPhantom benchmark target.")
    parser.add_argument("--rate", type=int, default=200)
    parser.add_argument("--threads", type=int, default=40)
    args = parser.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", 0), BenchmarkHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    target = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        wordlist = tmp / "words.txt"
        wordlist.write_text(
            "\n".join(["admin", "api", "hidden", "redirect", "missing", "backup", "login"]),
            encoding="utf-8",
        )
        output_dir = tmp / "reports"

        fp_command = [
            sys.executable,
            "main.py",
            "-d",
            target,
            "--dir",
            "--dir-wordlist",
            str(wordlist),
            "--dir-depth",
            "1",
            "--rate",
            str(args.rate),
            "--threads",
            str(args.threads),
            "--no-calibration",
            "--no-banner",
            "--silent",
            "--output",
            "jsonl",
            "--output-dir",
            str(output_dir),
        ]
        fp_code, fp_elapsed, fp_output = run_command(fp_command, ROOT)
        print(f"FuzzPhantom: exit={fp_code} elapsed={fp_elapsed:.3f}s target={target}")
        if fp_code != 0:
            print(fp_output)

        ffuf_path = shutil.which("ffuf")
        if ffuf_path:
            ffuf_command = [
                ffuf_path,
                "-u",
                f"{target}/FUZZ",
                "-w",
                str(wordlist),
                "-mc",
                "200,302,403",
                "-rate",
                str(args.rate),
                "-t",
                str(args.threads),
                "-s",
            ]
            ffuf_code, ffuf_elapsed, ffuf_output = run_command(ffuf_command, ROOT)
            print(f"ffuf: exit={ffuf_code} elapsed={ffuf_elapsed:.3f}s")
            if ffuf_code != 0:
                print(ffuf_output)
        else:
            print("ffuf: skipped, executable not found on PATH")

    server.shutdown()
    return fp_code


if __name__ == "__main__":
    raise SystemExit(main())
