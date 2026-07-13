import urllib.request
import os
from pathlib import Path

# Trusted URLs from Daniel Miessler's SecLists (GitHub)
WORDLISTS = {
    "subdomains.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
    "directories.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
}

def bootstrap():
    wordlist_dir = Path(__file__).parent
    print(f"[*] Bootstrapping high-quality wordlists into {wordlist_dir.resolve()}...\n")
    
    for filename, url in WORDLISTS.items():
        dest = wordlist_dir / filename
        print(f"[+] Downloading {filename} from {url}...")
        try:
            # Override user-agent to avoid raw.githubusercontent UA blocking
            req = urllib.request.Request(
                url, 
                headers={"User-Agent": "Mozilla/5.0 FuzzPhantom Bootstrapper"}
            )
            with urllib.request.urlopen(req) as response:
                data = response.read()
                
            # Backup original if it exists and isn't already upgraded
            if dest.exists() and dest.stat().st_size < len(data):
                backup_path = dest.with_suffix(".txt.bak")
                if not backup_path.exists():
                    try:
                        dest.rename(backup_path)
                        print(f"    [i] Backed up original {filename} to {backup_path.name}")
                    except Exception:
                        pass
                    
            with open(dest, "wb") as f:
                f.write(data)
            print(f"[V] Successfully downloaded {filename} ({len(data)} bytes, {len(data.split(b'\n'))} entries)\n")
        except Exception as e:
            print(f"[X] Failed to download {filename}: {e}\n")

if __name__ == "__main__":
    bootstrap()
