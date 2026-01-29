import requests
import hashlib
import json
import os
import re
import difflib
from bs4 import BeautifulSoup
from datetime import datetime

SITES_FILE = "sites.txt"
STATE_FILE = "site_state.json"
DIFF_DIR = "diffs"
TIMEOUT = 10

os.makedirs(DIFF_DIR, exist_ok=True)


def load_sites():
    with open(SITES_FILE) as f:
        sites = []
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            sites.append(line.split("#", 1)[0].strip())
        return sites


def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def clean_text(html):
    soup = BeautifulSoup(html, "html.parser")

    # Remove obvious noise
    for tag in soup(["script", "style", "noscript", "footer", "nav", "aside"]):
        tag.decompose()

    text = soup.get_text(separator="\n")

    # Normalize whitespace
    text = re.sub(r"\s+", " ", text)

    # Remove dates, times, counters (basic but effective)
    text = re.sub(r"\b\d{1,2}:\d{2}\b", "", text)      # times
    text = re.sub(r"\b\d{4}-\d{2}-\d{2}\b", "", text) # ISO dates
    text = re.sub(r"\b\d+\b", "", text)               # numbers

    return text.strip()


def text_hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def save_diff(url, old, new):
    diff = difflib.unified_diff(
        old.splitlines(),
        new.splitlines(),
        fromfile="previous",
        tofile="current",
        lineterm=""
    )

    safe_name = re.sub(r"[^\w]+", "_", url)
    filename = f"{DIFF_DIR}/{safe_name}_{datetime.utcnow().date()}.diff.txt"

    with open(filename, "w") as f:
        f.write("\n".join(diff))

    return filename


def check_site(url, previous):
    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-GB,en;q=0.9",
        }

        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        status = r.status_code

        if status != 200:
            return {"status": "BROKEN", "http_status": status}

        cleaned = clean_text(r.text)
        current_hash = text_hash(cleaned)

        changed = previous and current_hash != previous["hash"]

        diff_file = None
        if changed:
            diff_file = save_diff(url, previous["text"], cleaned)

        return {
            "status": "OK",
            "http_status": status,
            "hash": current_hash,
            "text": cleaned,
            "changed": changed,
            "diff_file": diff_file,
        }

    except requests.RequestException as e:
        return {"status": "ERROR", "error": str(e)}


def main():
    sites = load_sites()
    state = load_state()

    print("\n=== Weekly Website Check ===\n")

    for url in sites:
        previous = state.get(url)
        result = check_site(url, previous)

        if result["status"] == "OK":
            if result.get("changed"):
                print(f"🔄 CHANGED: {url}")
                print(f"   ↳ Diff saved to {result['diff_file']}")
            else:
                print(f"✅ NO CHANGE: {url}")

            state[url] = {
                "last_checked": datetime.utcnow().isoformat(),
                "hash": result["hash"],
                "text": result["text"],
                "http_status": result["http_status"],
            }

        else:
            print(f"❌ {result['status']}: {url}")
            state[url] = {
                "last_checked": datetime.utcnow().isoformat(),
                "hash": None,
                "text": None,
                "http_status": result.get("http_status"),
            }

    save_state(state)


if __name__ == "__main__":
    main()