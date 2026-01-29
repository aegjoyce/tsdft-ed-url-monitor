import requests
import hashlib
import json
import os
import re
import difflib
import io
import requests
from PyPDF2 import PdfReader
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
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            print(f"⚠️ Warning: {STATE_FILE} is corrupted or empty. Creating new baseline.")
            return {}
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

def pdf_to_text(url):
    r = requests.get(url, timeout=TIMEOUT)
    r.raise_for_status()
    f = io.BytesIO(r.content)
    reader = PdfReader(f)
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    return text

def check_site(url, previous):
    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-GB,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }

        # GET request (follows redirects by default)
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        status = r.status_code
        final_url = r.url

        # Handle common HTTP errors
        if status == 403:
            return {"status": "RESTRICTED", "http_status": status, "final_url": final_url}
        elif status in (404, 410):
            return {"status": "NOT_FOUND", "http_status": status, "final_url": final_url}
        elif status != 200:
            return {"status": "BROKEN", "http_status": status, "final_url": final_url}

        # Detect content type
        content_type = r.headers.get("Content-Type", "").lower()

        # PDF handling
        if "application/pdf" in content_type:
            import io
            from PyPDF2 import PdfReader

            f = io.BytesIO(r.content)
            reader = PdfReader(f)
            cleaned = "\n".join(page.extract_text() or "" for page in reader.pages)

        # HTML handling
        elif "text/html" in content_type or "application/xhtml+xml" in content_type:
            cleaned = clean_text(r.text)

        # Unsupported / binary content
        else:
            return {
                "status": "BINARY",
                "http_status": status,
                "final_url": final_url,
                "hash": None,
                "text": None
            }

        # Compute hash
        current_hash = text_hash(cleaned)

        # Check if content changed
        changed = previous and previous.get("hash") and current_hash != previous["hash"]

        # Save diff if previous text exists
        diff_file = None
        if changed and previous.get("text"):
            diff_file = save_diff(url, previous["text"], cleaned)

        return {
            "status": "OK",
            "http_status": status,
            "hash": current_hash,
            "text": cleaned,
            "changed": changed,
            "diff_file": diff_file,
            "final_url": final_url,
            "content_type": content_type
        }

    except requests.RequestException as e:
        return {"status": "ERROR", "error": str(e)}
    except Exception as e:
        return {"status": "ERROR", "error": str(e)}


for url in sites:
    previous = state.get(url)
    result = check_site(url, previous)

    if result["status"] == "OK":
        if result.get("changed"):
            print(f"🔄 CHANGED: {url}")
            if result.get("diff_file"):
                print(f"   ↳ Diff saved to {result['diff_file']}")
        else:
            print(f"✅ NO CHANGE: {url}")

        state[url] = {
            "last_checked": datetime.utcnow().isoformat(),
            "hash": result["hash"],
            "text": result["text"],
            "http_status": result["http_status"],
            "final_url": result["final_url"],
            "content_type": result["content_type"]
        }

    elif result["status"] in ("BINARY", "RESTRICTED", "BROKEN", "NOT_FOUND"):
        print(f"❌ {result['status']}: {url} ({result.get('final_url','')})")
        state[url] = {
            "last_checked": datetime.utcnow().isoformat(),
            "hash": None,
            "text": None,
            "http_status": result.get("http_status"),
            "final_url": result.get("final_url"),
            "content_type": result.get("content_type")
        }

    else:
        # Catch-all for errors
        print(f"⚠️ ERROR: {url} -> {result.get('error')}")
        state[url] = {
            "last_checked": datetime.utcnow().isoformat(),
            "hash": None,
            "text": None,
            "http_status": None,
            "final_url": None,
            "content_type": None
        }

save_state(state)



if __name__ == "__main__":
    main()