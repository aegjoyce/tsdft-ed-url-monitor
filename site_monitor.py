import requests
import hashlib
import json
import os
import re
import difflib
import io
from PyPDF2 import PdfReader
from bs4 import BeautifulSoup
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.exceptions import ReadTimeout

SITES_FILE = "sites.txt"
STATE_FILE = "site_state.json"
DIFF_DIR = "diffs"

# Allow adjusting the per-request timeout via env (seconds)
TIMEOUT = int(os.environ.get("MONITOR_TIMEOUT", "10"))

# Regex to find the first URL on a line (allows labels, bullets or text before URL)
URL_RE = re.compile(r"https?://\S+")

# Keep diffs directory for fallback/local archive, but prefer GitHub issues when configured.
os.makedirs(DIFF_DIR, exist_ok=True)

# requests session with retries/backoff for transient network errors
session = requests.Session()
retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504], allowed_methods=["GET", "HEAD"])
adapter = HTTPAdapter(max_retries=retries)
session.mount("https://", adapter)
session.mount("http://", adapter)

def content_fingerprint(text):
    lines = [
        line for line in text.splitlines()
        if len(line) > 40  # ignore nav/boilerplate fragments
    ]
    return text_hash("\n".join(lines))

def load_sites():
    with open(SITES_FILE) as f:
        sites = []
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = URL_RE.search(line)
            if m:
                sites.append(m.group(0))
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

def extract_main(soup):
    for selector in ("main", "article", "#content", ".content", ".main"):
        node = soup.select_one(selector)
        if node:
            return node
    return soup.body or soup

def clean_text(html):
    soup = BeautifulSoup(html, "html.parser")

    # Remove obvious noise
    for tag in soup(["script", "style", "noscript", "footer", "nav", "aside"]):
        tag.decompose()

    # Heuristics: remove floating/sticky navigation elements that frequently change
    # - Remove elements with inline styles indicating fixed or sticky positioning
    # - Remove elements with class/id/aria-label hints like 'sidebar', 'toc', 'floating-nav'
    # - Remove elements explicitly marked with role="navigation"
    for tag in list(soup.find_all(True)):
        # guard against non-standard elements that may not have attrs set
        attrs = getattr(tag, "attrs", None) or {}
        style = (attrs.get("style") or "").lower()
        classes = " ".join(attrs.get("class") or [])
        ident = " ".join([str(attrs.get("id") or ""), str(attrs.get("aria-label") or "")])

        if "position:fixed" in style or "position:sticky" in style:
            tag.decompose()
            continue

        if re.search(r"\b(sidebar|side-nav|toc|table-of-contents|floating|floating-nav|sticky|site-nav|toc-list|toc-wrapper)\b", classes, re.I):
            tag.decompose()
            continue

        if re.search(r"\b(toc|table-of-contents|sidebar|side-nav|floating|floating-nav)\b", ident, re.I):
            tag.decompose()
            continue

        if attrs.get("role") == "navigation":
            tag.decompose()
            continue

    # --- Remove dynamic NHS "Local Services" blocks ---
    for h in soup.find_all(["h2", "h3"]):
        if h.get_text(strip=True).lower() == "local services":
            for sib in list(h.next_siblings):
                if getattr(sib, "name", None) in ("h2", "h3"):
                    break
                sib.decompose()
            h.decompose()

    root = extract_main(soup)
    text = root.get_text(separator="\n")

    # Normalize line endings and preserve paragraph structure.
    # Collapse repeated spaces within lines but keep newlines so diffs are
    # computed per logical line instead of creating one very long line.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in text.split("\n")]

    # Collapse consecutive empty lines into a single blank line
    normalized_lines = []
    prev_empty = False
    for line in lines:
        if not line:
            if not prev_empty:
                normalized_lines.append("")
            prev_empty = True
        else:
            normalized_lines.append(line)
            prev_empty = False

    text = "\n".join(normalized_lines)

    # Remove times and dates
    text = re.sub(r"\b\d{1,2}:\d{2}(:\d{2})?\b", "", text)
    text = re.sub(r"\b\d{4}-\d{2}-\d{2}\b", "", text)

    # Remove UI counters
    text = re.sub(
        r"\b(page|pages|views|updated|last updated)\s*\d+\b",
        "",
        text,
        flags=re.I
    )

    return text.strip()


def text_hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compact_diff(old_text, new_text, context=2, max_hunks=20):
    """Return a compact diff showing only changed hunks with a small context.

    - `context` lines of context before/after each change are included.
    - `max_hunks` limits the number of hunks shown to avoid enormous issue bodies.
    """
    old_lines = old_text.splitlines()
    new_lines = new_text.splitlines()
    matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines)

    hunks = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        # expand the hunk by the context window, but keep within bounds
        start_old = max(i1 - context, 0)
        end_old = min(i2 + context, len(old_lines))
        start_new = max(j1 - context, 0)
        end_new = min(j2 + context, len(new_lines))

        hunk_old = old_lines[start_old:end_old]
        hunk_new = new_lines[start_new:end_new]
        hunks.append((start_old, end_old, start_new, end_new, hunk_old, hunk_new))
        if len(hunks) >= max_hunks:
            break

    if not hunks:
        return "(no diff)"

    out_lines = []
    for idx, (so, eo, sn, en, h_old, h_new) in enumerate(hunks):
        out_lines.append(f"@@ HUNK {idx+1} (old:{so}-{eo} new:{sn}-{en}) @@")
        # show old (removed) lines
        for i, line in enumerate(h_old, start=so):
            # mark lines that are not present in the new hunk
            if i < (eo - context) and (i < eo and (i - so) < len(h_old)):
                pass
            out_lines.append("- " + line)

        # show new (added) lines
        for j, line in enumerate(h_new, start=sn):
            out_lines.append("+ " + line)

        out_lines.append("")

    if len(hunks) >= max_hunks:
        out_lines.append("... (more changes omitted) ...")

    return "\n".join(out_lines)


def save_diff(url, old, new, final_url=None):
    """Create a GitHub issue containing the unified diff when configured.

    Falls back to saving the diff locally under `DIFF_DIR` if `GITHUB_TOKEN` or
    `GITHUB_REPO` are not set or if the GitHub API call fails.
    Returns either the created issue URL (when posted) or the local filename.
    """
    # Build a compact diff: only changed hunks with a small context window.
    diff_text = compact_diff(old, new, context=2, max_hunks=30)

    gh_token = os.environ.get("GITHUB_TOKEN")
    gh_repo = os.environ.get("GITHUB_REPO") or os.environ.get("GITHUB_REPOSITORY")

    # Optional: mention users so they receive notifications.
    # - `GITHUB_ISSUE_MENTION`: comma-separated GitHub usernames (with or without @)
    mention = os.environ.get("GITHUB_ISSUE_MENTION")

    if gh_token and gh_repo:
        title = f"Website change detected: {url}"
        body = ""
        if mention:
            # Ensure mentions are prefixed with @
            mentions = " ".join([m if m.startswith("@") else f"@{m}" for m in re.split(r"\s*,\s*", mention)])
            body += mentions + "\n\n"

        body += (
            f"Automated monitor detected a change for {url}\n\n"
            f"Checked at: {datetime.utcnow().isoformat()}Z\n"
        )
        if final_url:
            body += f"Final URL: {final_url}\n\n"
        body += "Diff:\n\n```diff\n" + (diff_text or "(no diff)") + "\n```\n"

        payload = {"title": title, "body": body, "labels": ["site-monitor"]}
        headers = {
            "Authorization": f"token {gh_token}",
            "Accept": "application/vnd.github.v3+json",
        }

        try:
            r = requests.post(f"https://api.github.com/repos/{gh_repo}/issues", json=payload, headers=headers, timeout=10)
            if r.status_code in (200, 201):
                data = r.json()
                return data.get("html_url")
            else:
                # Fall back to local file save if API fails
                print(f"⚠️ GitHub API returned {r.status_code}: falling back to local diff save")
        except requests.RequestException as e:
            print(f"⚠️ GitHub API error: {e}; falling back to local diff save")

    # Fallback local save
    safe_name = re.sub(r"[^\w]+", "_", url)
    filename = f"{DIFF_DIR}/{safe_name}_{datetime.utcnow().date()}.diff.txt"
    try:
        with open(filename, "w") as f:
            f.write(diff_text)
    except Exception as e:
        print(f"⚠️ Failed to write local diff file: {e}")

    return filename

def pdf_to_text(url):
    try:
        r = session.get(url, timeout=TIMEOUT)
    except ReadTimeout:
        raise
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
        }

        # Fetch (requests follows redirects by default)
        try:
            r = session.get(url, headers=headers, timeout=TIMEOUT)
        except ReadTimeout:
            return {"status": "ERROR", "error": f"Read timed out (timeout={TIMEOUT})"}
        status = r.status_code
        final_url = r.url

        # Handle HTTP errors early
        if status == 403:
            return {"status": "RESTRICTED", "http_status": status, "final_url": final_url}
        if status in (404, 410):
            return {"status": "NOT_FOUND", "http_status": status, "final_url": final_url}
        if status != 200:
            return {"status": "BROKEN", "http_status": status, "final_url": final_url}

        content_type = r.headers.get("Content-Type", "").lower()

        # ---- Content handling ----

        # PDF
        if "application/pdf" in content_type:
            import io
            from PyPDF2 import PdfReader

            f = io.BytesIO(r.content)
            reader = PdfReader(f)
            cleaned = "\n".join(page.extract_text() or "" for page in reader.pages)

        # HTML
        elif "text/html" in content_type or "application/xhtml+xml" in content_type:
            cleaned = clean_text(r.text)

        # Everything else (Word, Excel, images, zip, etc.)
        else:
            return {
                "status": "BINARY",
                "http_status": status,
                "final_url": final_url,
                "content_type": content_type,
                "hash": None,
                "text": None,
            }

        # ---- Decode sanity check ----
        # If we see lots of replacement characters, decoding went wrong
        if cleaned.count("\ufffd") > 10:
            return {
                "status": "DECODE_ERROR",
                "http_status": status,
                "final_url": final_url,
                "content_type": content_type,
                "hash": None,
                "text": None,
            }

        # ---- Hash + diff ----
        current_hash = content_fingerprint(cleaned)

        changed = False

        if previous and previous.get("hash") and current_hash != previous["hash"]:
            old_text = previous.get("text", "")
            new_text = cleaned

            similarity = difflib.SequenceMatcher(
                None,
                old_text,
                new_text
            ).ratio()

            # Only treat as changed if enough text actually differs
            changed = similarity < 0.985

        diff_file = None
        if changed and previous.get("text"):
            diff_file = save_diff(url, previous["text"], cleaned, final_url=final_url)

        return {
            "status": "OK",
            "http_status": status,
            "hash": current_hash,
            "text": cleaned,
            "changed": changed,
            "diff_file": diff_file,
            "final_url": final_url,
            "content_type": content_type,
        }

    except requests.RequestException as e:
        return {"status": "ERROR", "error": str(e)}
    except Exception as e:
        return {"status": "ERROR", "error": str(e)}



def main():
    sites = load_sites()
    state = load_state()

    print("\n=== Monthly Website Check ===\n")

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
                "content_type": result["content_type"],
            }

        elif result["status"] in (
            "BINARY",
            "DECODE_ERROR",
            "RESTRICTED",
            "BROKEN",
            "NOT_FOUND",
        ):
            print(f"❌ {result['status']}: {url}")
            state[url] = {
                "last_checked": datetime.utcnow().isoformat(),
                "hash": None,
                "text": None,
                "http_status": result.get("http_status"),
                "final_url": result.get("final_url"),
                "content_type": result.get("content_type"),
            }

        else:
            print(f"⚠️ ERROR: {url} → {result.get('error')}")
            state[url] = {
                "last_checked": datetime.utcnow().isoformat(),
                "hash": None,
                "text": None,
                "http_status": None,
                "final_url": None,
                "content_type": None,
            }

    save_state(state)




if __name__ == "__main__":
    main()