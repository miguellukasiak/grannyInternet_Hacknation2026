"""Home's relay for a collector on a server: the LLM on home's card.

The server reaches it only through an SSH tunnel opened from home (nothing listens on home's router), and every
question carries HOME_TOKEN. Only what judge() needs passes: the model's chat and tags. NASK is asked by the server
itself: one address, never home's too.
The same tunnel brings the server's panel to home (SERVER_PANEL): home's DNS copies its lists every minute.
"""
import hmac
import json
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import collector as c

TOKEN = os.getenv("HOME_TOKEN") or ""
FORWARDED = {("POST", "/api/chat"), ("GET", "/api/tags")}  # never pull, delete or create a model
MAX_BODY = 1_000_000  # an ad, its page and its facts are under 30 kB
SERVER_PANEL = os.getenv("SERVER_PANEL", "http://host.docker.internal:8081")  # the tunnel's -L end on home's PC


def sync() -> bool:
    """Copies the server's lists into home's lists/; True when one changed (then Blocky reloads)."""
    with urllib.request.urlopen(f"{SERVER_PANEL}/api/lists", timeout=30) as response:
        lists = json.load(response)
    changed = False
    for name in c.SERVED:
        text, target = lists.get(name), c.LISTS / name
        old = target.read_text(encoding="utf-8") if target.exists() else ""
        if not isinstance(text, str) or text == old or (old.strip() and not text.strip()):
            continue  # an empty list from a broken server never unblocks home
        tmp = target.with_suffix(".tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(target)  # atomic: Blocky never reads half a list
        changed = True
    return changed


def syncing() -> None:
    while True:
        try:
            if sync():
                c.reload_blocky()
                print("lists from the server")
        except (OSError, ValueError):  # tunnel down: home's DNS keeps the last lists
            pass
        time.sleep(60)


class Relay(BaseHTTPRequestHandler):
    def answer(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def allowed(self) -> bool:
        if hmac.compare_digest(self.headers.get("Authorization", "").encode(), f"Bearer {TOKEN}".encode()):
            return True
        self.answer(401, b'{"error": "token"}')
        return False

    def forward(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            return self.answer(413, b'{"error": "too big"}')
        body = self.rfile.read(length) if length else None
        request = urllib.request.Request(f"{c.OLLAMA}{self.path}", body, {"Content-Type": "application/json"},
                                         method=method)
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                self.answer(response.status, response.read())
        except urllib.error.HTTPError as e:
            self.answer(e.code, e.read())
        except OSError as e:  # Ollama not started yet
            self.answer(502, json.dumps({"error": str(e)}).encode())

    def do_POST(self) -> None:
        if self.allowed():
            self.forward("POST") if ("POST", self.path) in FORWARDED else self.answer(404, b"{}")

    def do_GET(self) -> None:
        if self.allowed():
            self.forward("GET") if ("GET", self.path) in FORWARDED else self.answer(404, b"{}")

    def log_message(self, *args) -> None:  # every question would go to the log: domains only, nothing to keep
        pass


def main() -> None:
    if c.HOME:
        raise SystemExit("HOME_URL is set here: this is the server's setting, home's relay talks to Ollama itself")
    if len(TOKEN) < 32 or not c.OLLAMA:
        raise SystemExit("home.py needs HOME_TOKEN (at least 32 characters) and OLLAMA_URL in .env")
    print(f"home relay on :8765, model at {c.OLLAMA}, lists from {SERVER_PANEL}")
    threading.Thread(target=syncing, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8765), Relay).serve_forever()


if __name__ == "__main__":
    main()
