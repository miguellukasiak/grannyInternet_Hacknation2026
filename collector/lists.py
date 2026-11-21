"""Blocklist updater: many free lists -> one SQLite base with provenance -> Blocky files per package.

Every source refreshes on its own schedule. A failed download or a list that suddenly shrinks keeps
the previous copy, so a broken upstream never silently unblocks anything.

Each package is written in two parts: pkg-<name>.txt and pkg-<name>-top.txt. The -top part holds the
entries that hit one of the N most popular sites (safe_top in sources.toml), so a mode decides whether
it blocks them. Sites are split by the Public Suffix List: phish.github.io is its own site, not GitHub.
"""

import concurrent.futures
import hashlib
import re
import sqlite3
import time
import tomllib
import urllib.request
from pathlib import Path

from collector import BLOCKY, extract, popular_domains

CONFIG = Path("/config/sources.toml")
DATA = Path("/data")
TICK_SECONDS = 30
MIN_KEEP = 0.5  # a source shrinking below half of its last size is treated as broken...
STRIKES = 3  # ...unless it stays that small for this many fetches in a row

BLOCK_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1"}
HOST = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)+")
ADBLOCK = re.compile(r"\|\|([a-z0-9_.-]+)\^(?:\$[a-z0-9,_-]*)?")  # whole-domain rules only: no paths, no page scopes
COMMENT = re.compile(r"(?:^|\s)#.*")  # needs whitespace before "#", so cosmetic "site##.ad" rules get rejected

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (name TEXT PRIMARY KEY, package TEXT, fetched_at REAL DEFAULT 0,
                                    size INT DEFAULT 0, digest TEXT, strikes INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS entries (source TEXT, domain TEXT, site TEXT, PRIMARY KEY (source, domain)) WITHOUT ROWID;
"""


def parse(text: str) -> dict[str, str]:
    """{domain: site} from hosts, plain, wildcard (*.x) and adblock (||x^) lists. Anything else is ignored."""
    found = {}
    for line in text.lower().splitlines():
        if m := ADBLOCK.fullmatch(line.strip()):
            tokens = [m[1]]
        else:
            tokens = COMMENT.sub("", line).split()
            if len(tokens) > 1 and tokens[0] in BLOCK_IPS:
                tokens = tokens[1:]
            elif len(tokens) != 1:
                continue
        for token in tokens:
            domain = token.removeprefix("*.")
            if not HOST.fullmatch(domain):
                continue
            parts = extract(domain)
            # TLDs like "pl" or "com.pl" and bare IPs would cut off whole countries; platforms like github.io stay
            if parts.top_domain_under_public_suffix or parts.is_private:
                found[domain] = parts.top_domain_under_public_suffix or domain
    return found


def fetch(source: dict, known_digest: str | None) -> tuple[str, str, dict[str, str] | None, str]:
    """(name, digest, {domain: site} or None if unchanged, error)."""
    request = urllib.request.Request(source["url"], headers={"User-Agent": "scam-dns-lists"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            text = response.read().decode("utf-8", "replace")
    except (OSError, ValueError) as e:
        return source["name"], "", None, str(e)
    digest = hashlib.sha256(text.encode()).hexdigest()
    return source["name"], digest, None if digest == known_digest else parse(text), ""


def save(db: sqlite3.Connection, name: str, digest: str, domains: dict[str, str] | None, error: str) -> bool:
    """Store a fresh copy of a source. Returns True when the stored domains changed."""
    size, strikes = db.execute("SELECT size, strikes FROM sources WHERE name = ?", (name,)).fetchone()
    now = time.time()
    if error or domains is None:  # failed (keep previous copy) or unchanged since last fetch
        db.execute("UPDATE sources SET fetched_at = ? WHERE name = ?", (now, name))
        db.commit()
        if error:
            print(f"{name}: keeping previous copy ({error})")
        return False
    if size and len(domains) < size * MIN_KEEP and strikes + 1 < STRIKES:
        db.execute("UPDATE sources SET fetched_at = ?, strikes = ? WHERE name = ?", (now, strikes + 1, name))
        db.commit()
        print(f"{name}: keeping previous copy (shrank from {size} to {len(domains)}, strike {strikes + 1})")
        return False
    with db:
        db.execute("DELETE FROM entries WHERE source = ?", (name,))
        db.executemany("INSERT INTO entries VALUES (?, ?, ?)", ((name, d, s) for d, s in domains.items()))
        db.execute("UPDATE sources SET fetched_at = ?, size = ?, digest = ?, strikes = 0 WHERE name = ?",
                   (now, len(domains), digest, name))
    print(f"{name}: {len(domains)} domains")
    return True


def sync(db: sqlite3.Connection, sources: list[dict]) -> None:
    """Make the base match sources.toml: new sources are added, removed or disabled ones are dropped."""
    names = [s["name"] for s in sources]
    marks = ",".join("?" * len(names))
    with db:
        db.executemany("INSERT INTO sources (name, package) VALUES (?, ?) "
                       "ON CONFLICT (name) DO UPDATE SET package = excluded.package",
                       [(s["name"], s["package"]) for s in sources])
        db.execute(f"DELETE FROM entries WHERE source NOT IN ({marks})", names)
        db.execute(f"DELETE FROM sources WHERE name NOT IN ({marks})", names)


def write_atomic(path: Path, content: str) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)  # Blocky never reads a half-written file


def export(db: sqlite3.Connection, packages: set[str], top: set[str]) -> None:
    for package in sorted(packages):
        rows = db.execute("SELECT DISTINCT domain, site FROM entries JOIN sources ON name = source "
                          "WHERE package = ? ORDER BY domain", (package,)).fetchall()
        hits = [domain for domain, site in rows if site in top]
        rest = [domain for domain, site in rows if site not in top]
        write_atomic(DATA / f"pkg-{package}.txt", "".join(f"*.{d}\n" for d in rest))
        write_atomic(DATA / f"pkg-{package}-top.txt", "".join(f"*.{d}\n" for d in hits))
        print(f"package {package}: {len(rest)} domains + {len(hits)} on top sites")


def refresh_blocky() -> None:
    try:
        urllib.request.urlopen(urllib.request.Request(f"{BLOCKY}/api/lists/refresh", method="POST"), timeout=300).close()
    except OSError as e:  # Blocky not up yet: it reads the files when it starts
        print(f"blocky refresh skipped ({e})")


def main() -> None:
    DATA.mkdir(exist_ok=True)
    db = sqlite3.connect(DATA / "lists.db")
    db.executescript(SCHEMA)
    seen_config, top, top_at = "", set(), 0.0
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        while True:
            text = CONFIG.read_text(encoding="utf-8")
            config = tomllib.loads(text)
            sources = [s for s in config["source"] if s.get("enabled", True)]
            package_of = {s["name"]: s["package"] for s in sources}
            every_package = {s["package"] for s in config["source"]}  # each gets files, even if empty
            dirty = set()
            if text != seen_config:  # sources added, removed, moved between packages or safe_top changed
                sync(db, sources)
                seen_config, top_at, dirty = text, 0.0, every_package
            if BLOCKY and time.time() - top_at > 24 * 3600:  # the top sites only split the package files
                try:
                    fresh = popular_domains(config["safe_top"])
                    top_at, dirty = time.time(), dirty | (every_package if fresh != top else set())
                    top = fresh
                except OSError as e:
                    print(f"tranco: keeping previous top sites ({e})")

            fetched = dict(db.execute("SELECT name, fetched_at FROM sources"))
            digests = dict(db.execute("SELECT name, digest FROM sources"))
            due = [s for s in sources if time.time() - fetched[s["name"]] >= s["every"] * 60]
            for name, digest, domains, error in pool.map(lambda s: fetch(s, digests[s["name"]]), due):
                if save(db, name, digest, domains, error):
                    dirty.add(package_of[name])

            if dirty and (top or not BLOCKY):  # without the top sites the split is impossible: wait, don't over-block
                if BLOCKY:  # the server has no DNS: its panel reads only lists.db, home's lists writes home's files
                    export(db, dirty, top)
                    refresh_blocky()
                (DATA / "ready").touch()
            time.sleep(TICK_SECONDS)


if __name__ == "__main__":
    main()
