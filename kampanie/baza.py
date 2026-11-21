"""Our collector's verdicts as campaign materials: each judged domain with its ad, page text, links, servers and IDs.

python baza.py /db/verdicts.db [--limit N]   (read from a copy: the collector's database is never written)
"""
import json
import re
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

import kampanie as k

# who decided: a person in the auditors' panel, the language model, or one of the collector's rules
WHO = {"human": "człowiek", "llm": "model", "rule": "reguła"}


def source(decided_by: str | None, reason: str | None) -> str:
    if decided_by == "human":
        return "human"
    return "llm" if (reason or "").startswith("llm") else "rule"


def material(domain: str, verdict: str, reason: str, decided_by: str | None, raw: str | None) -> k.Material:
    m = k.Material(id=domain, name=domain, origin="baza kolektora")
    try:
        ad = json.loads(raw or "{}")
    except ValueError:
        ad = {}
    m.landing.append(domain)
    for text in (ad.get("ad_creative_bodies") or []) + (ad.get("ad_creative_link_titles") or []):
        if text not in m.text:
            k.add_text(m, text)
    for dom, page in (ad.get("landing") or {}).items():
        if page.lstrip().startswith("<"):
            k.add_html(m, page, url=f"https://{dom}/", source="strona z bazy")
        else:
            k.add_text(m, page)
    for url in (ad.get("links") or {}).values():
        k.add_url(m, url, landing=True)
    for url in ad.get("destinations") or []:
        k.add_url(m, url, landing=True)
    for ids in (ad.get("trackers") or {}).values():
        for t in ids:
            name = re.sub(r"^fb:", "piksel Meta ", re.sub(r"^tt:", "piksel TikTok ", t))
            if not re.search(r"-(X+|0+)(-0)?$", t) and name not in m.trackers:  # GTM-XXXXXX: a template left as is
                m.trackers.append(name)
    for num in (ad.get("number") or {}).values():
        m.trackers.append(f"numer firmy {num}")
    if ad.get("page_id"):  # one Facebook page advertising many domains: one owner
        m.trackers.append(f"strona FB {ad['page_id']}")
    m.ips = sorted({ip for ips in (ad.get("ips") or {}).values() for ip in ips})
    m.ages = {d: a for d, a in (ad.get("age_days") or {}).items() if isinstance(a, int)}
    m.sources.append(f"decyzja w bazie: {verdict}, {WHO[source(decided_by, reason)]}: {reason or 'bez powodu'}")
    return k.finish(m)


def read(path: str, verdicts=("block",), limit: int | None = None) -> list[tuple[str, k.Material]]:
    """[(who decided, material)], the newest decisions first."""
    with tempfile.TemporaryDirectory() as tmp:  # a WAL database on a read-only mount cannot be opened in place
        for suffix in ("", "-wal"):  # shortcut: copied while the collector writes, a torn WAL is possible; then load again
            if Path(path + suffix).is_file():
                shutil.copyfile(path + suffix, Path(tmp) / ("v.db" + suffix))
        db = sqlite3.connect(Path(tmp) / "v.db")
        try:
            rows = db.execute(f"SELECT domain, verdict, reason, decided_by, ad FROM verdicts WHERE verdict IN "
                              f"({','.join('?' * len(verdicts))}) ORDER BY COALESCE(decided_at, seen_at) DESC"
                              + (" LIMIT ?" if limit else ""), (*verdicts, *([limit] if limit else []))).fetchall()
        finally:
            db.close()
    return [(source(r[3], r[2]), material(*r)) for r in rows]


if __name__ == "__main__":
    args = sys.argv[1:]
    limit = int(args[args.index("--limit") + 1]) if "--limit" in args else None
    found = read(args[0], limit=limit)
    print(f"{len(found)} zablokowanych domen z bazy")
