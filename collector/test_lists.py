"""Self-check of the list updater (no network): python test_lists.py"""

import sqlite3
import tempfile
from pathlib import Path

import lists
from lists import export, parse, save, sync

sample = """
! Title: adblock header
[Adblock Plus 2.0]
||ads.example.com^
||tracker.example.net^$third-party
||example.org/banner/*
example.com##.sponsored
@@||good.example.com^
0.0.0.0 hosts-entry.example.com  # comment
127.0.0.1 localhost
0.0.0.0 0.0.0.0
*.wild.example.com
plain.example.com
1.2.3.4
com.pl
pl
"""
assert set(parse(sample)) == {
    "ads.example.com", "tracker.example.net", "hosts-entry.example.com", "wild.example.com", "plain.example.com",
}, parse(sample)
assert parse("ads.google.com\nphish.github.io\ngithub.io\n") == {
    "ads.google.com": "google.com", "phish.github.io": "phish.github.io", "github.io": "github.io"}


def entries(*domains: str) -> dict[str, str]:
    return {d: lists.extract(d).top_domain_under_public_suffix or d for d in domains}


db = sqlite3.connect(":memory:")
db.executescript(lists.SCHEMA)
sync(db, [{"name": "a", "package": "reklamy"}, {"name": "b", "package": "reklamy"}, {"name": "c", "package": "scam"}])

many = entries(*(f"d{i}.example.com" for i in range(10)))
assert save(db, "a", "h1", many, "")
assert not save(db, "a", "h1", None, "")  # unchanged digest
assert not save(db, "a", "", None, "HTTP Error 404")  # failed download keeps the copy
assert not save(db, "a", "h2", entries("d0.example.com"), "")  # shrank 10 -> 1: strike 1
assert not save(db, "a", "h2", entries("d0.example.com"), "")  # strike 2
assert save(db, "a", "h2", entries("d0.example.com", "ads.google.com", "github.io"), "")  # third time: accepted
assert db.execute("SELECT count(*) FROM entries WHERE source = 'a'").fetchone() == (3,)

save(db, "b", "x", entries("d0.example.com", "phish.github.io"), "")
save(db, "c", "y", entries("scam.example.com"), "")
lists.DATA = Path(tempfile.mkdtemp())
export(db, {"reklamy", "scam"}, top={"google.com", "github.io"})
read = lambda name: (lists.DATA / name).read_text().split()
assert read("pkg-reklamy.txt") == ["*.d0.example.com", "*.phish.github.io"]  # deduplicated, GitHub tenant stays
assert read("pkg-reklamy-top.txt") == ["*.ads.google.com", "*.github.io"]  # only ultra blocks these
assert read("pkg-scam.txt") == ["*.scam.example.com"] and read("pkg-scam-top.txt") == []

sync(db, [{"name": "a", "package": "reklamy"}])  # b and c removed from sources.toml
assert db.execute("SELECT DISTINCT source FROM entries").fetchall() == [("a",)]

print("ok")
