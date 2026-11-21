"""Decision panel for the review queue: a local page where a human blocks, passes or marks domains as doubtful.

python panel.py, then http://127.0.0.1:8080. Decisions go straight to verdicts.db (the verdicts volume), watpliwe.txt
and Blocky.

Auditors reach it through the Cloudflare tunnel under PANEL_PUBLIC: they sign up on /login, wait for the owner's
approval (on /konta in the owner's panel, or python panel.py audytorzy | zatwierdz <login> | usun <login>) and then decide on the cards like the owner.
The server's own tools (lists, metrics, exceptions, CERT reports) stay local. Anyone may send a suspect site on
/zglos, behind Cloudflare Turnstile; auditors read them on /api/suspects.
"""

import difflib
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import urllib.parse
import urllib.request
from contextlib import closing
from datetime import datetime, timedelta, timezone
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from zoneinfo import ZoneInfo

import collector

PAGE = Path(__file__).with_name("panel.html")
LOGIN_PAGE = Path(__file__).with_name("login.html")
PUBLIC = os.getenv("PANEL_PUBLIC", "")  # the panel's name behind the Cloudflare tunnel; empty: local only
OWNER_ONLY = {"/api/allow", "/api/reported", "/api/account", "/api/remark-done"}  # POSTs never taken through the tunnel
LOCAL_ONLY = {"/api/recent", "/api/lists", "/metrics", "/konta", "/api/accounts"}  # GETs never served through the tunnel
ACCOUNTS_PAGE = Path(__file__).with_name("accounts.html")
ACCOUNT = {"/api/signup", "/api/login", "/api/logout"}  # through the tunnel only
# a logged-in auditor's own, through the tunnel only
MINE = {"/api/batch", "/api/release", "/api/password", "/api/forget", "/api/remark", "/api/name", "/api/seen"}
# Auditors see only their batch: domains to review taken for LEASE, which no one else may decide meanwhile
LEASE = timedelta(hours=2)
BATCH_MAX = 50
GONE = "usunięte konto"  # history's who after an auditor deleted their account: no e-mail left behind
REPORT_PAGE = Path(__file__).with_name("report.html")
APPEAL_PAGE = Path(__file__).with_name("appeal.html")
LANDING = {"https://grannyinternet.me", "https://jury.grannyinternet.me"}  # the only pages allowed to read /api/liczby
TURNSTILE_SITE, TURNSTILE_SECRET = os.getenv("TURNSTILE_SITE", ""), os.getenv("TURNSTILE_SECRET", "")
# mail through Resend (free: 100 a day); no key, no mail. The sender's domain is verified there by DNS records.
RESEND_KEY, MAIL_FROM = os.getenv("RESEND_KEY", ""), os.getenv("MAIL_FROM", "Granny Internet <noreply@grannyinternet.me>")
MAIL_REPLY_TO = os.getenv("MAIL_REPLY_TO", "")  # where an auditor's answer goes; only in .env, never in git
SIGN = "\n\nGranny Internet\nhttps://grannyinternet.me"
MAILS = {  # subject and text; the owner's answers are only starting points, edited on /konta before sending
    "received": ("Otrzymaliśmy Twoje zgłoszenie", "Dzień dobry,\n\notrzymaliśmy Twoje zgłoszenie na audytora Granny "
                 "Internet. Odpowiemy w ciągu doby.\n\nJeśli to nie Ty, zignoruj tę wiadomość: bez naszej akceptacji "
                 "konto nie zadziała." + SIGN),
    "approve": ("Twoje konto audytora działa", "Dzień dobry,\n\nTwoje konto audytora zostało zatwierdzone. Zaloguj "
                "się na https://panel.example.org/login tym e-mailem i hasłem podanym przy zgłoszeniu.\n\n"
                "Dziękujemy za pomoc!" + SIGN),
    "reject": ("Twoje zgłoszenie na audytora", "Dzień dobry,\n\ndziękujemy za zgłoszenie. Na razie nie możemy "
               "przyznać Ci konta audytora." + SIGN),
    "appeal": ("Otrzymaliśmy Twoje odwołanie", "Dzień dobry,\n\notrzymaliśmy odwołanie od blokady strony. Sprawdzimy "
               "ją jeszcze raz i odpowiemy na ten adres.\n\nJeśli to nie Ty, zignoruj tę wiadomość." + SIGN),
}
SUSPECTS_A_DAY = 500  # all reporters together: a flood fills no disk
# a site owner's appeal is a remark starting with this, so it reaches the owner's "uwagi" tab with the card
APPEAL = "Odwołanie od blokady: "
APPEALS_A_DAY = 50  # each sends a confirmation, and Resend gives 100 a day
# Placeholder values: the ledger keeps each entry's kind, so totals can be recounted when the real rules come.
POINTS = {"decision": 1, "suspect": 1, "training": 5}
RANKS = [(0, "nowicjusz")]  # (from points, name), lowest first; the real ladder comes with the ranking
# (id, group, how many, name, what for): how many of the group's decisions (distinct domains) or finished trainings;
# None: a secret or the pioneer, each tested in earn(). A secret's name and reason stay hidden until earned.
BADGES = [
    ("pass-1", "pass", 1, "Otwieracz Drzwi", "pierwsza przepuszczona strona"),
    ("pass-50", "pass", 50, "Dobry Odźwierny", "50 przepuszczonych stron"),
    ("pass-100", "pass", 100, "Strażnik Bramy", "100 przepuszczonych stron"),
    ("pass-500", "pass", 500, "Klucznik Królestwa", "500 przepuszczonych stron"),
    ("pass-1000", "pass", 1000, "Mistrz Mostu Zwodzonego", "1000 przepuszczonych stron"),
    ("pass-secret", "pass", None, "Telefon do Przyjaciela", "strona przepuszczona po sprawdzeniu poza nią: telefonem albo w rejestrze"),
    ("doubtful-1", "doubtful", 1, "Uniesiona Brew", "pierwsza strona oznaczona jako wątpliwa"),
    ("doubtful-50", "doubtful", 50, "Sceptyk z Zasadami", "50 stron oznaczonych jako wątpliwe"),
    ("doubtful-100", "doubtful", 100, "Detektyw we Mgle", "100 stron oznaczonych jako wątpliwe"),
    ("doubtful-500", "doubtful", 500, "Inspektor Lupa", "500 stron oznaczonych jako wątpliwe"),
    ("doubtful-1000", "doubtful", 1000, "Wielki Mistrz Wątpliwości", "1000 stron oznaczonych jako wątpliwe"),
    ("doubtful-secret", "doubtful", None, "Nocny Marek", "strona oznaczona jako wątpliwa między północą a piątą rano"),
    ("block-1", "block", 1, "Pierwszy Szlaban", "pierwsza zablokowana strona"),
    ("block-50", "block", 50, "Pogromca Naciągaczy", "50 zablokowanych stron"),
    ("block-100", "block", 100, "Łowca Oszustów", "100 zablokowanych stron"),
    ("block-500", "block", 500, "Tarcza Babci", "500 zablokowanych stron"),
    ("block-1000", "block", 1000, "Postrach Scamerów", "1000 zablokowanych stron"),
    ("block-secret", "block", None, "Piorun Kulisty", "10 blokad w ciągu 10 minut"),
    ("training-1", "training", 1, "Pilny Uczeń", "pierwsze ukończone szkolenie"),
    ("training-5", "training", 5, "Prymus", "5 ukończonych szkoleń"),
    ("training-10", "training", 10, "Profesor Internetu", "10 ukończonych szkoleń"),
    ("pioneer", "pioneer", None, "Pionier 2026", "konto audytora założone w 2026, pierwszym roku Granny Internet"),
]
WARSAW = ZoneInfo("Europe/Warsaw")
# a public name instead of the e-mail, which other auditors never see: "Czujna Sowa 42" until they pick their own
NAME = re.compile(r"[A-Za-z0-9ĄĆĘŁŃÓŚŹŻąćęłńóśźż][A-Za-z0-9ĄĆĘŁŃÓŚŹŻąćęłńóśźż _.-]{1,22}[A-Za-z0-9ĄĆĘŁŃÓŚŹŻąćęłńóśźż]")
ANIMALS = [("Sowa", 1), ("Wiewiórka", 1), ("Kuna", 1), ("Sarna", 1), ("Pszczoła", 1), ("Wydra", 1),
           ("Borsuk", 0), ("Jeż", 0), ("Lis", 0), ("Bóbr", 0), ("Ryś", 0), ("Sokół", 0), ("Żubr", 0), ("Puchacz", 0)]
TRAITS = [("Czujny", "Czujna"), ("Bystry", "Bystra"), ("Rozważny", "Rozważna"), ("Sprytny", "Sprytna"),
          ("Uważny", "Uważna"), ("Dzielny", "Dzielna"), ("Cichy", "Cicha"), ("Rączy", "Rącza")]
COOKIE = "__Host-sesja"  # __Host-: only over HTTPS, only for this name, no subdomain can set it
SESSION = timedelta(days=14)
# letters, digits and ._%+- only: no quotes, brackets, commas or "?" to break a mailto: link or a mail header
EMAIL = re.compile(r"[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,190}\.[a-z]{2,24}")
# control and invisible characters out of anything typed: no hidden text, no right-to-left trick in the owner's view
HIDDEN = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
SIGNUP_NOTE, REMARK_NOTE, APPEAL_NOTE = 1000, 2000, 2000
URL_MAX = 2048  # the longest link that works everywhere (sitemaps, old browsers); a domain itself is at most 253

WAITING_MAX = 30  # sign-ups waiting for approval; more is a flood, not auditors
VIEWS = {  # tab -> verdicts shown, newest first
    "review": "review",  # waiting for a human
    "block": "block",  # spot check of what the collector blocked
    "doubtful": "doubtful",
    "cert": "block",  # blocks to report to CERT Polska, see cert_queue()
    "sample": None,  # the collector's own blocks and passes, see cards()
    "remarks": None,  # auditors' technical notes, each with its card as they saw it, see remark()
}
DECISIONS = {"block", "pass", "doubtful", "review", "verified"}  # review = back to the queue (undo)
STRICT = {"block": 2, "doubtful": 1}  # anything else lets the site through: pass, verified, review
DECIDING = threading.Lock()  # one decision at a time: the check, the row and watpliwe.txt together
URL = re.compile(r"https?://[^\s;\"']+")
COLUMNS = "domain, verdict, score, reason, ad_id, page, seen_at, ad, decided_by, decided_at"
UNSEEN = "verdict IN ('block', 'pass') AND decided_by IS NULL"  # the collector decided, no human looked
SAMPLE = 50  # cards in one sample batch
LISTS_DB = Path("/data/lists.db")  # the lists service's base: which source list holds a domain
CERT_SOURCE = "cert"  # hole.cert.pl in sources.toml: what is there already needs no report
CERT_BATCH = 50  # the most domains one report on incydent.cert.pl takes
# Automatic blocks sure enough to report without a human: the rest (llm, no company named) need a B in the panel first.
# Not "no website": a domain without an address has nothing for CERT to block.
# The domain a scam ad shows but does not open: its victim, the scam is where the ad leads (reported on its own)
VICTIM = re.compile(r"the ad shows ")
# Proof in the domain's own infrastructure, enough for CERT on an old domain too: a decoy, a copied page, a NIP shared
INFRA = re.compile(r"^(?:decoy: (?!no website)|same page as)|the same number as on")
STRONG = re.compile(r"^(?:decoy: (?!no website)|same ad as|same page as|NIP|VAT|KRS|REGON|hidden behind the caption|FB page)")
# A sign of fraud in the reason: the queue shows these first. Old firms only missing proof of a company (lee.com,
# agatameble.pl) go last: popularity alone does not clear them, humans held webinarjam.com and dramabox.com doubtful.
WARNING = re.compile(r"^llm(?! passed it)|leads to|hidden behind the caption|(?:NIP|VAT|KRS|REGON) [A-Z]{0,2}\d|same server|same tracking|named like"
                     r"|Polish name|FB page|health|quiz|decoy|dead page|closing-down|words like blocked")
# Reasons humans nearly always passed, shown after everything else (blocked or doubtful of decided: "llm passed it
# but wrote" 12 of 39, a named company "the model claimed none" 4 of 17, bot check 0 of 6, social icons 0 of 1)
# Host names the panel answers to, with any port: the browser here or through the tunnel, Prometheus, home.py
LOCAL_NAMES = {"127.0.0.1", "localhost", "panel", "host.docker.internal"}
NOISE = re.compile(r"^llm passed it but wrote|the model claimed none|bot check|social icons lead nowhere")


def urgency(card: dict) -> int:
    """The review queue's group: signs of fraud, then young or unknown-age domains, then old ones, then the noise."""
    if WARNING.search(card["reason"]):
        return 0
    if NOISE.search(card["reason"]):
        return 3
    return 1 if not isinstance(card["age_days"], int) or card["age_days"] <= collector.ESTABLISHED_DAYS else 2


_numbers: dict[tuple, tuple] = {}  # (domain, seen_at, reason, stored number) -> (company number, the site's KRS): 3 s a tab when searched each time
_shots: set[str] = set()  # screenshot names, see read_shots()


def read_shots() -> None:
    """One directory read before a batch of cards: a stat per card took 1 s on the Windows mount."""
    global _shots  # replaced whole: another request's cards may be reading it
    _shots = set(os.listdir(collector.SHOTS)) if collector.SHOTS.is_dir() else set()


def related(db, domain: str, ad: dict) -> list[dict]:
    """The ad's other domains the base knows (captions, targets) with their state, for the card's checkboxes:
    on carolina.pl's card the scam it fronts, healthoone.online, is blocked from there too."""
    others = sorted((collector.ad_domains(ad) | set(collector.hidden_domains(ad))) - {domain} - collector.PLATFORMS
                    - collector.SHORTENERS)  # a shortener in a caption: the link of anyone
    if domain in collector.PLATFORMS:  # the advertiser's own subdomain, not the platform hosting everyone's
        hosts = {urllib.parse.urlsplit(u).hostname or "" for u in [*(ad.get("links") or {}).values(), *(ad.get("destinations") or [])]}
        others += sorted(h.removeprefix("www.") for h in hosts if h.endswith(f".{domain}") and h != f"www.{domain}")
    rows = db.execute(f"SELECT domain, verdict, decided_by, decided_at, reason LIKE 'the ad shows %' FROM verdicts "
                      f"WHERE domain IN ({', '.join('?' * len(others))})", others) if others else []
    # spare: its box starts unticked; the ad only wears its name (ccc.eu's caption on superceny.club), or the collector
    # never judges it: popular, trusted or allowed (amazon.nl beside trend-sky.info)
    known = {row[0]: dict(zip(("domain", "verdict", "decided_by", "decided_at", "spare"), row[:4] + (bool(row[4]),)))
             for row in rows}
    allowed = allow_list()  # not joined with the 20 000 popular ones: a new set per card took 10 s a tab
    # one not judged yet too: homla.pl's ad opens dailycartplus.shop, which the collector reaches later
    return [(d := known.get(name) or {"domain": name, "verdict": None, "decided_by": None, "decided_at": None,
                                      "spare": False})
            | {"spare": d["spare"] or name in _popular or name in collector.TRUSTED or name in allowed} for name in others]


_popular: set[str] = set()  # Tranco's top 20 000, as the collector reads it; until loaded, those boxes start ticked
_allowed: list = [None, set(), 0.0]  # allow.txt's mtime, its domains, when last looked at


def allow_list() -> set[str]:
    """allow.txt, read again only when it changed, looked at once in 10 s: read per card it took 10 of the queue's
    12 s, and even a stat per card 4 s on the Windows folder."""
    if time.monotonic() - _allowed[2] > 10:
        path = collector.LISTS / "allow.txt"
        if _allowed[0] != (stamp := path.stat().st_mtime if path.exists() else 0):
            _allowed[:2] = [stamp, collector.read_list(path)]
        _allowed[2] = time.monotonic()
    return _allowed[1]


def load_popular() -> None:
    global _popular
    try:
        _popular = collector.popular_domains()
    except OSError as e:
        print(f"popular domains not read, their boxes start ticked: {e}")


def card(row: tuple, db=None) -> dict:
    domain, verdict, score, reason, ad_id, page, seen_at, ad, decided_by, decided_at = row
    ad = json.loads(ad) if ad else {}
    # the stored number in the key: one filled in later (GUS's NIP for a KRS) must not hide behind the kept one
    if (key := (domain, seen_at, reason, (ad.get("number") or {}).get(domain))) not in _numbers:
        # the number the reason names, the one the collector found on the site's pages,
        # else one on the saved page or in the ad, last one near a courier's or payment firm's name
        texts = ((ad.get("landing") or {}).get(domain, ""), " ".join(ad.get("ad_creative_bodies", [])))
        number = collector.company_number(reason or "") or (ad.get("number") or {}).get(domain) or next(filter(
            None, map(collector.company_number, texts)), None) or collector.company_number(texts[0], own=False) or (
            collector.court_number(reason or "") or collector.court_number(texts[0]))  # a site giving only KRS or REGON
        court = collector.court_number(texts[0]) or ""  # the site's KRS: a closed company's heir is found by it
        _numbers[key] = number, court[4:] if court.startswith("KRS ") else None
    number, krs = _numbers[key]
    landing = (ad.get("links") or {}).get(domain)  # the page the ad really opens, when the collector found it
    return {
        "landing": landing,
        "others": [href for href in ad.get("destinations", []) if href != landing],  # the ad's other targets
        "country": (ad.get("country") or {}).get(domain),  # the version from the home page's country picker read too
        # days since registration when judged; "hidden" when the registry gives no date, None when not stored
        "age_days": "hidden" if (ages := ad.get("age_days") or {}).get(domain, 0) is None else ages.get(domain),
        "shot": f"/shots/{domain}.jpg" if f"{domain}.jpg" in _shots else None,  # its first screen
        # the address the ad shows, as the collector opened it (path too: reha-oferta.surveysparrow.com/s/...),
        # for entries without the real link; None when it is just the home page
        "caption": None if (shown := collector.caption_url(ad, domain)) == f"https://{domain}/" else shown,
        "domain": domain, "verdict": verdict, "score": score, "reason": reason or "", "page": page,
        "seen_at": seen_at, "decided_by": decided_by, "decided_at": decided_at,
        "saved": "ad_creative_link_captions" in ad,  # older entries keep only the links found later
        "text": "\n\n".join(dict.fromkeys(ad.get("ad_creative_bodies", []))),  # ads often repeat their text
        "titles": ad.get("ad_creative_link_titles", []),
        "captions": ad.get("ad_creative_link_captions", []),
        "library": f"https://www.facebook.com/ads/library/?id={ad_id}" if ad_id else None,
        "manual": URL.findall(reason or ""),  # files and pages the collector left for a human, never opened
        "number": number,  # for the registry check
        "krs": krs,  # sent with it: a closed company's KRS may show the company that took it over
        # set when that number is the NIP GUS holds behind the site's KRS or REGON: the card says the site gives none
        "number_by": collector.court_number(reason) if "no NIP on the site" in (reason or "") else (
            (ad.get("number_by") or {}).get(domain) if number == (ad.get("number") or {}).get(domain) else None),
        "related": related(db, domain, ad) if db else [],
        "platform": domain in collector.PLATFORMS,  # its box starts unticked whatever the reason says
        "fb_page": ad.get("fb_page"),  # likes, categories, address of the advertiser's page, read from the Library
        # the API's page id opens the page too when the Library no longer shows it (the ad gone: vorela.pl)
        "fb_id": f"https://www.facebook.com/{ad['page_id']}" if str(ad.get("page_id") or "").isdigit() else None,
    }


def sample(db) -> str:
    """The condition of the sample batch: SAMPLE unseen verdicts drawn once and kept until a human decided each, then
    the next batch. A fresh draw on every refresh never counted down, whatever the user had decided."""
    batch = f"{UNSEEN} AND domain IN (SELECT domain FROM sample)"
    if not db.execute(f"SELECT 1 FROM verdicts WHERE {batch}").fetchone():
        db.execute("DELETE FROM sample")
        db.execute(f"INSERT INTO sample SELECT domain FROM verdicts WHERE {UNSEEN} ORDER BY random() LIMIT ?", (SAMPLE,))
        db.commit()
    return batch


def cards(db, view: str, limit: int = 1000, who: str | None = None) -> list[dict]:  # 300 left 118 of 418 queued out of sight
    read_shots()
    if view == "cert":
        return cert_queue(db)[:limit]
    if view in ("review", "batch"):  # newest first within each group (a stable sort keeps that order); batch: `who`'s
        mine = " AND domain IN (SELECT domain FROM leases WHERE login = ? AND until > ?)" if view == "batch" else ""
        rows = db.execute(f"SELECT {COLUMNS} FROM verdicts WHERE verdict = 'review'{mine} ORDER BY seen_at DESC",
                          (who, now()) if mine else ())
        return sorted((card(row, db) for row in rows), key=urgency)[:limit]
    if view == "remarks":  # the open ones, oldest first: each answered by mail, then marked done
        rows = db.execute("SELECT rowid, note, card, who, at FROM remarks WHERE done IS NULL ORDER BY at LIMIT ?", (limit,))
        return [json.loads(shown) | {"remark": {"id": i, "note": note, "who": who_, "at": at}}
                for i, note, shown, who_, at in rows]
    if view == "sample":  # humans saw 2 of its blocks and 17 passes: their verdicts here measure its precision
        rows = db.execute(f"SELECT {COLUMNS} FROM verdicts WHERE {sample(db)} ORDER BY seen_at DESC LIMIT ?", (limit,))
        return [card(row, db) for row in rows]
    rows = db.execute(f"SELECT {COLUMNS} FROM verdicts WHERE verdict = ? ORDER BY seen_at DESC LIMIT ?",
                      (VIEWS[view], limit))
    return [card(row, db) for row in rows]


def counts(db) -> dict[str, int]:
    found = {name: db.execute("SELECT count(*) FROM verdicts WHERE verdict = ?", (verdict,)).fetchone()[0]
             for name, verdict in VIEWS.items()}
    batch = db.execute(f"SELECT count(*) FROM verdicts WHERE {sample(db)}").fetchone()[0]
    return found | {"cert": len(cert_domains(db)), "sample": batch,
                    "remarks": db.execute("SELECT count(*) FROM remarks WHERE done IS NULL").fetchone()[0]}


def tally(db, who: str | None) -> dict[str, int]:
    """The tabs' numbers: the owner's queues, an auditor's batch only."""
    return counts(db) if who is None else {"batch": batch_state(db, who)["batch"]}


def figures(db) -> dict:
    """The landing's numbers: domains checked, blocked now, handed to a human, decisions people made. Totals only."""
    one = lambda sql: db.execute(sql).fetchone()[0]
    return {"checked": one("SELECT count(*) FROM verdicts"),
            "blocked": one("SELECT count(*) FROM verdicts WHERE verdict = 'block'"),
            "human": one("SELECT count(*) FROM history WHERE by = 'human'"),
            # domains the collector could not settle and handed to a human instead of blocking
            "asked": one("SELECT count(DISTINCT domain) FROM history WHERE by LIKE 'collector%' AND verdict = 'review'"),
            "since": (one("SELECT min(seen_at) FROM verdicts") or "")[:10],
            "at": datetime.now(timezone.utc).isoformat(timespec="minutes")}


def lists_db():
    return closing(sqlite3.connect(f"file:{LISTS_DB}?mode=ro", uri=True, timeout=10))


def parents(host: str) -> list[str]:
    """a.shop.com.pl, shop.com.pl, com.pl: an entry for any of them covers the host."""
    parts = host.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


def listed(host: str) -> list[dict]:
    """Source lists (sources.toml) blocking the host; [] when the lists base is not there yet."""
    if not LISTS_DB.exists():
        return []
    names = parents(host)
    with lists_db() as db:  # CROSS JOIN: per source by primary key, not a scan of 5 million rows
        rows = db.execute("SELECT name, package, domain FROM sources CROSS JOIN entries ON source = name "
                          f"WHERE domain IN ({','.join('?' * len(names))})", names)
        return [{"source": source, "package": package, "entry": entry} for source, package, entry in rows]


def cert_domains(db) -> list[str]:
    """Blocks to report to CERT Polska: confirmed by a human or by strong evidence, not reported yet and not on
    hole.cert.pl already. CERT checks each one; its list then blocks it for every Polish ISP.

    Oldest first: a block found while the user fills in the form joins the end, so the batch on screen stays the
    one sent (newest first, inudaciun.shop took healthroom.com's place in the "sent" batch).
    """
    # picked by three columns, the ads read only for those left: the tab counts need no ads (0.7 s)
    rows = db.execute("SELECT domain, reason, decided_by FROM verdicts WHERE verdict = 'block' AND domain NOT IN "
                      "(SELECT domain FROM history WHERE verdict = 'reported') ORDER BY seen_at").fetchall()
    why = {domain: reason or "" for domain, reason, by in rows if by == "human" or STRONG.match(reason or "")}
    ages = dict(db.execute("SELECT domain, json_extract(ad, '$.age_days.\"' || domain || '\"') FROM verdicts WHERE "
                           f"domain IN ({','.join('?' * len(why))})", list(why))) if why else {}
    # never the brand a scam ad showed (wedel.pl led to blakcaweek.club), nor an old firm on weaker proof than its
    # own page (margobizuteria.pl, biedronka.pl: blocked here, CERT would block them for every Polish ISP)
    picked = [domain for domain, reason in why.items() if not VICTIM.match(reason)
              and not ((ages.get(domain) or 0) > collector.OLD_DAYS and not INFRA.search(reason))]
    global _on_cert
    if picked and LISTS_DB.exists():
        try:
            with lists_db() as lists:
                _on_cert = {domain for (domain,) in lists.execute(
                    f"SELECT domain FROM entries WHERE source = ? AND domain IN ({','.join('?' * len(picked))})",
                    [CERT_SOURCE, *picked])}
        except sqlite3.OperationalError:  # lists.py swapping a source of millions of rows: the last answer stays
            pass
    return [domain for domain in picked if domain not in _on_cert]


_on_cert: set[str] = set()  # blocks already on hole.cert.pl, as last read from lists.db


def cert_queue(db) -> list[dict]:
    return [card(db.execute(f"SELECT {COLUMNS} FROM verdicts WHERE domain = ?", (domain,)).fetchone()) for domain in cert_domains(db)]


def reported(db, domains: list[str]) -> int:
    """Marks blocked domains as sent to CERT; the number marked."""
    blocked = [d for d in domains if db.execute("SELECT 1 FROM verdicts WHERE domain = ? AND verdict = 'block'",
                                                (d,)).fetchone()]
    for domain in blocked:
        collector.log(db, domain, "reported", "CERT Polska, incydent.cert.pl", "human")
    db.commit()
    return len(blocked)


def write_lines(path: Path, lines: list[str]) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(path)  # the lists service and Blocky never read a half-written file


def allowed_by(host: str) -> str | None:
    """The allow.txt entry that lets the host through (*.allegro.pl for a.allegro.pl), None when there is none."""
    entries = collector.read_list(collector.LISTS / "allow.txt")
    return next((f"*.{name}" for name in parents(host) if name in entries), None)


def unallow(db, host: str) -> None:
    """Removes *.host from allow.txt. Adding is by hand only: one click let a whole platform through, every scam
    shop on its subdomains included (*.myshoplaza.com)."""
    path = collector.LISTS / "allow.txt"
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    kept = [line for line in lines if line.strip() not in {f"*.{host}", host}]
    if kept != lines:
        write_lines(path, kept)
    collector.log(db, host, "unallow", None, "human")
    db.commit()
    publish_soon(reload=True)  # Blocky reads allow.txt only when it reloads


def lookup(db, query: str, viewer: str | None = None) -> dict | None:
    """Everything about one domain: our card, every list blocking it, the exception and the history.
    Who decided: the login for the owner (viewer None); an auditor sees only "ty" at their own, never others' e-mails."""
    host = urlsplit(query if "//" in query else f"//{query}").hostname or ""
    if len(host) > 253 or not collector.DOMAIN.fullmatch(host):
        return None
    domain = collector.extract(host).top_domain_under_public_suffix or host  # verdicts are per registrable domain
    row = db.execute(f"SELECT {COLUMNS} FROM verdicts WHERE domain = ?", (domain,)).fetchone()
    read_shots()
    history = db.execute("SELECT verdict, reason, by, at, who FROM history WHERE domain IN (?, ?) ORDER BY at, rowid",
                         (domain, host)).fetchall()
    return {"domain": host, "card": card(row, db) if row else None, "lists": listed(host), "allowed_by": allowed_by(host),
            "history": [dict(zip(("verdict", "reason", "by", "at"), entry))
                        | {"who": who if viewer is None else "ty" if who == viewer else None} for *entry, who in history]}


def similar(db, query: str, top: int = 20) -> list[str]:
    """Domains in the base that hold the typed fragment, else the closest names: "frisco", "patryk misiewicz", "friscco"."""
    host = urlsplit(query if "//" in query else f"//{query}").hostname or query
    bit = re.sub(r"[^a-z0-9.-]", "", host.lower()).strip(".-")
    if len(bit) < 3:
        return []
    like = bit.replace("%", "").replace("_", "")
    if hits := [d for (d,) in db.execute("SELECT domain FROM verdicts WHERE domain LIKE ? ORDER BY length(domain), domain"
                                         " LIMIT ?", (f"%{like}%", top))]:
        return hits
    names = {}  # "frisco" for frisco.pl: a typo is measured against the name, not the ending
    for (domain,) in db.execute("SELECT domain FROM verdicts"):
        names.setdefault(domain.split(".")[0], []).append(domain)
        names.setdefault(domain, []).append(domain)
    close = difflib.get_close_matches(bit, names, n=top, cutoff=0.75)
    return list(dict.fromkeys(d for name in close for d in names[name]))[:top]


KRS = "https://api-krs.ms.gov.pl/api/krs/OdpisAktualny/{}?rejestr={}&format=json"  # the court register, free, no key
MF_FIELDS = ("name", "statusVat", "regon", "krs", "workingAddress", "residenceAddress", "registrationLegalDate")


def krs_entry(number: str) -> dict | None:
    """A company's court register entry: since when, its capital, liquidation, bankruptcy or a merger (section 6).
    None when the register did not answer."""
    for register in ("P", "S"):  # businesses, then associations and foundations
        try:
            entry = collector.http_json(KRS.format(number, register))["odpis"]
        except (OSError, ValueError, KeyError):  # 404 when it is in the other register
            continue
        sections = entry.get("dane", {})
        capital = (sections.get("dzial1", {}).get("kapital") or {}).get("wysokoscKapitaluZakladowego") or {}
        events, closed = section6(sections.get("dzial6") or {})
        return {"since": entry.get("naglowekA", {}).get("dataRejestracjiWKRS"), "capital": capital.get("wartosc"),
                "events": events, "closed": closed}
    return None


def section6(events: dict) -> tuple[list[str], list[str]]:
    """Section 6 events still open, and the closed ones: a liquidation ended by a resolution is over (czlowiekuruszsie.pl,
    opened and ended in 2021); an empty heading ("rozwiazanieUniewaznienie": {...: []}) is no event at all."""
    def filled(item):
        return any(filled(v) for v in item.values()) if isinstance(item, dict) else (
            any(map(filled, item)) if isinstance(item, list) else bool(item))
    def ended(item):
        return isinstance(item, dict) and any(k.startswith(("zakonczenie", "uchylenie")) and filled(v) for k, v in item.items())
    still, closed = [], []
    for name, value in sorted(events.items()):
        if items := [i for i in (value if isinstance(value, list) else [value]) if filled(i)]:
            (closed if all(map(ended, items)) else still).append(name)
    return still, closed


def registry(query: str, krs: str | None = None) -> dict | None:
    """What the registries say of a number from a card: a Polish NIP (or the one GUS finds behind a KRS or REGON)
    in GUS REGON, on the MF white list, in KRS and CEIDG, an EU VAT number in VIES. None when it is neither. A registry that did not answer is None in the result.
    Asked afresh each time a card opens: the user wants today's state, not a kept one.
    `krs`: the site's KRS, for a company closed in GUS: the court record may name the one that took it over."""
    number = re.sub(r"^\s*NIP:?|[\s.-]", "", query.upper())  # as copied from a footer: "NIP: 123-456-32-18"
    if m := re.fullmatch(r"(KRS|REGON):?(\d{9,10})", number):  # a site giving no NIP: GUS knows the NIP behind it
        entry = collector.gus_subject(m[2], m[1].capitalize())
        if entry and entry.get("nip"):
            return registry(entry["nip"]) | {"by": f"{m[1]} {m[2]}"}
        return {"nip": None, "by": f"{m[1]} {m[2]}", "gus": entry, "mf": None, "krs": None, "ceidg": None}
    if m := re.fullmatch(r"(?:PL)?(\d{10})", number):
        nip = m[1]
        if sum(int(d) * w for d, w in zip(nip, collector.NIP_WEIGHTS)) % 11 != int(nip[9]):
            for country in collector.foreign_vat(nip):  # a foreign VAT number without its prefix (SK2120099014)
                if ((found := registry(country + nip))["vies"] or {}).get("userError") != "INVALID":
                    return found  # valid, or the country did not answer
            return {"nip": nip, "made_up": True}
        mf, gus = collector.vat_subject(nip), collector.gus_subject(nip)
        heir = krs and gus and gus.get("ended") and collector.krs_heir(krs)  # hossanova.pl: merged in 2022
        return {"nip": nip, "gus": gus, "mf": mf and {k: mf.get(k) for k in MF_FIELDS},
                "krs": (mf or {}).get("krs") and krs_entry(mf["krs"]), "ceidg": collector.ceidg_subject(nip)} | (
            {"heir": heir} if heir else {})
    if (m := re.fullmatch(r"([A-Z]{2})([0-9A-Z+*]{2,13})", number)) and m[1] in collector.VAT_FORMAT:
        try:
            answer = collector.vies(m[1], m[2])
        except (OSError, ValueError):
            answer = None
        return {"vat": number, "made_up": collector.vat_malformed(m[1], m[2]),
                "vies": answer and {k: answer.get(k) for k in ("isValid", "name", "address", "userError")}}
    return None


def outranked(db, domain: str, decision: str, who: str | None) -> str | None:
    """Why an auditor's decision may not replace the one there, None when it may. A stricter human decision by
    someone else stays (pass < doubtful < block): two auditors at once, or one on an old screen, never let a site
    through that another blocked. Their own they may change; the owner (who None) decides last.
    A domain waiting in another auditor's batch is theirs until they decide it or the batch runs out."""
    if who is None:
        return None
    if (holder := db.execute("SELECT l.login FROM leases l JOIN verdicts v USING (domain) WHERE l.domain = ? "
                             "AND l.until > ? AND v.verdict = 'review'", (domain, now())).fetchone()) and holder[0] != who:
        return f"{domain}: jest w paczce innego audytora"
    row = db.execute("SELECT verdict FROM verdicts WHERE domain = ? AND decided_by IN ('human', 'verified')",
                     (domain,)).fetchone()
    if not row or STRICT.get(row[0], 0) <= STRICT.get(decision, 0):
        return None
    last = db.execute("SELECT who FROM history WHERE domain = ? AND by = 'human' ORDER BY rowid DESC LIMIT 1",
                      (domain,)).fetchone()
    if last and last[0] == who:
        return None
    by = "inny audytor" if last and last[0] else "właściciel"
    return f"{domain}: {by} dał {'blokadę' if row[0] == 'block' else 'wątpliwą'}, surowsza decyzja zostaje"


def decide(db, domain: str, decision: str, undo: bool = False, card: str | None = None, who: str | None = None) -> bool:
    """Store a human decision; False when the domain is unknown. Blocky picks up a block within ~30 s.

    An undo puts back the earlier verdict without marking it as a human decision: those are training labels.
    `card`: the card it was decided on; a domain of that card's ad not in the base yet gets a row with its ad.
    `who`: the auditor's login, kept in history and in the points ledger; None for the owner on the server.
    """
    human = decision != "review" and not undo
    # passed after a phone call or a registry visit: the page alone looked bad, so no label to learn from;
    # still a human decision, never judged again
    verified = decision == "verified"
    decision = "pass" if verified else decision
    by = "verified" if verified else "human" if human else None
    now = datetime.now(timezone.utc).isoformat(timespec="seconds") if human else None
    changed = db.execute("UPDATE verdicts SET verdict = ?, decided_by = ?, decided_at = ? WHERE domain = ?",
                         (decision, by, now, domain)).rowcount
    if not changed and human and card and (row := db.execute(
            f"SELECT {COLUMNS} FROM verdicts WHERE domain = ?", (card,)).fetchone()):
        if domain not in {d["domain"] for d in related(db, card, json.loads(row[7] or "{}"))}:
            return False  # only the ad's own domains, never any name sent here
        changed = db.execute("INSERT INTO verdicts (domain, verdict, score, reason, ad_id, page, seen_at, ad, decided_by,"
                             " decided_at) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, 'human', ?)",
                             (domain, decision, f"decided on the card of {card}", *row[4:8], now)).rowcount
    if not changed:
        return False
    collector.log(db, domain, decision, "checked outside the site" if verified else None, "human" if human else "undo", who)
    if who and human:
        award(db, who, "decision", domain)
    db.commit()
    doubtful = collector.LISTS / "watpliwe.txt"
    lines = doubtful.read_text(encoding="utf-8").splitlines() if doubtful.exists() else []
    entry = f"*.{domain}"
    kept = [line for line in lines if line != entry] + ([entry] if decision == "doubtful" else [])
    if kept != lines:  # the lists service reads this file every minute
        write_lines(doubtful, kept)
    publish_soon()
    return True


def accounts(db) -> None:
    """Auditors (approved: when the owner let them in, NULL while waiting) and their sessions. Only hashes are kept,
    so the hourly copy on Google holds no password and no live session."""
    db.execute("CREATE TABLE IF NOT EXISTS auditors (login TEXT PRIMARY KEY, password TEXT, note TEXT, asked TEXT, approved TEXT)")
    db.execute("CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, login TEXT, until TEXT)")
    # sites sent from outside; who: the auditor when logged in, else NULL (no address or other trace kept)
    db.execute("CREATE TABLE IF NOT EXISTS suspects (domain TEXT, url TEXT, note TEXT, who TEXT, at TEXT)")
    db.execute("CREATE INDEX IF NOT EXISTS suspects_domain ON suspects (domain)")
    # the ranking's ledger: one row per auditor, kind (decision, suspect, training) and thing (a domain, a course)
    db.execute("CREATE TABLE IF NOT EXISTS points (login TEXT, kind TEXT, ref TEXT, points INT, at TEXT, "
               "PRIMARY KEY (login, kind, ref))")
    db.execute("CREATE TABLE IF NOT EXISTS badges (login TEXT, badge TEXT, at TEXT, PRIMARY KEY (login, badge))")
    # an auditor's batch: domains to review only they decide until `until` (see reserve())
    db.execute("CREATE TABLE IF NOT EXISTS leases (domain TEXT PRIMARY KEY, login TEXT, until TEXT)")
    # an auditor's technical note: card is the card as they saw it (JSON), done when the owner answered
    db.execute("CREATE TABLE IF NOT EXISTS remarks (domain TEXT, note TEXT, card TEXT, who TEXT, at TEXT, done TEXT)")
    # an auditor's public name; when a badge's "you got it" was shown (NULL: still to show)
    for table, column in (("auditors", "name"), ("badges", "shown")):
        if column not in {c[1] for c in db.execute(f"PRAGMA table_info({table})")}:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT")
    for (login,) in db.execute("SELECT login FROM auditors WHERE name IS NULL").fetchall():
        db.execute("UPDATE auditors SET name = ? WHERE login = ?", (made_up_name(db), login))
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS auditors_name ON auditors (name COLLATE NOCASE)")
    db.commit()


def made_up_name(db) -> str:
    """A free name like "Czujna Sowa 42": an adjective that agrees with the animal, and a number."""
    while True:
        animal, female = secrets.choice(ANIMALS)
        name = f"{secrets.choice(TRAITS)[female]} {animal} {secrets.randbelow(90) + 10}"
        if not db.execute("SELECT 1 FROM auditors WHERE name = ? COLLATE NOCASE", (name,)).fetchone():
            return name


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def award(db, login: str, kind: str, ref: str) -> None:
    """Points for one thing once: flipping a decision back and forth, or sending one site again, earns nothing more."""
    db.execute("INSERT OR IGNORE INTO points VALUES (?, ?, ?, ?, ?)",
               (login, kind, ref, POINTS.get(kind, 0), datetime.now(timezone.utc).isoformat(timespec="seconds")))


def grant(db, login: str, badge: str) -> None:
    db.execute("INSERT OR IGNORE INTO badges (login, badge, at) VALUES (?, ?, ?)",
               (login, badge, datetime.now(timezone.utc).isoformat(timespec="seconds")))


def decided(db, login: str) -> dict:
    """The auditor's decisions by verdict: their last one on each domain, so one changed counts once."""
    return dict(db.execute("SELECT verdict, count(*) FROM history WHERE rowid IN (SELECT max(rowid) FROM history "
                           "WHERE who = ? AND by = 'human' GROUP BY domain) GROUP BY verdict", (login,)))


def earn(db, login: str) -> None:
    """Grants every badge the auditor has reached: counted from history each time, so a badge added later reaches
    those who earned it before. A badge once got stays, even when a changed decision lowers the count."""
    done = decided(db, login)
    done["training"] = db.execute("SELECT count(*) FROM points WHERE login = ? AND kind = 'training'", (login,)).fetchone()[0]
    rows = db.execute("SELECT verdict, reason, at FROM history WHERE who = ? AND by = 'human'", (login,)).fetchall()
    blocks = sorted(datetime.fromisoformat(at) for verdict, _, at in rows if verdict == "block")
    joined = db.execute("SELECT asked, approved FROM auditors WHERE login = ?", (login,)).fetchone() or ("", "")
    reached = {
        "pass-secret": any(v == "pass" and r == "checked outside the site" for v, r, _ in rows),
        "doubtful-secret": any(v == "doubtful" and datetime.fromisoformat(at).astimezone(WARSAW).hour < 5 for v, _, at in rows),
        "block-secret": any(last - first <= timedelta(minutes=10) for first, last in zip(blocks, blocks[9:])),
        "pioneer": (joined[0] or joined[1] or "")[:4] == "2026",
    }
    for badge, group, need, *_ in BADGES:
        if reached.get(badge) or need and done.get(group, 0) >= need:
            grant(db, login, badge)
    db.commit()


def shelf(db, login: str) -> list[dict]:
    """Every badge, got (with when) or not; a secret not got shows neither its name nor what it is for."""
    got = dict(db.execute("SELECT badge, at FROM badges WHERE login = ?", (login,)))
    return [{"id": badge, "group": group, "need": need, "at": got.get(badge), "secret": need is None and group != "pioneer"}
            | ({"name": name, "why": why} if badge in got or need or group == "pioneer" else {})
            for badge, group, need, name, why in BADGES]


def unseen(db, login: str) -> list[dict]:
    """Badges got whose "you got it" the auditor has not seen yet."""
    new = {b for b, in db.execute("SELECT badge FROM badges WHERE login = ? AND shown IS NULL", (login,))}
    return [b for b in shelf(db, login) if b["id"] in new]


def standing(db, login: str) -> dict:
    """An auditor's points, what they came from, badges and rank."""
    total = db.execute("SELECT coalesce(sum(points), 0) FROM points WHERE login = ?", (login,)).fetchone()[0]
    return {"login": login, "points": total,
            "name": (db.execute("SELECT name FROM auditors WHERE login = ?", (login,)).fetchone() or [None])[0],
            "from": dict(db.execute("SELECT kind, count(*) FROM points WHERE login = ? GROUP BY kind", (login,))),
            "badges": shelf(db, login),
            "rank": [name for floor, name in RANKS if total >= floor][-1]}


def batch_state(db, login: str) -> dict:
    """What is left of the auditor's batch, of how many taken, until when, and how many domains wait for anyone."""
    taken, until = db.execute("SELECT count(*), max(until) FROM leases WHERE login = ? AND until > ?",
                              (login, now())).fetchone()
    left = db.execute("SELECT count(*) FROM verdicts WHERE verdict = 'review' AND domain IN "
                      "(SELECT domain FROM leases WHERE login = ? AND until > ?)", (login, now())).fetchone()[0]
    pool = db.execute("SELECT count(*) FROM verdicts WHERE verdict = 'review' AND domain NOT IN "
                      "(SELECT domain FROM leases WHERE until > ?)", (now(),)).fetchone()[0]
    return {"batch": left, "taken": taken if left else 0, "until": until if left else None, "pool": pool}


def reserve(db, login: str, size: int) -> int:
    """Takes `size` free domains to review for the auditor, the most urgent first, for LEASE; 0 while their batch still
    holds some (a new one only after deciding or handing back the rest). Called under DECIDING: no domain twice."""
    db.execute("DELETE FROM leases WHERE until <= ?", (now(),))
    if batch_state(db, login)["batch"]:
        return 0
    db.execute("DELETE FROM leases WHERE login = ?", (login,))  # the decided rest of the last batch
    rows = db.execute("SELECT domain, reason, ad FROM verdicts WHERE verdict = 'review' AND domain NOT IN "
                      "(SELECT domain FROM leases) ORDER BY seen_at DESC").fetchall()
    free = sorted(rows, key=lambda r: urgency({"reason": r[1] or "",
                                               "age_days": (json.loads(r[2] or "{}").get("age_days") or {}).get(r[0])}))
    until = (datetime.now(timezone.utc) + LEASE).isoformat(timespec="seconds")
    db.executemany("INSERT INTO leases VALUES (?, ?, ?)", [(r[0], login, until) for r in free[:size]])
    db.commit()
    return min(size, len(free))


def profile(db, login: str) -> dict:
    """The auditor's own page: since when, their decisions (the last one on each domain), sites sent, points, batch,
    and the badges they got but have not seen announced."""
    earn(db, login)  # the first visit after a new badge rule grants what was earned before it
    return standing(db, login) | {
        "since": (db.execute("SELECT approved FROM auditors WHERE login = ?", (login,)).fetchone() or [None])[0],
        "decisions": decided(db, login),
        "suspects": db.execute("SELECT count(*) FROM suspects WHERE who = ?", (login,)).fetchone()[0],
        "lease": batch_state(db, login), "fresh": unseen(db, login)}


def public_profile(db, name: str, viewer: str | None) -> dict | None:
    """Another auditor as everyone sees them, found by their public name: never the e-mail. None when no such one."""
    row = db.execute("SELECT login, name, approved FROM auditors WHERE name = ? COLLATE NOCASE AND approved IS NOT NULL",
                     (name,)).fetchone()
    if not row:
        return None
    login, name, since = row
    earn(db, login)
    total = db.execute("SELECT coalesce(sum(points), 0) FROM points WHERE login = ?", (login,)).fetchone()[0]
    return {"name": name, "since": since, "decisions": decided(db, login), "points": total, "me": login == viewer,
            "from": dict(db.execute("SELECT kind, count(*) FROM points WHERE login = ? GROUP BY kind", (login,))),
            "rank": [rank for floor, rank in RANKS if total >= floor][-1], "badges": shelf(db, login)}


def named(db, query: str, top: int = 5) -> list[str]:
    """Approved auditors' public names holding the typed text, any case (Polish letters too)."""
    bit = typed(query).casefold()
    if len(bit) < 2:
        return []
    # shortcut: every name read on each hint, fine for hundreds of auditors; a name_folded column past that
    names = [n for n, in db.execute("SELECT name FROM auditors WHERE approved IS NOT NULL AND name IS NOT NULL ORDER BY name")]
    return [n for n in names if bit in n.casefold()][:top]


RESERVED = re.compile(r"(?i)admin|granny|w[łl]a[śs]ciciel|moderator|usuni[ęe]te konto|\bcert\b|\bnask\b")


def rename(db, login: str, name: str) -> str | None:
    """The auditor's own public name; the error to show, None when changed."""
    name = re.sub(r"\s+", " ", typed(name))
    if not NAME.fullmatch(name):
        return "nazwa: od 3 do 24 znaków, litery, cyfry, spacje i . _ - (bez znaków na brzegach)"
    if RESERVED.search(name):
        return "tej nazwy nie można użyć: udaje kogoś z obsługi projektu"
    if any(other.casefold() == name.casefold() for other, in db.execute(
            "SELECT name FROM auditors WHERE login != ? AND name IS NOT NULL", (login,))):
        return "ta nazwa jest już zajęta"
    db.execute("UPDATE auditors SET name = ? WHERE login = ?", (name, login))
    db.commit()
    return None


def forget(db, login: str) -> None:
    """An auditor deletes their account: no trace of the e-mail stays. Their decisions stay as GONE's."""
    db.execute("UPDATE history SET who = ? WHERE who = ?", (GONE, login))
    db.execute("UPDATE suspects SET who = NULL WHERE who = ?", (login,))
    db.execute("UPDATE remarks SET who = ? WHERE who = ?", (GONE, login))
    for table in ("points", "badges"):
        db.execute(f"DELETE FROM {table} WHERE login = ?", (login,))
    remove(db, login)


def typed(text: str) -> str:
    """What someone typed, without hidden characters; new lines and tabs stay."""
    return HIDDEN.sub("", text).strip()


def remark(db, who: str, domain: str, note: str, most: int = REMARK_NOTE) -> str | None:
    """Stores an auditor's technical note with the card as it is now (what they saw); the error to show, None when stored.
    "simplybook.it is a platform" came from such a card: the owner answers each one by mail."""
    note = typed(note)
    if not 3 <= len(note) <= most:
        return f"opisz uwagi: od 3 do {most} znaków"
    if not (row := db.execute(f"SELECT {COLUMNS} FROM verdicts WHERE domain = ?", (domain,)).fetchone()):
        return "nie ma takiej domeny"
    read_shots()
    db.execute("INSERT INTO remarks VALUES (?, ?, ?, ?, ?, NULL)",
               (domain, note, json.dumps(card(row, db), ensure_ascii=False), who, now()))
    db.commit()
    return None


def suspect_site(text: str) -> tuple[str, str] | None:
    """The host and address someone typed; None for an IP, a mail address or anything else. Never opened here."""
    if len(text := text.strip()) > URL_MAX:
        return None
    url = text if re.match(r"(?i)https?://", text) else "http://" + text
    try:
        parts = urlsplit(url)
        host = collector.ascii_domain((parts.hostname or "").rstrip("."))
    except ValueError:
        return None
    # "@": a mail address, or the bank.pl@zly.pl trick where the name before it only pretends to be the site
    return (host, url) if parts.username is None and len(host) <= 253 and collector.DOMAIN.fullmatch(host) else None


def add_suspect(db, text: str, note: str, who: str | None) -> str | None:
    """Stores a sent site; the error to show, None when stored."""
    if not (site := suspect_site(text)):
        return "podaj adres strony, np. sklep-przyklad.pl"
    day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds")
    if db.execute("SELECT count(*) FROM suspects WHERE at > ?", (day_ago,)).fetchone()[0] >= SUSPECTS_A_DAY:
        return "za dużo zgłoszeń dziś, spróbuj jutro"
    db.execute("INSERT INTO suspects VALUES (?, ?, ?, ?, ?)",
               (*site, typed(note)[:500], who, datetime.now(timezone.utc).isoformat(timespec="seconds")))
    if who:
        award(db, who, "suspect", site[0])
    db.commit()
    return None


def blocked(db, host: str) -> tuple[str, str] | None:
    """(domain, "block" or "doubtful") when we block the host, both in every DNS mode; None when we let it through.
    The host itself first: a hosting client's subdomain is a domain of its own."""
    host = host.removeprefix("www.")
    for domain in dict.fromkeys((host, collector.extract(host).top_domain_under_public_suffix)):
        row = domain and db.execute("SELECT verdict FROM verdicts WHERE domain = ? AND verdict IN ('block', 'doubtful')",
                                    (domain,)).fetchone()
        if row:
            return domain, row[0]
    return None


def appeal(db, sender: str, text: str, note: str) -> str | None:
    """A site owner's appeal against our block, stored as a remark with its card; the error to show, None when stored.
    The owner answers it by mail from the "uwagi" tab, as an auditor's remark."""
    if len(sender) > 254 or not EMAIL.fullmatch(sender):
        return "podaj adres e-mail, na który odpowiemy"
    if not (site := suspect_site(text)):
        return "podaj adres strony, np. sklep-przyklad.pl"
    note = typed(note)
    if not 10 <= len(note) <= APPEAL_NOTE:
        return f"uzasadnij odwołanie: od 10 do {APPEAL_NOTE} znaków"
    if not (found := blocked(db, site[0])):
        return "nie blokujemy tej strony, więc nie ma od czego się odwołać"
    domain = found[0]
    day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds")
    if db.execute("SELECT count(*) FROM remarks WHERE at > ? AND note LIKE ?",
                  (day_ago, APPEAL + "%")).fetchone()[0] >= APPEALS_A_DAY:
        return "za dużo odwołań dziś, spróbuj jutro"
    return remark(db, sender, domain, APPEAL + note, len(APPEAL) + APPEAL_NOTE)


def suspects(db, limit: int = 200) -> list[dict]:
    """Sent sites by host, newest first, with what we already think of them: the collector judges each (3 a cycle),
    under its registrable domain (www.sklep.pl as sklep.pl)."""
    rows = db.execute("SELECT domain, count(*), max(at) FROM suspects GROUP BY domain ORDER BY max(at) DESC LIMIT ?",
                      (limit,)).fetchall()
    return [{"domain": domain, "times": n, "last": at,
             "verdict": (db.execute("SELECT verdict FROM verdicts WHERE domain = ?",
                                    (collector.extract(domain).top_domain_under_public_suffix,)).fetchone() or [None])[0],
             "notes": [n for n, in db.execute("SELECT note FROM suspects WHERE domain = ? AND note != '' "
                                               "ORDER BY at DESC LIMIT 3", (domain,))]} for domain, n, at in rows]


def human_check(token: str, ip: str) -> bool:
    """Cloudflare Turnstile's answer for the form; False when it cannot be asked."""
    data = urllib.parse.urlencode({"secret": TURNSTILE_SECRET, "response": token[:2048], "remoteip": ip}).encode()
    try:
        with urllib.request.urlopen("https://challenges.cloudflare.com/turnstile/v0/siteverify", data, timeout=10) as r:
            return json.load(r).get("success") is True
    except (OSError, ValueError):
        return False


def hashed(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    return salt.hex() + "$" + hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1).hex()


def password_ok(stored: str | None, password: str) -> bool:
    """Hashes even for an unknown login, so the time taken does not tell which logins exist."""
    check = hashed(password, bytes.fromhex(stored.split("$")[0]) if stored else b"\0" * 16)
    return bool(stored) and hmac.compare_digest(stored, check)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def sign_up(db, login: str, password: str, note: str) -> str | None:
    """Stores a waiting account; the error to show, None when stored."""
    if len(login) > 254 or not EMAIL.fullmatch(login):
        return "podaj adres e-mail"
    if not 12 <= len(password) <= 200:
        return "hasło: co najmniej 12 znaków"
    if len(note := typed(note)) > SIGNUP_NOTE:
        return f"opis: najwyżej {SIGNUP_NOTE} znaków"
    if db.execute("SELECT count(*) FROM auditors WHERE approved IS NULL").fetchone()[0] >= WAITING_MAX:
        return "za dużo kont czeka na akceptację, spróbuj później"
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if not db.execute("INSERT OR IGNORE INTO auditors (login, password, note, asked, name) VALUES (?, ?, ?, ?, ?)",
                      (login, hashed(password), note, now, made_up_name(db))).rowcount:
        return "to konto już istnieje"
    db.commit()
    return None


def log_in(db, login: str, password: str) -> str | None:
    """A new session's token for the right password of an approved auditor."""
    row = db.execute("SELECT password, approved FROM auditors WHERE login = ?", (login,)).fetchone()
    if not password_ok(row and row[0], password) or not row[1]:
        return None
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    db.execute("DELETE FROM sessions WHERE until < ?", (now.isoformat(),))
    db.execute("INSERT INTO sessions VALUES (?, ?, ?)", (token_hash(token), login, (now + SESSION).isoformat()))
    db.commit()
    return token


def session_login(db, token: str) -> str | None:
    """The approved auditor behind a live session; a removed one is out at once."""
    row = db.execute("SELECT a.login FROM sessions s JOIN auditors a ON a.login = s.login "
                     "WHERE s.token = ? AND s.until > ? AND a.approved IS NOT NULL",
                     (token_hash(token), datetime.now(timezone.utc).isoformat())).fetchone()
    return row and row[0]


_tries: dict[str, list[float]] = {}


def too_many(key: str, limit: int, window: float) -> bool:
    """Counts one try of `key`; True once more than `limit` came within `window` seconds.
    Kept in memory, a restart forgets it; a table if someone learns to wait for restarts."""
    now = time.time()
    _tries[key] = [t for t in _tries.get(key, []) if now - t < window] + [now]
    if len(_tries) > 10_000:  # many addresses: drop the quiet ones
        for k in [k for k, times in _tries.items() if now - times[-1] > 3600]:
            del _tries[k]
    return len(_tries[key]) > limit


def notify(text: str, title: str = "Panel: nowy audytor") -> None:
    """A note to the owner's phone over ntfy, as alarm.sh sends; never holds up the request."""
    if topic := os.getenv("NTFY_TOPIC"):
        request = urllib.request.Request(f"https://ntfy.sh/{topic}", text.encode(),
                                         {"Title": title, "Tags": "bust_in_silhouette"})
        threading.Thread(target=_send_quietly, args=(request,), daemon=True).start()


def _send_quietly(request) -> bool:
    try:
        urllib.request.urlopen(request, timeout=20).close()
        return True
    except OSError as e:
        print(f"{urlsplit(request.full_url).hostname} failed: {e}")
        return False


def mail(to: str, subject: str, text: str) -> bool:
    """One plain-text mail through Resend; False when not sent (no key, or Resend refused)."""
    if not RESEND_KEY:
        print(f"mail to {to} not sent: no RESEND_KEY")
        return False
    message = {"from": MAIL_FROM, "to": [to], "subject": subject, "text": text} | (
        {"reply_to": MAIL_REPLY_TO} if MAIL_REPLY_TO else {})
    return _send_quietly(urllib.request.Request(  # Cloudflare in front of Resend turns away Python's own agent name
        "https://api.resend.com/emails", json.dumps(message).encode(),
        {"Authorization": f"Bearer {RESEND_KEY}", "Content-Type": "application/json", "User-Agent": "grannyinternet-panel"}))


def waiting(db) -> list[dict]:
    """Auditor accounts for /konta: the waiting first, oldest first, with their decisions (domains) and points."""
    return [{"login": login, "note": note, "asked": asked, "approved": approved, "decisions": decisions, "points": points}
            for login, note, asked, approved, decisions, points in db.execute(
                "SELECT login, note, asked, approved, (SELECT count(DISTINCT domain) FROM history WHERE who = a.login AND "
                "by = 'human'), (SELECT coalesce(sum(points), 0) FROM points p WHERE p.login = a.login) FROM auditors a "
                "ORDER BY approved IS NOT NULL, asked")]


def approve(db, login: str) -> bool:
    done = db.execute("UPDATE auditors SET approved = ? WHERE login = ? AND approved IS NULL",
                      (datetime.now(timezone.utc).isoformat(timespec="seconds"), login.lower())).rowcount
    db.commit()
    return bool(done)


def remove(db, login: str) -> bool:
    """A refused or removed account; their decisions stay in history under their login, the session ends at once."""
    db.execute("DELETE FROM sessions WHERE login = ?", (login.lower(),))
    db.execute("DELETE FROM leases WHERE login = ?", (login.lower(),))  # their batch back to everyone at once
    done = db.execute("DELETE FROM auditors WHERE login = ?", (login.lower(),)).rowcount
    db.commit()
    return bool(done)


def manage(command: str, login: str = "") -> None:
    """python panel.py audytorzy | zatwierdz <login> | usun <login>: the owner on the server lets auditors in."""
    with base() as db:
        accounts(db)
        if command == "audytorzy":
            for row in db.execute("SELECT login, asked, approved, note FROM auditors ORDER BY approved IS NOT NULL, asked"):
                print(f"{row[0]}  zgłoszony {row[1]}  {'zatwierdzony ' + row[2] if row[2] else 'CZEKA'}  {row[3]!r}")
            return
        if command == "zatwierdz":  # no mail from here: /konta writes one
            done = approve(db, login)
        elif command == "usun":
            done = remove(db, login)
        else:
            raise SystemExit("python panel.py audytorzy | zatwierdz <login> | usun <login>")
        print("gotowe" if done else f"nie ma takiego konta{' czekającego' if command == 'zatwierdz' else ''}: {login}")


def metrics(db) -> str:
    """The base's state for Prometheus: queues, human labels, CERT reports. Counters of the collector run: :9100."""
    lines = [f'scamdns_verdicts{{verdict="{v}"}} {n}'
             for v, n in db.execute("SELECT verdict, count(*) FROM verdicts GROUP BY verdict")]
    lines += [f'scamdns_human_decisions{{verdict="{v}"}} {n}' for v, n in db.execute(
        "SELECT verdict, count(*) FROM verdicts WHERE decided_by = 'human' GROUP BY verdict")]
    oldest = db.execute("SELECT min(seen_at) FROM verdicts WHERE verdict = 'review'").fetchone()[0]
    waiting = (datetime.now(timezone.utc) - datetime.fromisoformat(oldest)).total_seconds() if oldest else 0
    lines += [f"scamdns_review_oldest_seconds {waiting:.0f}",
              f"scamdns_cert_queue {len(cert_domains(db))}",
              "scamdns_cert_reported " + str(db.execute(
                  "SELECT count(DISTINCT domain) FROM history WHERE verdict = 'reported'").fetchone()[0]),
              f"scamdns_allowlisted {len(collector.read_list(collector.LISTS / 'allow.txt'))}"]
    for model, cards, accuracy, caught, wrong in db.execute(  # the last measure of each model, see collector.measure()
            "SELECT model, cards, accuracy, caught, false_alarms FROM trainings t WHERE at = "
            "(SELECT max(at) FROM trainings WHERE model = t.model)"):
        lines += [f'scamdns_model_{name}{{model="{model}"}} {value}' for name, value in
                  (("accuracy", accuracy), ("caught", caught), ("false_alarms", wrong), ("cards", cards))]
    return "".join(f"{line}\n" for line in lines)


_dirty = threading.Event()
_reload = False  # allow.txt changed: Blocky reloads even when fb.txt did not


def publish_soon(reload: bool = False) -> None:
    """Hand fb.txt and Blocky to the background: Blocky reloads all 5 million entries, about 20 s."""
    global _reload
    _reload |= reload
    _dirty.set()


def publisher() -> None:
    global _reload
    while True:
        _dirty.wait()
        time.sleep(2)  # a burst of decisions becomes one reload
        _dirty.clear()
        reload, _reload = _reload, False
        try:
            with base() as db:  # fb.txt and a reload only when the blocks changed
                if not collector.publish(db) and reload:
                    collector.reload_blocky()
        except OSError as e:  # Blocky down: decisions are saved, the collector publishes them on its next cycle
            print(f"publish failed: {e}")


def base():
    return closing(collector.open_db(collector.VERDICTS))


class Panel(BaseHTTPRequestHandler):
    def send(self, status: int, body: bytes, kind: str = "application/json", cache: str = "no-store", **headers) -> None:
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        if kind.startswith("text/html"):  # no framing (a hidden click on "pass"), no panel address to the scam sites
            self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
        for name, value in headers.items():
            self.send_header(name.replace("_", "-"), value)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data, status: int = 200) -> None:
        self.send(status, json.dumps(data, ensure_ascii=False).encode())

    def place(self) -> str | None:
        """"local" on the server, "public" through the Cloudflare tunnel; None (and 403 sent) for any other name:
        a page that points its domain at 127.0.0.1 (DNS rebinding) counts as the same site in the browser and could
        send X-Panel and pass a scam. Cloudflare adds Cf-Connecting-Ip: with it a request is never local."""
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        if host in LOCAL_NAMES and not self.headers.get("Cf-Connecting-Ip"):
            return "local"
        if PUBLIC and host == PUBLIC:
            return "public"
        self.send_json({"error": "forbidden"}, 403)
        return None

    def session_token(self) -> str | None:
        try:
            morsel = SimpleCookie(self.headers.get("Cookie") or "").get(COOKIE)
        except CookieError:
            return None
        return morsel and morsel.value

    def auditor(self) -> str | None:
        """The logged-in auditor of a public request; None without a live session."""
        if not (token := self.session_token()):
            return None
        with base() as db:
            return session_login(db, token)

    def suspect(self, place: str, body: dict) -> None:
        """A site sent by anyone. From outside without a login it passes Turnstile first; no key set, none taken."""
        ip = self.headers.get("Cf-Connecting-Ip", "")
        who = self.auditor() if place == "public" else None
        if too_many(f"suspect {who or ip}", 20 if who else 5, 3600):
            return self.send_json({"error": "za dużo zgłoszeń, spróbuj za godzinę"}, 429)
        if place == "public" and not who and self.not_human(body, ip):
            return
        text = body.get("url") if isinstance(body.get("url"), str) else ""
        note = body["note"].strip() if isinstance(body.get("note"), str) else ""
        with base() as db:
            if error := add_suspect(db, text, note, who):
                return self.send_json({"error": error}, 400)
        self.send_json({"ok": True})

    def not_human(self, body: dict, ip: str) -> bool:
        """Turnstile for a public form; True when it failed and the answer is sent. No key set, nothing taken."""
        if not TURNSTILE_SECRET:
            self.send_json({"error": "zgłoszenia jeszcze nie działają"}, 503)
            return True
        token = body.get("cf-turnstile-response")
        if not isinstance(token, str) or not human_check(token, ip):
            self.send_json({"error": "nie udało się potwierdzić, że to człowiek; odśwież stronę"}, 403)
            return True
        return False

    def owner_appeal(self, place: str, body: dict) -> None:
        """A blocked site's owner asks us to look again, from /odwolanie: to the owner's "uwagi" tab and phone."""
        ip = self.headers.get("Cf-Connecting-Ip", "")
        if too_many(f"appeal {ip}", 3, 3600):
            return self.send_json({"error": "za dużo odwołań, spróbuj za godzinę"}, 429)
        if place == "public" and self.not_human(body, ip):  # a mail goes to the address typed: a person, not a script
            return
        text, sender, note = (body[k].strip() if isinstance(body.get(k), str) else "" for k in ("url", "email", "note"))
        sender = sender.lower()
        with base() as db:
            if error := appeal(db, sender, text, note):
                return self.send_json({"error": error}, 400)
        notify(f"{suspect_site(text)[0]}: właściciel prosi o ponowne sprawdzenie. Panel: zakładka uwagi",
               "Panel: odwołanie od blokady")
        # fixed text only, nothing they typed: the form cannot carry someone's message to a stranger
        threading.Thread(target=mail, args=(sender, *MAILS["appeal"]), daemon=True).start()
        self.send_json({"ok": True, "mail": bool(RESEND_KEY)})

    def account(self, path: str, body: dict) -> None:
        """Sign-up, login and logout through the tunnel."""
        ip = self.headers.get("Cf-Connecting-Ip", "")
        login = body["login"].strip().lower() if isinstance(body.get("login"), str) else ""
        password = body["password"] if isinstance(body.get("password"), str) else ""
        cookie = "Path=/; Secure; HttpOnly; SameSite=Strict"
        if path == "/api/logout":
            if token := self.session_token():
                with base() as db:
                    db.execute("DELETE FROM sessions WHERE token = ?", (token_hash(token),))
                    db.commit()
            return self.send(200, b'{"ok": true}', Set_Cookie=f"{COOKIE}=; Max-Age=0; {cookie}")
        if path == "/api/signup":
            if too_many(f"signup {ip}", 3, 3600):
                return self.send_json({"error": "za dużo prób, spróbuj za godzinę"}, 429)
            if self.not_human(body, ip):  # a mail goes to the address typed: a person, not a script sending it to strangers
                return
            note = body["note"].strip() if isinstance(body.get("note"), str) else ""
            with base() as db:
                if error := sign_up(db, login, password, note):
                    return self.send_json({"error": error}, 400)
            notify(f"{login} czeka na akceptację: {note[:300]}\nZatwierdź w panelu: http://127.0.0.1:8081/konta (z tunelem)")
            # fixed text only, nothing they typed: the form cannot carry someone's message to a stranger
            threading.Thread(target=mail, args=(login, *MAILS["received"]), daemon=True).start()
            return self.send_json({"ok": True, "mail": bool(RESEND_KEY)})
        # login: tries counted by address and by account, so neither many guesses at one nor one at many pass
        if too_many(f"login {ip}", 10, 900) | too_many(f"login {login}", 10, 900):
            return self.send_json({"error": "za dużo prób, spróbuj za kwadrans"}, 429)
        with base() as db:
            if not (token := log_in(db, login, password)):
                return self.send_json({"error": "zły login lub hasło albo konto jeszcze nie zatwierdzone"}, 401)
        self.send(200, b'{"ok": true}', Set_Cookie=f"{COOKIE}={token}; Max-Age={int(SESSION.total_seconds())}; {cookie}")

    def own(self, path: str, body: dict, who: str) -> None:
        """The auditor's batch, password and account."""
        password = body["password"] if isinstance(body.get("password"), str) else ""
        with base() as db:
            if path == "/api/batch":  # the size picked each time
                size = body.get("size")
                if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= BATCH_MAX:
                    return self.send_json({"error": f"paczka: od 1 do {BATCH_MAX} domen"}, 400)
                with DECIDING:
                    taken = reserve(db, who, size)
                return self.send_json({"taken": taken, "lease": batch_state(db, who)})
            if path == "/api/remark":  # the e-mail stays here: the phone note says only which card
                if too_many(f"remark {who}", 20, 3600):
                    return self.send_json({"error": "za dużo uwag naraz, spróbuj za godzinę"}, 429)
                domain, note = body.get("domain"), body.get("note")
                if not isinstance(domain, str) or not isinstance(note, str):
                    return self.send_json({"error": "need domain and note"}, 400)
                if error := remark(db, who, domain, note):
                    return self.send_json({"error": error}, 400)
                notify(f"Uwagi do {domain}. Panel: zakładka uwagi", "Panel: uwagi audytora")
                return self.send_json({"ok": True})
            if path == "/api/name":
                if too_many(f"name {who}", 10, 3600):
                    return self.send_json({"error": "za dużo zmian nazwy, spróbuj za godzinę"}, 429)
                if error := rename(db, who, body["name"] if isinstance(body.get("name"), str) else ""):
                    return self.send_json({"error": error}, 400)
                return self.send_json({"ok": True})
            if path == "/api/seen":  # the "you got a badge" sheets shown: not again
                ids = body.get("ids")
                if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
                    return self.send_json({"error": "need ids"}, 400)
                db.executemany("UPDATE badges SET shown = ? WHERE login = ? AND badge = ? AND shown IS NULL",
                               [(now(), who, i) for i in ids[:len(BADGES)]])
                db.commit()
                return self.send_json({"ok": True})
            if path == "/api/release":  # hand back the rest: others may take it at once
                with DECIDING:
                    db.execute("DELETE FROM leases WHERE login = ?", (who,))
                    db.commit()
                return self.send_json({"ok": True})
            # both below need the current password: a session left open on someone's computer changes nothing
            if too_many(f"password {who}", 5, 900):
                return self.send_json({"error": "za dużo prób, spróbuj za kwadrans"}, 429)
            stored = db.execute("SELECT password FROM auditors WHERE login = ?", (who,)).fetchone()
            if not password_ok(stored and stored[0], password):
                return self.send_json({"error": "złe hasło"}, 403)
            if path == "/api/password":
                new = body["new"] if isinstance(body.get("new"), str) else ""
                if not 12 <= len(new) <= 200:
                    return self.send_json({"error": "nowe hasło: co najmniej 12 znaków"}, 400)
                db.execute("UPDATE auditors SET password = ? WHERE login = ?", (hashed(new), who))
                # every other session ends: whoever knew the old password is out
                db.execute("DELETE FROM sessions WHERE login = ? AND token != ?",
                           (who, token_hash(self.session_token() or "")))
                db.commit()
                return self.send_json({"ok": True})
            with DECIDING:  # /api/forget
                forget(db, who)
        self.send(200, b'{"ok": true}', Set_Cookie=f"{COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict")

    def do_GET(self) -> None:
        if not (place := self.place()):
            return
        url = urlsplit(self.path)
        if url.path == "/zglos":  # anyone, logged in or not
            page = REPORT_PAGE.read_text(encoding="utf-8").replace("TURNSTILE_SITE", TURNSTILE_SITE)
            return self.send(200, page.encode(), "text/html; charset=utf-8")
        if url.path == "/odwolanie":  # anyone: a blocked site's owner
            page = APPEAL_PAGE.read_text(encoding="utf-8").replace("TURNSTILE_SITE", TURNSTILE_SITE)
            return self.send(200, page.encode(), "text/html; charset=utf-8")
        if url.path == "/api/blokada":  # anyone, for /odwolanie: one site's state, what our DNS answers anyway
            if too_many(f"status {self.headers.get('Cf-Connecting-Ip', '')}", 60, 3600):
                return self.send_json({"error": "za dużo sprawdzeń, spróbuj za godzinę"}, 429)
            if not (site := suspect_site(parse_qs(url.query).get("q", [""])[0])):
                return self.send_json({"error": "podaj adres strony, np. sklep-przyklad.pl"}, 400)
            with base() as db:
                found = blocked(db, site[0])
            return self.send_json({"host": site[0], "domain": found and found[0], "verdict": found and found[1]})
        if url.path == "/api/liczby":  # anyone, and the landing from its own domain: totals, no domain names
            with base() as db:
                body = json.dumps(figures(db)).encode()
            origin = self.headers.get("Origin", "")
            return self.send(200, body, cache="public, max-age=300", Vary="Origin",
                             Access_Control_Allow_Origin=origin if origin in LANDING else "https://grannyinternet.me")
        who = None
        if place == "public":
            if url.path == "/login":
                page = LOGIN_PAGE.read_text(encoding="utf-8").replace("TURNSTILE_SITE", TURNSTILE_SITE)
                return self.send(200, page.encode(), "text/html; charset=utf-8")
            if url.path in LOCAL_ONLY:
                return self.send_json({"error": "forbidden"}, 403)
            if not (who := self.auditor()):
                if url.path == "/":
                    return self.send(302, b"", "text/plain", Location="/login")
                return self.send_json({"error": "login"}, 401)
            if url.path == "/api/registry" and too_many(f"registry {who}", 60, 3600):  # GUS, MF and VIES are not ours
                return self.send_json({"error": "limit sprawdzeń w rejestrach: 60 na godzinę"}, 429)
        if url.path == "/":
            return self.send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        if url.path == "/konta":  # the owner's only (LOCAL_ONLY)
            return self.send(200, ACCOUNTS_PAGE.read_bytes(), "text/html; charset=utf-8")
        if url.path == "/api/accounts":
            with base() as db:
                return self.send_json({"accounts": waiting(db), "mail": bool(RESEND_KEY),
                                       "templates": {k: MAILS[k][1] for k in ("approve", "reject")}})
        if (m := re.fullmatch(r"/shots/([a-z0-9.-]+\.jpg)", url.path)) and (shot := collector.SHOTS / m[1]).is_file():
            # kept by the browser, asked whether it changed: with no-store each card fetched its picture again
            if self.headers.get("If-Modified-Since") == (stamp := self.date_time_string(int(shot.stat().st_mtime))):
                self.send_response(304)
                self.end_headers()
                return
            return self.send(200, shot.read_bytes(), "image/jpeg", "no-cache", Last_Modified=stamp)  # no "/": no way out
        query = parse_qs(url.query)
        if url.path == "/api/suspects":
            with base() as db:
                return self.send_json(suspects(db))
        if url.path == "/api/me":  # the auditor's own page; the owner has none
            if not who:
                return self.send_json({"error": "only for auditors"}, 404)
            with base() as db:
                return self.send_json(profile(db, who))
        if url.path == "/api/cards":
            view = query.get("view", ["batch" if who else "review"])[0]
            if who and view != "batch":  # an auditor works on their batch only, never on the whole queue
                return self.send_json({"error": "forbidden"}, 403)
            if view not in VIEWS and not who:
                return self.send_json({"error": "unknown view"}, 400)
            with base() as db:
                return self.send_json({"cards": cards(db, view, who=who), "counts": tally(db, who)}
                                      | ({"lease": batch_state(db, who)} if who else {}))
        if url.path == "/api/recent":  # start_gui.py's last verdicts: the base is on a Docker volume, not in lists/
            limit = min(int(n), 50) if (n := query.get("n", ["5"])[0]).isdigit() else 5
            with base() as db:
                return self.send_json(db.execute("SELECT at, verdict, domain, reason, by FROM history ORDER BY rowid "
                                                 "DESC LIMIT ?", (limit,)).fetchall())
        if url.path == "/api/counts":  # after a decision: the page moves on by itself, only the tabs need numbers
            with base() as db:
                return self.send_json(tally(db, who))
        if url.path == "/api/domain":
            with base() as db:
                q = query.get("q", [""])[0].strip().lower()[:200]
                found = lookup(db, q, who)
                if not (found and found["card"]) and (names := similar(db, q)):  # a fragment or a typo: every near one
                    return self.send_json({"matches": [lookup(db, name, who) for name in names], "counts": tally(db, who)})
                if not found:
                    return self.send_json({"error": "not a domain"}, 400)
                return self.send_json(found | {"counts": tally(db, who)})
        if url.path == "/api/suggest":  # hints under the search box while typing: auditors by name, then domains
            q = query.get("q", [""])[0].strip()[:200]
            with base() as db:
                return self.send_json({"users": named(db, q), "domains": similar(db, q.lower(), 8) if len(q) >= 3 else []})
        if url.path == "/api/auditor":  # another auditor's page, by their public name
            with base() as db:
                if not (found := public_profile(db, query.get("name", [""])[0][:40], who)):
                    return self.send_json({"error": "nie ma takiego audytora"}, 404)
                return self.send_json(found)
        if url.path == "/api/registry":
            if not (found := registry(query.get("q", [""])[0][:40], query.get("krs", [""])[0][:10] or None)):
                return self.send_json({"error": "not a NIP, KRS, REGON or an EU VAT number"}, 400)
            return self.send_json(found)
        if url.path == "/api/lists":  # home's DNS copies the server's decisions through the SSH tunnel (home.py)
            return self.send_json({name: (collector.LISTS / name).read_text(encoding="utf-8")
                                   for name in collector.SERVED if (collector.LISTS / name).is_file()})
        if url.path == "/metrics":
            with base() as db:
                return self.send(200, metrics(db).encode(), "text/plain; version=0.0.4")
        self.send_json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        # Another site open in the same browser cannot add a custom header without a CORS preflight,
        # which this server never answers, so it cannot make decisions behind the user's back.
        if not (place := self.place()):
            return
        path = urlsplit(self.path).path
        allowed = (ACCOUNT | MINE if place == "public" else OWNER_ONLY) | {"/api/decide", "/api/suspect", "/api/appeal"}
        if path not in allowed or self.headers.get("X-Panel") != "1":
            return self.send_json({"error": "forbidden"}, 403)
        try:
            # never below 0: read(-1) would wait for the whole stream, as long as the sender likes
            body = json.loads(self.rfile.read(min(max(int(self.headers.get("Content-Length", 0)), 0), 10_000)))
        except ValueError:
            return self.send_json({"error": "bad json"}, 400)
        if not isinstance(body, dict):
            return self.send_json({"error": "bad json"}, 400)
        if path in ACCOUNT:
            return self.account(path, body)
        if path == "/api/suspect":
            return self.suspect(place, body)
        if path == "/api/appeal":
            return self.owner_appeal(place, body)
        who = None
        if place == "public" and not (who := self.auditor()):
            return self.send_json({"error": "login"}, 401)
        if path in MINE:
            return self.own(path, body, who)
        with base() as db:
            if path == "/api/allow":
                host = body.get("domain")
                if not isinstance(host, str) or len(host) > 253 or not collector.DOMAIN.fullmatch(host):
                    return self.send_json({"error": "need a domain"}, 400)
                if body.get("allow") is not False:
                    return self.send_json({"error": "exceptions are added by hand in lists/allow.txt"}, 403)
                unallow(db, host)
                return self.send_json({"ok": True})
            if path == "/api/account":  # the owner lets an auditor in or turns them away, with a mail they edited
                login, action, text = body.get("login"), body.get("action"), body.get("message")
                if not isinstance(login, str) or action not in ("approve", "reject") or not isinstance(text, str):
                    return self.send_json({"error": "need login, action and message"}, 400)
                if not (approve(db, login) if action == "approve" else remove(db, login)):
                    return self.send_json({"error": "nie ma takiego konta albo już zatwierdzone"}, 404)
                sent = bool(text.strip()) and mail(login.lower(), MAILS[action][0], text[:5000])
                return self.send_json({"ok": True, "mailed": sent})
            if path == "/api/remark-done":  # answered by mail: off the tab
                if not isinstance(body.get("id"), int) or isinstance(body.get("id"), bool):
                    return self.send_json({"error": "need id"}, 400)
                db.execute("UPDATE remarks SET done = ? WHERE rowid = ? AND done IS NULL", (now(), body["id"]))
                db.commit()
                return self.send_json({"ok": True})
            if path == "/api/reported":
                domains = body.get("domains")
                if not isinstance(domains, list) or not all(isinstance(d, str) for d in domains):
                    return self.send_json({"error": "need domains"}, 400)
                return self.send_json({"ok": True, "marked": reported(db, domains[:CERT_BATCH])})
            if body.get("decision") not in DECISIONS or not isinstance(body.get("domain"), str):
                return self.send_json({"error": "need domain and decision"}, 400)
            card = body.get("card") if isinstance(body.get("card"), str) else None
            with DECIDING:
                if why := outranked(db, body["domain"], body["decision"], who):
                    return self.send_json({"error": why}, 409)
                if not decide(db, body["domain"], body["decision"], undo=body.get("undo") is True, card=card, who=who):
                    return self.send_json({"error": "unknown domain"}, 404)
            if who:  # a badge reached by this decision: the page announces it at once
                earn(db, who)
                return self.send_json({"ok": True, "fresh": unseen(db, who)})
        self.send_json({"ok": True})

    def log_message(self, *args) -> None:  # decisions are in the base; no request log
        pass


def warm() -> None:
    """Finds the company numbers of the tabs at start and then each minute, outside the user's requests, and keeps
    them over restarts: cold, the review tab took 129 s of the busy server's CPU, and a card judged again misses."""
    numbers = collector.VERDICTS.with_name("panel_numbers.json")
    try:
        _numbers.update((tuple(key), tuple(value)) for key, value in json.loads(numbers.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    saved = 0
    while True:
        try:
            with base() as db:
                for view in ("review", "block", "doubtful", "cert"):
                    cards(db, view)
                current = set(db.execute("SELECT domain, seen_at FROM verdicts"))
            if len(_numbers) != saved:  # only the verdicts' present state: older ones dropped from the file
                saved = len(_numbers)
                tmp = numbers.with_suffix(".tmp")
                tmp.write_text(json.dumps([[*item] for item in list(_numbers.items()) if item[0][:2] in current]),
                               encoding="utf-8")
                tmp.replace(numbers)
        except (sqlite3.Error, OSError) as e:
            print(f"cards not warmed: {e}")
        time.sleep(60)


def main() -> None:
    host = os.getenv("PANEL_HOST", "127.0.0.1")  # 0.0.0.0 only inside Docker, published on 127.0.0.1 by compose
    with base() as db:  # adds the decision columns to an older base
        accounts(db)
    threading.Thread(target=publisher, daemon=True).start()
    threading.Thread(target=warm, daemon=True).start()
    threading.Thread(target=load_popular, daemon=True).start()
    print(f"panel: http://127.0.0.1:8080 (listening on {host})")
    ThreadingHTTPServer((host, 8080), Panel).serve_forever()


if __name__ == "__main__":
    manage(*sys.argv[1:3]) if len(sys.argv) > 1 else main()
