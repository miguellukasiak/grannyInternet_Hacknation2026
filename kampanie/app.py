"""GUI of kampanie: http://127.0.0.1:8501. The user uploads materials in the browser (files, a folder, a ZIP, a URL or
an ad text); their features are kept in /data/baza.json and every new one is compared with all the others."""
import contextlib
import email.parser
import email.policy
import html
import json
import math
import mmap
import os
import re
import secrets
import shutil
import tempfile
import textwrap
import threading
import traceback
import urllib.error
import urllib.request
import zipfile
from collections import Counter, OrderedDict, deque
from dataclasses import asdict, fields
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

import maxminddb
import numpy as np

import baza
import kampanie as k

BAZA = Path(os.environ.get("BAZA", "/data/baza.json"))
ONLINE = os.environ.get("ONLINE", "1") == "1"  # RDAP ages of landing domains; 0 = nothing leaves the container
KOLEKTOR = Path(os.environ.get("KOLEKTOR", "/verdicts/verdicts.db"))  # the collector's verdicts, mounted read-only
STATIC = Path(__file__).with_name("static")
MAX_UPLOAD = 2_000_000_000  # a whole incident set with its videos; the body goes to disk, never to memory
MAX_UNZIP, MAX_FILES = 3_000_000_000, 20_000  # a ZIP bomb stops here
MAX_IMPORT = int(os.environ.get("MAX_IMPORT", "0"))  # 0 = all; a server caps it: 5484 domains took 3 GB and 8 min
PANEL = os.environ.get("PANEL", "")  # the auditors' /api/suspect inside the server's network; empty = reports stay here
PANEL_HOST = os.environ.get("PANEL_HOST", "")  # the name the panel answers publicly: its Turnstile and rate limit apply
TURNSTILE_SITE = os.environ.get("TURNSTILE_SITE", "")
AUDITORS = {"ok": "Zgłoszenie trafiło też do audytorów.",
            "limit": "Do audytorów nie dotarło: za dużo zgłoszeń z tego adresu, spróbuj za godzinę.",
            "czlowiek": "Do audytorów nie dotarło: nie udało się potwierdzić, że to człowiek. Odśwież stronę i zgłoś ponownie.",
            "blad": "Do audytorów nie dotarło: panel nie odpowiada."}
SAVED = ("Zapisano w bazie. Kampanie przeliczają się w tle, zwykle do minuty: potem materiał będzie w tabeli i na grafie. "
         "Kolejne materiały możesz dodawać od razu, przeliczą się razem.")
DONE = "Gotowe: materiał jest w bazie, w tabeli i na grafie, a kampanie są przeliczone."
FAILED = "Nie udało się dołączyć materiału do kampanii. Baza została bez zmian, spróbuj dodać go jeszcze raz."


def saved_note(m, note: str) -> tuple[str, bool]:
    """A saved material's note as things stand now, and whether its regrouping still runs (the page then refreshes)."""
    if not note.startswith(SAVED):
        return note, False
    if m.id in state["base"].by_id:
        return DONE + note[len(SAVED):], False
    if work.locked() or any(x.id == m.id for x in pending):
        return note, True
    return FAILED + note[len(SAVED):], False
work = threading.Lock()  # one writer at a time: uploads and deletes
state = {"base": k.Base([]), "campaigns": [], "status": "", "error": ""}
pending = deque()  # materials waiting to join the base: grouping ~2000 again takes minutes on the server
results = OrderedDict()  # token -> (material, note): a POST answers with a redirect here, so Back never re-sends a form
PER_CAMPS, PER_ROWS, PER_GRAPH = 20, 50, 12  # one page of each list: all of them at once were 1.5 MB and 18 s


def save(materials):
    BAZA.parent.mkdir(parents=True, exist_ok=True)
    tmp = BAZA.with_suffix(".tmp")
    tmp.write_text(json.dumps({"materials": [asdict(m) for m in materials]}, ensure_ascii=False), encoding="utf-8")
    tmp.replace(BAZA)  # never a half-written base


def commit(materials):
    """Group again and keep: called with `work` held."""
    base = k.Base(materials)
    state.update(base=base, campaigns=base.campaigns())
    save(materials)


def regroup():
    """Adds the waiting materials and groups once for all of them, outside any request: Cloudflare gives up at 100 s."""
    with work, idle():
        while pending:
            new, ids = [], set(state["base"].by_id)
            while pending:
                m = pending.popleft()
                if m.id not in ids:
                    new.append(m)
                    ids.add(m.id)
            if new:
                commit(state["base"].materials + new)


@contextlib.contextmanager
def idle():
    """Clears the busy bar however the work ends: a failed regroup must not refresh the page every 3 s for ever."""
    try:
        yield
    except Exception:
        traceback.print_exc()  # the old base stays; the materials of this round are not added
    finally:
        if not pending:  # a delete ending while materials wait must not hide that they are still being added
            state["status"] = ""


EVIDENCE = [f.name for f in fields(k.Material) if f.name not in ("id", "name", "origin", "sources", "missing", "ages")]


def twin(m, others):
    """A material that already holds everything m does: the same folder sent twice, or an address sent again when
    its page would not load (an empty copy). Such m gets no row of its own."""
    if not any(getattr(m, f) for f in EVIDENCE):
        return None
    for x in others:
        if x.id != m.id and m.text in ("", x.text) and m.title in ("", x.title) and set(m.landing) <= set(x.landing) \
                and all({json.dumps(i) for i in getattr(m, f)} <= {json.dumps(i) for i in getattr(x, f)}
                        for f in EVIDENCE if isinstance(getattr(m, f), list)):
            return x
    return None


def add_later(m):
    pending.append(m)
    state["status"] = "Przeliczam kampanie z nowymi materiałami"
    threading.Thread(target=regroup, daemon=True).start()


def drop_later(mid):
    def run():
        with work, idle():
            commit([m for m in state["base"].materials if m.id != mid])
    state["status"] = "Usuwam materiał i przeliczam kampanie"
    threading.Thread(target=run, daemon=True).start()


def load():
    if BAZA.exists():
        materials = [k.Material(**m) for m in json.loads(BAZA.read_text(encoding="utf-8"))["materials"]]
        base = k.Base(materials)
        state.update(base=base, campaigns=base.campaigns())


# ---------- uploads ----------

def parse_multipart(body: Path, ctype: str, spool: Path) -> tuple[dict, list[tuple[str, Path]]]:
    """Fields and files of a multipart body kept on disk; file names keep the folder path the browser sent."""
    found = re.search(r'boundary="?([^";]+)"?', ctype)
    if not found or body.stat().st_size == 0:
        return {}, []
    sep = b"--" + found[1].encode()
    form, files = {}, []
    with open(body, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        pos = mm.find(sep)
        while pos != -1 and mm[pos + len(sep):pos + len(sep) + 2] != b"--":
            start = pos + len(sep) + 2
            end = mm.find(b"\r\n" + sep, start)
            head_end = mm.find(b"\r\n\r\n", start, end)
            if end == -1 or head_end == -1:
                break
            head = email.parser.HeaderParser(policy=email.policy.HTTP).parsestr(mm[start:head_end].decode("utf-8", "replace"))
            name = head.get_param("name", header="content-disposition")
            fname = head.get_param("filename", header="content-disposition")
            if fname is not None:
                if end > head_end + 4:
                    with open(p := spool / f"{len(files):05d}", "wb") as out:
                        for i in range(head_end + 4, end, 1 << 22):
                            out.write(mm[i:min(i + (1 << 22), end)])
                    files.append((str(fname), p))
            elif name:
                form[str(name)] = mm[head_end + 4:end].decode("utf-8", "replace")
            pos = end + 2
    return form, files


def clean(path: str) -> str:
    """A safe relative path: no root, no .., no odd characters."""
    parts = [re.sub(r"[^\w.\- ]", "_", p) for p in path.replace("\\", "/").split("/")]
    # long names lose their middle, not their end: "X.html" and its folder "X_files" stay apart
    return "/".join(p if len(p) <= 120 else p[:60] + "~" + p[-59:] for p in parts if p not in ("", ".", ".."))


def expand(files: list[tuple[str, Path]], spool: Path) -> list[tuple[str, Path]]:
    """Uploaded files with ZIPs unpacked; a ZIP's files sit in a folder named after it."""
    out, total = [], 0
    for fname, p in files:
        rel = clean(fname)
        if not rel:
            continue
        if rel.lower().endswith(".zip") and zipfile.is_zipfile(p):
            with zipfile.ZipFile(p) as z:
                for info in z.infolist():
                    total += info.file_size
                    if total > MAX_UNZIP or len(out) > MAX_FILES:
                        raise ValueError("archiwum jest za duże")
                    if info.filename.endswith(("/", "\\")) or not (inner := clean(info.filename)):  # Windows tools write folders with "\\"
                        continue
                    with z.open(info) as src, open(q := spool / f"z{len(out):05d}", "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    out.append((f"{rel[:-4]}/{inner}", q))
            p.unlink()
        else:
            out.append((rel, p))
    return out


def group(entries: list[tuple[str, Path]], one: bool) -> list[tuple[str, list[tuple[str, Path]]]]:
    """Folders shared by every file are only wrappers; then every subfolder is a material if all files sit in
    subfolders (a set of incidents), else everything is one material (the files of one incident)."""
    name = ""
    while entries and all("/" in r for r, _ in entries) and len({r.split("/", 1)[0] for r, _ in entries}) == 1:
        name = entries[0][0].split("/", 1)[0]
        entries = [(r.split("/", 1)[1], p) for r, p in entries]
    if one or not entries or not all("/" in r for r, _ in entries):
        return [(name, entries)]
    groups: dict[str, list] = {}
    for r, p in entries:
        top, rest = r.split("/", 1)
        groups.setdefault(top, []).append((rest, p))
    return sorted(groups.items(), key=lambda g: (len(g[0]), g[0]))


def new_id(name: str, taken: set) -> str:
    base = re.sub(r"[^\w.\-]+", "-", name).strip("-.")
    base = (base if len(base) <= 32 else base[:32].rsplit("-", 1)[0]).strip("-.") or "material"  # whole words
    out, n = base, 1
    while out in taken:
        n += 1
        out = f"{base}-{n}"
    taken.add(out)
    return out


def absorb(m: k.Material, old: k.Material):
    """What the base already knows about the domain (the ad's text, where the ad really leads) joins a fresh look:
    a page fetched today may show a plain shop while the ad sent people elsewhere."""
    for f in fields(k.Material):
        a, b = getattr(m, f.name), getattr(old, f.name)
        if isinstance(a, list):
            a += [x for x in b if x not in a]
        elif isinstance(a, dict):
            a.update({x: v for x, v in b.items() if x not in a})
    m.text = f"{m.text}\n{old.text}".strip()
    m.title = m.title or old.title
    m.sources.append(f"zapis z bazy o {old.name}")


def analyse_one(m: k.Material, files: list[tuple[str, Path]], root: Path, form: dict) -> k.Material:
    paths = []
    for rel, p in files:
        (target := root / rel).parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            target = target.with_name(f"{len(paths)}-{target.name}")
        p.rename(target)
        paths.append(target)
    if url := form.get("url", "").strip():
        url = url if "://" in url else "https://" + url
        try:
            if not ONLINE:
                raise ConnectionRefusedError("tryb offline, strony nie pobieramy")
            k.fetch(m, url)
        except Exception as err:  # the page is gone or refuses: its address still says something
            m.missing.append(f"strona {url}: niedostępna ({err.__class__.__name__}: {str(err)[:120]})")
            k.add_url(m, url, landing=True)
        if old := known(k.domain_of(k.host_of(url)) or "")[0]:
            absorb(m, old)
    if text := form.get("tekst", "").strip():
        k.add_text(m, text)
        for dom in k.DOMAIN_TEXT.findall(text.lower()):  # an address in the ad's caption is where it leads
            k.add_url(m, "https://" + dom, landing=True)
        m.sources.append("tekst z formularza")
    k.from_files(m, paths, root)
    if ONLINE:
        k.look_up_ages(m)
    return m


def ingest(form: dict, entries: list[tuple[str, Path]], work_dir: Path) -> list[k.Material]:
    """Analyse every group into a material."""
    one = bool(form.get("url", "").strip() or form.get("tekst", "").strip())
    groups = group(entries, one)
    taken = set(state["base"].by_id) | {m.id for m in pending}
    out, failed = [], []
    for i, (name, files) in enumerate(groups):
        label = name or (urlsplit(form["url"].strip()).netloc if form.get("url", "").strip() else "") \
            or (Path(files[0][0]).stem if files else "") \
            or textwrap.shorten(form.get("tekst", ""), 44, placeholder=" …") or "materiał"
        state["status"] = f"Analiza {i + 1} z {len(groups)}: {label}"
        try:
            m = analyse_one(k.Material(id=new_id(label, taken), name=label, origin="dodane"),
                            files, work_dir / f"g{i}", form)
        except Exception as err:  # one unreadable incident does not stop the rest of a set
            if len(groups) == 1:
                raise
            failed.append(f"{label} ({err.__class__.__name__}: {str(err)[:80]})")
            continue
        out.append(m)
    state["error"] = ("Nie udało się odczytać: " + "; ".join(failed)) if failed else ""
    return out


def run_import(limit: int | None):
    """The collector's blocked domains join the base: each one with its ad, page, links, servers and IDs."""
    try:
        with work:
            found = baza.read(str(KOLEKTOR), limit=limit)
            taken = set(state["base"].by_id)
            new = [m for _, m in found if m.id not in taken]
            state["status"] = f"Grupuję {len(taken) + len(new)} materiałów w kampanie"
            commit(state["base"].materials + new)
            state["error"] = ""
    except Exception as err:
        state["error"] = f"Nie udało się wczytać bazy kolektora: {err.__class__.__name__}: {err}"
    finally:
        state["status"] = ""


def to_auditors(dom: str, note: str, token: str, ip: str) -> str:
    """The report on to the auditors' panel, as its own form sends it: the panel checks Turnstile and its limit per IP.
    A key of AUDITORS, or "" when no panel is set."""
    if not PANEL:
        return ""
    req = urllib.request.Request(PANEL, json.dumps({"url": dom, "note": note[:500], "cf-turnstile-response": token}).encode(),
                                 headers={"Content-Type": "application/json", "X-Panel": "1", "Host": PANEL_HOST,
                                          "Cf-Connecting-Ip": ip})
    try:
        with urllib.request.urlopen(req, timeout=20):
            return "ok"
    except urllib.error.HTTPError as err:
        return {429: "limit", 403: "czlowiek"}.get(err.code, "blad")
    except OSError:
        return "blad"


def known(dom: str):
    """The material of a reported domain already in the base, and what was decided about it."""
    m = next((m for m in [*state["base"].materials, *pending] if m.id == dom or dom in m.landing), None)
    if not m:
        return None, ""
    decision = next((s for s in m.sources if s.startswith("decyzja w bazie")), "")
    return m, (f"Domena {dom} jest już w bazie. "
               + (decision.replace("decyzja w bazie: block", "Kolektor ją zablokował").rstrip(". ") + "." if decision
                  else "Zgłoszono ją lub wgrano wcześniej.") + " Poniżej jej werdykt i kampania.")


def run_batch(form, entries, work_dir):
    try:
        with work:
            new, seen = [], [*state["base"].materials, *pending]
            for m in ingest(form, entries, work_dir):
                if old := twin(m, seen + new):
                    state["error"] += f"{' ' if state['error'] else ''}{m.name}: już jest w bazie jako {old.name}, pominięty."
                else:
                    new.append(m)
            state["status"] = f"Grupuję {len(state['base'].materials) + len(new)} materiałów w kampanie"
            commit(state["base"].materials + new)  # once for the whole set: each regroup of the base takes seconds
    except Exception as err:
        state["error"] = f"Nie udało się przeanalizować: {err.__class__.__name__}: {err}"
    finally:
        state["status"] = ""
        shutil.rmtree(work_dir, ignore_errors=True)


# ---------- HTML ----------

e = html.escape


def many_of(n: int) -> str:
    """Polish plural: 1 materiał, 2 materiały, 5 materiałów, 22 materiały."""
    return f"{n} " + ("materiał" if n == 1 else "materiały" if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14) else "materiałów")


def page_no(query, key: str, total: int, per: int) -> tuple[int, int]:
    """The page asked for in ?key= (clamped) and the last page."""
    last = max(1, math.ceil(total / per))
    n = (query or {}).get(key, ["1"])[0]
    return min(max(int(n) if n.isdigit() else 1, 1), last), last


def pager(query, key: str, n: int, last: int, where: str, anchor: str = "") -> str:
    if last == 1:
        return ""
    def go(i):  # the other list keeps its page
        q = {x: v[0] for x, v in (query or {}).items() if x in ("k", "s", "t") + COLS} | {key: str(i)}
        return e(f"{where}?{urlencode(q)}{anchor}")
    prev = f'<a class="btn btn-line btn-sm" href="{go(n - 1)}" rel="prev">← Poprzednie</a>' if n > 1 else ""
    nxt = f'<a class="btn btn-line btn-sm" href="{go(n + 1)}" rel="next">Następne →</a>' if n < last else ""
    return f'<nav class="pager" aria-label="Strony">{prev}<span>Strona {n} z {last}</span>{nxt}</nav>'


def camp_href(cid: str) -> str:
    """A campaign's link: the page of the list it is on."""
    ids = [c["id"] for c in state["campaigns"] if len(c["members"]) > 1]
    return f"/?k={ids.index(cid) // PER_CAMPS + 1 if cid in ids else 1}#{e(cid)}"


def num(x: float) -> str:
    return f"{x:.2f}".replace(".", ",")


def page(title: str, body: str, here: str = "", refresh: bool = False) -> bytes:
    def nav(href, text, key):
        return f'<a href="{href}"{" aria-current=page" if key == here else ""}>{text}</a>'
    busy = (f'<div class="busy" role="status"><div class="wrap"><i></i>{e(state["status"])}. Strona odświeża się sama.'
            f'</div></div>') if state["status"] else ""
    return f"""<!doctype html><html lang="pl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">{'<meta http-equiv="refresh" content="3">' if refresh and state["status"] else ''}
<title>{e(title)} · grannyInternet</title><link rel="stylesheet" href="/static/app.css?v=12">
<link rel="preload" href="/static/fonts/atkinson-next-latin.woff2" as="font" type="font/woff2" crossorigin>
<script src="/static/app.js?v=6" defer></script></head>
<body><a class="skip" href="#tresc">Przejdź do treści</a>{busy}
<header class="wrap top"><a class="mark" href="/"><i></i>grannyInternet <span>/ kampanie</span></a>
<nav aria-label="Główna">{nav("/#kampanie", "Kampanie", "k")}{nav("/#materialy", "Materiały", "m")}{nav("/graf", "Graf powiązań", "g")}
{nav("/eksport.json", "Eksport JSON", "x")}<a href="https://grannyinternet.me/audytorzy/">Strona dla audytorów</a><a class="nav-cta" href="/#dodaj">Zgłoś stronę</a></nav></header>
<main id="tresc">{body}</main>
<footer class="foot"><div class="wrap"><div class="foot-row"><a class="mark" href="/"><i></i>grannyInternet</a>
<span>Wynik to wstępna ocena z przesłankami, nie wyrok. Decyzję podejmuje człowiek.</span></div>
<p>Przesłanki: identyfikatory reklamowe (piksel, reklama, konto Google Ads, strona reklamodawcy), API zestawu strony,
identyczne pliki CSS/JS, domeny i przekierowania, schemat parametrów linku, adres IP, obrazy (dHash),
tekst i narracja, szablon HTML, osoby, marki, temat. Składają się jak niezależne poszlaki. Brak danych nie jest przesłanką
przeciw. Metodyka: README repozytorium.</p></div></footer></body></html>""".encode()


def mlink(mid: str, cls="chip") -> str:
    return f'<a class="{cls}" href="/m/{quote(mid)}">{e(mid)}</a>'


FIRST = 5  # chips shown before "więcej": a campaign of 101 filled a screen


def fold(parts: list[str]) -> str:
    """The first chips, the rest behind a native disclosure (no script)."""
    head = f'<div class="chips">{"".join(parts[:FIRST])}</div>'
    if len(parts) <= FIRST:
        return head
    return (f'{head}<details class="more"><summary>Pokaż jeszcze {len(parts) - FIRST}</summary>'
            f'<div class="chips">{"".join(parts[FIRST:])}</div></details>')


def chips(items, cls="chip") -> str:
    items = [x for x in items if x]
    return fold([f'<span class="{cls}">{e(str(x))}</span>' for x in items]) if items else '<span class="none">brak</span>'


# DB-IP Lite (CC BY 4.0), downloaded into the image by the Dockerfile: looked up here, addresses never leave the container
GEO = [Path(__file__).with_name(f"dbip-{kind}-lite.mmdb") for kind in ("country", "asn")]
_geo = None


def geo() -> list:
    """The two readers, opened once; [] without the files (the card leaves the row out)."""
    global _geo
    if _geo is None:
        try:
            _geo = [maxminddb.open_database(str(p)) for p in GEO]
        except (OSError, ValueError) as err:
            print("geo:", err)
            _geo = []
    return _geo


def hosting(ms) -> list[str]:
    """Who hosts a campaign's sites: each member once per hosting firm and country, then those only behind a CDN.
    Shown, never evidence: one firm hosts hundreds of unrelated scams, linking by it would merge campaigns."""
    if not geo():
        return []
    firms, cdn, bare = Counter(), 0, 0
    for m in ms:
        own = [ip for ip in m.ips if not k.on_cdn(ip)]
        cdn += bool(m.ips) and not own
        bare += not m.ips
        firms.update({w for ip in own if (w := where_is(ip))})
    return ([f"{firm} · {cc} · {n}" for (firm, cc), n in firms.most_common()]
            + ([f"za CDN {cdn}"] if cdn else []) + ([f"bez adresu {bare}"] if bare else []))


def where_is(ip: str):
    """(hosting firm, country) of an address; None behind a CDN, without the files or for junk."""
    if k.on_cdn(ip) or not geo():
        return None
    try:
        country, asn = ((r.get(ip) or {}) for r in _geo)
    except ValueError:  # an address from a HAR that is not one
        return None
    return (asn.get("autonomous_system_organization") or "nieznany dostawca",
            (country.get("country") or {}).get("iso_code") or "?")


def stamp(m, big=False) -> str:
    _, points = k.verdict(m)
    cls, text = ("hi", "Wysokie ryzyko") if points >= 4 else ("mid", "Podejrzane") if points >= 2 else \
        ("ok", "Słaby sygnał") if points else ("ok", "Brak sygnałów")
    return f'<span class="stamp {cls}{" stamp-big" if big else ""}">{text}</span><span class="pts">{points} pkt</span>'


def reasons(ev) -> str:
    return '<ul class="why">' + "".join(
        f"<li><small>{e(kind)}</small><span>{e(why)}<em>siła {num(s)}</em></span></li>" for s, kind, why in ev) + "</ul>"


def pair(score, who: str, ev) -> str:
    return (f'<li class="pair"><div><div class="pair-who">{who}</div><div class="score"><b>{num(score)}</b>'
            f'<i style="--s:{score:.3f}"></i></div></div>{reasons(ev)}</li>')


def topic_of(c) -> str:
    """A campaign's main topic: the one most of its materials have, so a mixed one still sits under one."""
    by_id = state["base"].by_id
    got = Counter(t for x in c["members"] if x in by_id for t in by_id[x].topics)
    return got.most_common(1)[0][0] if got else "bez tematu"


def by_topic(query, campaigns: list, where: str, anchor: str = "") -> tuple[list, str]:
    """The campaigns of the topic in ?t= (all for none or junk) and the filter links with their counts."""
    topics = [topic_of(c) for c in campaigns]
    counts = Counter(topics)
    t = (query or {}).get("t", [""])[0]
    t = t if t in counts else ""

    def link(name: str, label: str, n: int) -> str:
        href = e(where + (f"?{urlencode({'t': name})}" if name else "") + anchor)
        now = ' aria-current="true"' if name == t else ""
        return f'<a href="{href}"{now}>{e(label)} <b>{n}</b></a>'
    nav = (f'<nav class="filters" aria-label="Temat kampanii"><span>Temat:</span>{link("", "wszystkie", len(campaigns))}'
           f'{"".join(link(x, x, n) for x, n in counts.most_common())}</nav>')
    return [c for c, x in zip(campaigns, topics) if not t or x == t], nav


COLS = ("fm", "fw", "fk", "fd", "fo", "ft", "fb")  # the material table's column filters, in column order
LEVELS = {"hi": "Wysokie ryzyko", "mid": "Podejrzane", "low": "Słaby sygnał", "ok": "Brak sygnałów"}
OPTIONS = 150  # shortcut: only the most common people and brands are listed, a search field if the full base needs more


def mat_filter(query, ms, where, pts) -> tuple[list, str, str]:
    """Like Excel's column filters: the materials that pass, the filter row of the table head and the form line over it."""
    q = {x: (query or {}).get(x, [""])[0].strip()[:200] for x in COLS}
    camp = lambda m: c["id"] if (c := where.get(m.id)) and len(c["members"]) > 1 else "nowy"
    level = lambda m: (lambda p: "hi" if p >= 4 else "mid" if p >= 2 else "low" if p else "ok")(pts.get(m.id, 0))
    test = {"fm": lambda m, v: v.lower() in f"{m.id} {m.name}".lower(),
            "fw": lambda m, v: level(m) == v,
            "fk": lambda m, v: camp(m) == v or (v == "w" and camp(m) != "nowy"),
            "fd": lambda m, v: any(v.lower() in d for d in m.landing),
            "fo": lambda m, v: v in m.persons + m.claimed,
            "ft": lambda m, v: v in m.topics or (v == "bez tematu" and not m.topics),
            "fb": lambda m, v: bool(m.missing) == (v == "tak")}
    got = [m for m in ms if all(test[x](m, v) for x, v in q.items() if v)]

    def select(name, label, opts):
        if q[name] and q[name] not in {v for v, _, _ in opts}:
            opts = opts + [(q[name], q[name], 0)]  # the chosen one stays visible even when it fell off the list
        out = "".join(f'<option value="{e(v)}"{" selected" if v == q[name] else ""}>{e(t)}{f" ({n})" if n else ""}</option>'
                      for v, t, n in opts)
        return (f'<td><select name="{name}" form="mf" aria-label="Filtr: {label}"><option value="">wszystkie</option>'
                f'{out}</select></td>')

    def search(name, label, hint):
        return (f'<td><input type="search" name="{name}" form="mf" value="{e(q[name])}" placeholder="{hint}" '
                f'aria-label="Filtr: {label}" autocomplete="off"></td>')
    camps = Counter(camp(m) for m in ms)
    people = Counter(x for m in ms for x in dict.fromkeys(m.persons + m.claimed))
    topics = Counter(t for m in ms for t in (m.topics or ["bez tematu"]))
    levels = Counter(level(m) for m in ms)
    gaps = sum(1 for m in ms if m.missing)
    heads = ('<tr class="tf">' + search("fm", "materiał", "szukaj")
             + select("fw", "wstępny werdykt", [(v, t, levels[v]) for v, t in LEVELS.items()])
             + select("fk", "kampania", [("w", "w kampanii", len(ms) - camps["nowy"]), ("nowy", "nowy wzorzec", camps["nowy"])]
                      + [(c, c, n) for c, n in camps.items() if c != "nowy"])
             + search("fd", "domena strony", "np. .top")
             + select("fo", "osoby i marki", [(x, x, n) for x, n in people.most_common(OPTIONS)])
             + select("ft", "temat", [(x, x, n) for x, n in topics.most_common()])
             + select("fb", "braki danych", [("tak", "z brakami", gaps), ("nie", "bez braków", len(ms) - gaps)]) + "</tr>")
    keep = "".join(f'<input type="hidden" name="{x}" value="{e(v[0])}">' for x, v in (query or {}).items() if x in ("k", "t"))
    tools = (f'<form id="mf" class="tf-form" method="get" action="/#materialy">{keep}'
             f'<button class="btn btn-ink btn-sm">Filtruj</button><span>Pasuje <b>{len(got)}</b> z {len(ms)}</span>'
             + ('<a href="/#materialy">Wyczyść filtry</a>' if any(q.values()) else "") + "</form>")
    return got, heads, tools


def campaign_of(campaigns) -> dict:
    return {mid: c for c in campaigns for mid in c["members"]}


REPORT = """<section class="sec" id="zglos" aria-labelledby="zglos-t"><div class="wrap">
<div class="sec-head"><h2 id="zglos-t">Zgłoś podejrzaną domenę</h2><p><b>Dla każdego, kto trafił na podejrzaną reklamę.</b>
Zgłoszenie trafia do audytorów, którzy decydują o blokadzie. Wystarczy domena albo adres strony z reklamy. Od razu
sprawdzamy stronę na żywo i zapis w bazie: zobaczysz wstępny werdykt, a przy znanej domenie także jej decyzję i to, kto ją podjął.</p></div>
<form class="report" method="post" action="/zglos">
<label class="field"><span>Domena</span><input type="text" name="domena" required maxlength="2000" placeholder="np. oferta-dnia.top"
inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false"></label>
<label class="field"><span>Co wzbudziło podejrzenie (opcjonalnie)</span><input type="text" name="uwaga" maxlength="4000"
placeholder="Np. obiecany cudowny lek, znana osoba w reklamie" autocomplete="off"></label>{turnstile}
<button class="btn btn-ink">Zgłoś domenę <span aria-hidden="true">→</span></button></form></div></section>"""

TURNSTILE = ('<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'  # the panel checks it
             '<div class="cf-turnstile" data-sitekey="{}" data-language="pl"></div>')

COLLECTOR = """<form class="pull" method="post" action="/kolektor"><p><b>Baza kolektora jest podłączona.</b> Wczytaj domeny,
które kolektor zablokował, z reklamą, stroną, serwerami i identyfikatorami. Każda pokaże swoją decyzję: reguła, model albo człowiek.</p>
<label class="field"><span>Ile najnowszych</span><select name="ile"><option value="300">300</option><option value="1000">1000</option>
<option value="0">wszystkie (kilka minut)</option></select></label>
<button class="btn btn-line">Wczytaj zablokowane domeny</button></form>"""

FORM = """<section class="sec" id="dodaj" aria-labelledby="dodaj-t"><div class="wrap">
<div class="sec-head"><h2 id="dodaj-t">Dodaj materiał</h2></div>
<form class="add" method="post" action="/analizuj" enctype="multipart/form-data">
<div class="drop" data-drop><input type="file" name="pliki" multiple aria-label="Pliki materiału">
<b>Upuść tu pliki, folder albo ZIP</b><span class="files" data-files>albo kliknij, żeby wybrać pliki</span>
<div class="pick"><label class="btn btn-line btn-sm">Wybierz folder<input type="file" name="pliki" webkitdirectory multiple
aria-label="Folder z materiałami"></label></div></div>
<div class="fields">
<p class="hint">Każde z trzech jest opcjonalne: pliki, adres albo tekst. Wystarczy jedno z nich.</p>
<label class="field"><span>Adres reklamy lub strony (opcjonalnie)</span><input type="text" name="url" placeholder="https://" inputmode="url" autocomplete="off"></label>
<label class="field"><span>Tekst reklamy albo inna wskazówka (opcjonalnie)</span><textarea name="tekst" placeholder="Np. podpis reklamy, nazwa produktu, adres z paska"></textarea></label>
<label class="check"><input type="checkbox" name="dodaj" value="1" checked>Zapisz w bazie. Kolejne materiały będą z nim porównywane.</label>
<button class="btn btn-ink">Analizuj materiał <span aria-hidden="true">→</span></button>
<p class="hint">{online}</p></div></form>{collector}</div></section>"""


def index(query=None) -> bytes:
    base, campaigns = state["base"], state["campaigns"]
    ms = base.materials
    every = [c for c in campaigns if len(c["members"]) > 1]
    many, filters = by_topic(query, every, "/", "#kampanie")
    kn, klast = page_no(query, "k", len(many), PER_CAMPS)
    where = campaign_of(campaigns)
    if state.get("pts", (None,))[0] is not base:  # verdicts of ~2000 took 3 s on each visit: once per base
        state["pts"] = (base, {m.id: k.verdict(m)[1] for m in ms})
    pts = state["pts"][1]
    high = sum(1 for p in pts.values() if p >= 4)
    shown, heads, tools = mat_filter(query, ms, where, pts)
    sn, slast = page_no(query, "s", len(shown), PER_ROWS)
    lone = len(ms) - sum(len(c["members"]) for c in every)
    error = f'<div class="notice" role="alert">{e(state["error"])}</div>' if state["error"] else ""
    hero = f"""<section class="wrap hero"><p class="eyebrow">Kolekcjoner fejków · demonstrator</p>
<h1>Od pojedynczej reklamy <span>do kampanii.</span></h1>
<p class="lead">Wgraj zrzut reklamy, zapisaną stronę, HAR albo cały folder incydentów. Każdy materiał od razu dostaje
wstępny werdykt, a potem trafia do kampanii albo zostaje nowym wzorcem. Przy każdym powiązaniu widać, na jakiej podstawie.</p>
{error}<dl class="stats"><div><dt>Materiały</dt><dd>{len(ms)}</dd></div><div><dt>Kampanie</dt><dd>{len(every)}</dd></div>
<div class="hot"><dt>Wysokie ryzyko</dt><dd>{high}</dd></div><div><dt>Nowe wzorce</dt><dd>{lone}</dd></div></dl></section>"""
    form = FORM.format(online="Adresy stron i wiek domen (RDAP) sprawdzamy w sieci. Pliki nie opuszczają kontenera."
                       if ONLINE else "Tryb offline: nic nie opuszcza kontenera, adres strony jest tylko zapisany.",
                       collector=COLLECTOR if KOLEKTOR.is_file() else "") + REPORT.format(turnstile=TURNSTILE.format(e(TURNSTILE_SITE)) if TURNSTILE_SITE else "")
    cards = []
    for c in many[(kn - 1) * PER_CAMPS:kn * PER_CAMPS]:
        dups = ", ".join(f"{a} = {b}" for a, b in c["duplicates"])
        pairs = "".join(pair(s, f"{mlink(a, '')} ~ {mlink(b, '')}", ev[:3]) for s, a, b, ev in c["pairs"][:4])
        hosts = hosting([base.by_id[x] for x in c["members"] if x in base.by_id])
        hosts = (f'<div class="wide"><dt>Serwery stron</dt><dd>{chips(hosts)}<p class="none">Firma hostingowa · kraj serwera · '
                 f'liczba stron. Tylko informacja, nie dowód powiązania. <a href="https://db-ip.com">IP Geolocation by DB-IP</a></p></dd></div>') if hosts else ""
        cards.append(f"""<article class="camp" id="{e(c['id'])}"><div class="camp-side"><span class="camp-id">{e(c['id'])}</span>
<h3>{e(c['label'])}</h3><p>{many_of(len(c['members']))} · rodzina {e(c['family'])}</p></div>
<div class="camp-main"><dl class="facts"><div><dt>Materiały</dt><dd>{fold([mlink(x) for x in c['members']])}</dd></div>
<div><dt>Łączy je</dt><dd>{chips(c['linked_by'], 'chip sig')}</dd></div>
<div class="wide"><dt>Domeny stron</dt><dd>{chips(c['domains'])}</dd></div>{hosts}
{f'<div class="wide"><dt>Duplikaty</dt><dd>{chips(dups.split(", "))}</dd></div>' if dups else ''}</dl>
<ol class="pairs" aria-label="Najsilniejsze powiązania">{pairs}</ol></div></article>""")
    if not ms:
        camps = '<p class="lead muted">Baza jest pusta. Dodaj pierwsze materiały w formularzu wyżej.</p>'
    else:
        camps = ("".join(cards) + pager(query, "k", kn, klast, "/", "#kampanie")
                 or '<p class="lead muted">Żadne dwa materiały nie mają jeszcze powiązania ≥ 0,5.</p>')
    rows = []
    for m in shown[(sn - 1) * PER_ROWS:sn * PER_ROWS]:
        c = where.get(m.id)
        camp = (f'<a href="{camp_href(c["id"])}">{e(c["id"])}</a>' if c and len(c["members"]) > 1
                else '<span class="muted">nowy wzorzec</span>')
        rows.append(f"""<tr><td class="id">{mlink(m.id, '')}<small>{e(m.name) if m.name != m.id else ''}</small></td>
<td>{stamp(m)}</td><td>{camp}</td><td>{chips(m.landing[:3])}</td><td>{chips(m.persons + m.claimed)}</td>
<td>{chips(m.topics)}</td><td class="num">{len(m.missing) or '–'}</td></tr>""")
    rows = rows or ['<tr><td colspan="7" class="muted">Żaden materiał nie pasuje do filtrów.</td></tr>']
    table = (f"""{tools}<div class="table"><table><thead><tr><th>Materiał</th><th>Wstępny werdykt</th><th>Kampania</th>
<th>Domena strony</th><th>Osoby i marki</th><th>Temat</th><th>Braki danych</th></tr>{heads}</thead><tbody>{''.join(rows)}</tbody></table></div>
{pager(query, "s", sn, slast, "/", "#materialy")}"""
             if ms else '<p class="lead muted">Nic tu jeszcze nie ma.</p>')
    clear = ('<form class="rm" method="post" action="/wyczysc" data-confirm="Usunąć wszystkie materiały z bazy?">'
             '<button class="btn btn-line btn-sm">Wyczyść bazę</button></form>') if ms else ""
    return page("Kampanie", f"""{hero}{form}
<section class="sec" id="kampanie" aria-labelledby="kampanie-t"><div class="wrap"><div class="sec-head"><h2 id="kampanie-t">Kampanie</h2>
<p>Materiał należy do kampanii, gdy ma w niej co najmniej jedno powiązanie o sile ≥ {num(k.LINK)}. Kampanie, których
materiały są średnio podobne w stopniu ≥ {num(k.FAMILY)}, tworzą rodzinę. {many_of(lone)} bez takiego powiązania to nowe wzorce.</p></div>
{filters}<div class="camps">{camps}</div></div></section>
<section class="sec" id="materialy" aria-labelledby="materialy-t"><div class="wrap"><div class="sec-head"><h2 id="materialy-t">Materiały</h2>
<p>Wstępny werdykt to suma punktów za cechy oszustwa: od 4 punktów wysokie ryzyko, od 2 podejrzane. Kliknij materiał,
żeby zobaczyć powody, braki danych i podobne materiały.</p></div>{table}{clear}</div></section>""", "k", refresh=True)


def features(m) -> str:
    rows = [("Tytuł strony", e(m.title) or '<span class="none">brak</span>'), ("Domeny stron", chips(m.landing)),
            ("Wiek domen (RDAP)", chips(f"{d}: {a} dni" for d, a in m.ages.items() if a is not None)),
            ("Przekierowania", chips(" → ".join(c) for c in m.redirects)), ("Identyfikatory", chips(m.trackers)),
            ("Schemat parametrów linku", chips(m.params)), ("IP serwera", chips(m.ips)),
            ("Osoby", chips(m.persons)), ("Udawane marki", chips(m.claimed)), ("Temat", chips(m.topics)),
            ("Pola formularzy", chips(m.forms)), ("API strony (zestaw)", chips(m.kit)), ("Własne pliki CSS/JS", chips(m.files)),
("Obrazy (dHash)", f'<span class="num">{len({n for _, n in m.images})}</span>'),
            ("Inne domeny", chips(m.domains[:25])), ("Pliki strony", chips(m.assets[:20])), ("Przeczytane", chips(m.sources))]
    dl = "".join(f"<div><dt>{a}</dt><dd>{b}</dd></div>" for a, b in rows)
    text = (f'<details class="more text-more"><summary>Odczytany tekst ({len(m.text)} znaków)</summary>'
            f'<div class="text">{e(m.text[:3000])}</div></details>') if m.text else ""
    return f'<dl class="feat">{dl}</dl>{text}'


def material(m, placed=None, base=None, note="", again="", wait=False) -> bytes:
    base = base or state["base"]
    flags = "".join(f"<li><b>+{p}</b><span>{e(why)}</span></li>" for p, why in k.flags(m))
    flags = f'<ol class="flags">{flags}</ol>' if flags else '<p class="muted">Nic z cech, które znamy z oszustw.</p>'
    placed = placed or base.place(m, state["campaigns"])
    if placed["campaign"]:
        avg, top = placed["fit"][placed["campaign"]]
        where = (f'<a class="place-id" href="{camp_href(placed["campaign"])}">{e(placed["campaign"])}</a>'
                 f'<p>Najsilniejsze powiązanie z kampanią {num(top)}, średnio {num(avg)}.</p>')
    else:
        best = max(placed["fit"].items(), key=lambda x: x[1][1], default=None)
        where = (f'<span class="place-id new">Nowy wzorzec</span><p>Żadne powiązanie z twardą przesłanką nie sięga '
                 f'{num(k.LINK)}.' + (f" Najbliżej jest {e(best[0])} ({num(best[1][1])})." if best and best[1][1] > 0
                                      else " Same poszlaki (narracja, serwer, temat) nie tworzą kampanii.") + "</p>")
    gaps = "".join(f"<li>{e(x)}</li>" for x in m.missing)
    gaps = (f'<h2 style="margin-top:28px">Czego zabrakło</h2><ul class="gaps">{gaps}</ul><p class="hint" style="margin-top:10px">'
            f'Brak danych nie obniża wyniku: to brak przesłanki, nie przesłanka przeciw.</p>') if gaps else \
        '<p class="hint" style="margin-top:20px">Wszystkie wgrane źródła udało się odczytać.</p>'
    similar = []
    for score, other in placed["similar"]:
        if score < 0.05:
            break
        similar.append(pair(score, mlink(other, ""), base.compare(m, base.by_id[other])[1]))
    similar = f'<ol class="pairs">{"".join(similar)}</ol>' if similar else '<p class="muted">Brak podobnych materiałów.</p>'
    remove = (f'<form class="rm" method="post" action="/usun"><input type="hidden" name="id" value="{e(m.id)}">'
              f'<button class="btn btn-line btn-sm">Usuń z bazy</button></form>') if m.id in state["base"].by_id else ""
    more = (f'<p class="again"><a class="btn btn-ink btn-sm" href="/#{again}">'
            f'{"Zgłoś kolejną domenę" if again == "zglos" else "Dodaj kolejny materiał"} <span aria-hidden="true">→</span></a></p>'
            if again else "")
    note = f'<div class="notice" role="status">{note}{more}</div>' if note else ""
    return page(m.id, f"""<section class="wrap hero"><div class="case-head"><div><p class="eyebrow">Materiał {e(m.id)}</p>
<h1>{e(m.name)}</h1></div><div>{stamp(m, big=True)}</div></div>{note}
<div class="case-grid"><div class="panel"><h2>Co zwraca uwagę</h2>{flags}</div>
<div class="panel place"><h2>Kampania</h2>{where}{gaps}</div></div></section>
<section class="sec"><div class="wrap"><div class="sec-head"><h2>Podobne materiały</h2><p>Każde powiązanie z przesłankami
i ich siłą. Przesłanki składają się jak niezależne poszlaki: 1 − ∏(1 − siła).</p></div>{similar}</div></section>
<section class="sec"><div class="wrap"><div class="sec-head"><h2>Wyodrębnione cechy</h2><p>To, co odczytaliśmy z plików,
strony i tekstu. Z tych cech biorą się przesłanki.</p></div>{features(m)}{remove}</div></section>""", refresh=wait)


def graph(query=None) -> bytes:
    base = state["base"]
    chosen, filters = by_topic(query, state["campaigns"], "/graf")
    gn, glast = page_no(query, "g", len(chosen), PER_GRAPH)
    campaigns = chosen[(gn - 1) * PER_GRAPH:gn * PER_GRAPH]  # biggest first
    cols = max(1, math.ceil(math.sqrt(len(campaigns))))
    cell, pos, parts = 280, {}, []
    for i, c in enumerate(campaigns):
        cx, cy = cell * (i % cols) + cell / 2, cell * (i // cols) + cell / 2 + 10
        r = 0 if len(c["members"]) == 1 else min(40 + 12 * len(c["members"]), cell / 2 - 56)
        parts.append(f'<circle class="g-ring" cx="{cx}" cy="{cy}" r="{r + 24}"/>'
                     f'<text class="g-label" x="{cx}" y="{cy - r - 36}" text-anchor="middle">{e(c["id"])} '
                     f'<tspan>{e(c["label"][:30])}</tspan></text>')
        for j, mid in enumerate(c["members"]):
            a = 2 * math.pi * j / len(c["members"]) - math.pi / 2
            pos[mid] = (cx + r * math.cos(a), cy + r * math.sin(a))
    lines, ms = [], [base.by_id[x] for c in campaigns for x in c["members"] if x in base.by_id]
    # pairs scored when grouping, strongest first; a campaign of 101 drew 5050 lines: 2 MB and 6 s
    for c in campaigns:
        for s, a, b, ev in [p for p in c["pairs"] if p[0] >= k.FAMILY][:3 * len(c["members"])]:
            if a in pos and b in pos:
                (x1, y1), (x2, y2) = pos[a], pos[b]
                why = f"{a} ~ {b}: {num(s)}\n" + "\n".join(w for _, _, w in ev[:4])
                lines.append(f'<line class="g-line" x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" '
                             f'stroke-width="{1 + 5 * s:.1f}" opacity="{0.2 + 0.6 * s:.2f}"><title>{e(why)}</title></line>')
    nodes = []
    for m in ms:
        if m.id in pos:
            x, y = pos[m.id]
            pts = k.verdict(m)[1]
            cls = "hi" if pts >= 4 else "mid" if pts >= 2 else "ok"
            nodes.append(f'<a href="/m/{quote(m.id)}"><circle class="g-node {cls}" cx="{x:.0f}" cy="{y:.0f}" r="17">'
                         f'<title>{e(m.name)}</title></circle><text class="g-text {cls}" x="{x:.0f}" y="{y + 4:.0f}" '
                         f'text-anchor="middle">{e(m.id[:4])}</text></a>')
    rows = max(1, math.ceil(len(campaigns) / cols))
    svg = (f'<svg viewBox="0 0 {cols * cell} {rows * cell + 20}" role="img" aria-label="Graf powiązań materiałów">'
           f'{"".join(parts)}{"".join(lines)}{"".join(nodes)}</svg>'
           f'{pager(query, "g", gn, glast, "/graf")}') if ms else '<p class="muted">Baza jest pusta.</p>'
    t = (query or {}).get("t", [""])[0]
    live = (f'<div class="graph g-live" data-src="/graf.json{e("?" + urlencode({"t": t}) if t else "")}" hidden>'
            '<div class="g-tools"><button type="button" class="btn btn-line btn-sm" data-zoom="1.25">Przybliż</button>'
            '<button type="button" class="btn btn-line btn-sm" data-zoom="0.8">Oddal</button>'
            '<button type="button" class="btn btn-line btn-sm" data-fit>Pokaż całość</button>'
            '<button type="button" class="btn btn-line btn-sm" data-reset>Zwiń wszystko</button></div>'
            '<svg role="group" aria-label="Graf kampanii: kliknij kampanię albo materiał, żeby go rozwinąć"></svg>'
            '<aside class="g-info" aria-live="polite"><p class="muted">Kliknij kampanię, żeby zobaczyć jej materiały. '
            'Kliknij materiał, żeby zobaczyć, co dzieli z innymi.</p></aside></div>') if ms else ""
    return page("Graf powiązań", f"""<section class="wrap hero"><p class="eyebrow">Graf powiązań</p>
<h1>Kto z kim <span>i dlaczego.</span></h1><p class="lead">Na starcie same kampanie: im większa kropka, tym więcej
materiałów. Kliknij kampanię, a rozwiną się jej materiały i łączące je przesłanki. Kliknij materiał, a pokaże, co dzieli
z innymi (identyfikatory reklam, osoby, marki, domeny, serwer) i z jakimi kampaniami. Klik w rozwinięty węzeł go zwija. Kółko myszy przybliża, przeciąganie tła przesuwa widok.
Przerywana linia między kampaniami to słabe podobieństwo (≥ {num(k.FAMILY)}), za słabe, by je połączyć.</p></section>
<section class="wrap">{filters}<ul class="legend"><li><i class="camp"></i>kampania</li><li><i class="hi"></i>wysokie ryzyko</li>
<li><i></i>podejrzane</li><li><i class="ok"></i>brak sygnałów</li><li><i class="trait"></i>wspólna cecha</li>
<li><i class="ln"></i>powiązanie</li></ul>{live}<noscript><div class="graph">{svg}</div></noscript>
<script src="/static/graf.js?v=4" defer></script></section>""", "g")


TRAIT_KINDS = ("identyfikator", "zestaw", "pliki", "osoba", "marka", "domena", "serwer", "hosting")
_walk = {"of": None}  # what walking the graph needs, worked out once per grouping


def walk() -> dict:
    """Material -> campaign, trait -> materials and the weak links between campaigns, for the current grouping."""
    base, campaigns = state["base"], state["campaigns"]
    if _walk["of"] is not campaigns:
        camp_of = {x: c["id"] for c in campaigns for x in c["members"]}
        holders = {}
        for m in base.materials:
            for t in traits(m, base):
                holders.setdefault(t, []).append(m.id)
        _walk.update(of=campaigns, camp_of=camp_of, holders=holders, soft=soft_links(base, campaigns))
    return _walk


def traits(m, base) -> set:
    """What a material may share with others: ad and analytics IDs, names, rare domains and servers, the hosting firm.
    The firm is information only: one firm hosts hundreds of unrelated scams."""
    common = base.common
    return ({("identyfikator", x) for x in m.trackers} | {("osoba", x) for x in m.persons}
            | {("zestaw", x) for x in m.kit if ("k", x) not in common}
            | {("pliki", x) for x in m.files if ("f", x) not in common}
            | {("marka", x) for x in m.claimed} | {("domena", x) for x in m.domains if ("d", x) not in common}
            | {("serwer", x) for x in m.ips if ("i", x) not in common}
            | {("hosting", f"{w[0]} · {w[1]}") for x in m.ips if (w := where_is(x))})


def soft_links(base, campaigns) -> list:
    """Campaigns whose closest members score >= FAMILY: too weak to merge them, worth a dashed line.
    Taken from the pair scores grouping already computed, one campaign against all at a time."""
    multi = [c for c in campaigns if len(c["members"]) > 1]
    if not multi:
        return []
    s = base.matrix()
    lab = np.full(len(base.materials), -1)
    for i, c in enumerate(multi):
        lab[[base.row[x] for x in c["members"]]] = i
    out = []
    for i, c in enumerate(multi):
        mine = np.nonzero(lab == i)[0]
        top = s[mine].max(0)
        best = np.full(len(multi), -1.0)
        later = lab > i
        np.maximum.at(best, lab[later], top[later])
        for j in np.nonzero(best >= k.FAMILY)[0]:
            theirs = np.nonzero(lab == j)[0]
            r, q = np.unravel_index(s[np.ix_(mine, theirs)].argmax(), (len(mine), len(theirs)))
            a, b = base.materials[mine[r]], base.materials[theirs[q]]
            out.append({"a": c["id"], "b": multi[j]["id"], "s": round(float(best[j]), 3),
                        "why": [f"{a.id} ~ {b.id}"] + [w for _, _, w in base.compare(a, b)[1][:3]]})
    return out


def node(m) -> dict:
    pts = k.verdict(m)[1]
    return {"id": m.id, "label": (m.landing or [m.name])[0], "cls": "hi" if pts >= 4 else "mid" if pts >= 2 else "ok",
            "campaign": walk()["camp_of"].get(m.id, "")}


def graph_data(query) -> dict:
    """The expandable graph: ?c= a campaign's materials, ?m= what a material shares, else the campaigns (of ?t=)."""
    q = {x: v[0] for x, v in (query or {}).items()}
    base, w = state["base"], walk()
    if (cid := q.get("c")) is not None:
        c = next((x for x in state["campaigns"] if x["id"] == cid), None)
        if not c:
            return {"error": "Nie ma takiej kampanii."}
        n = len(c["members"])
        return {"id": cid, "members": [node(base.by_id[x]) for x in c["members"] if x in base.by_id],
                "links": [{"a": a, "b": b, "s": round(s, 3), "why": [x for _, _, x in ev[:3]]}  # strongest only, as /graf
                          for s, a, b, ev in [p for p in c["pairs"] if p[0] >= k.FAMILY][:3 * n]]}
    if (mid := q.get("m")) is not None:
        m = base.by_id.get(mid)
        if not m:
            return {"error": "Nie ma takiego materiału."}
        shared = sorted(((t, w["holders"][t]) for t in traits(m, base) if len(w["holders"].get(t, [])) > 1),
                        key=lambda x: (TRAIT_KINDS.index(x[0][0]), len(x[1])))  # IDs first, then the rarest
        return {**node(m), "href": f"/m/{quote(m.id)}", "traits": [
            {"id": f"{kind}:{name}", "kind": kind, "name": name, "more": max(0, len(ids) - 1 - TRAIT_OTHERS),
             "others": [node(base.by_id[x]) for x in ids if x != m.id][:TRAIT_OTHERS]}
            for (kind, name), ids in shared[:TRAITS]]}
    chosen = by_topic(query, [c for c in state["campaigns"] if len(c["members"]) > 1], "/graf")[0]
    ids = {c["id"] for c in chosen}
    return {"hubs": [{"id": c["id"], "label": c["label"], "topic": topic_of(c), "n": len(c["members"]),
                      "family": c["family"], "href": camp_href(c["id"])} for c in chosen],
            "links": [x for x in w["soft"] if x["a"] in ids and x["b"] in ids]}


TRAITS, TRAIT_OTHERS = 10, 8  # per material: a shared host can hold hundreds, the graph shows a handful

def export() -> bytes:
    base = state["base"]
    out = {"campaigns": [{**{x: c[x] for x in ("id", "family", "label", "members", "linked_by", "domains", "duplicates")},
                          "pairs": [{"a": a, "b": b, "score": round(s, 3), "evidence": [w for _, _, w in ev]}
                                    for s, a, b, ev in c["pairs"]]} for c in state["campaigns"]],
           "materials": [{**{x: v for x, v in asdict(m).items() if x not in ("shingles", "template", "text")},
                          "verdict": k.verdict(m)[0], "flags": [w for _, w in k.flags(m)]} for m in base.materials]}
    return json.dumps(out, ensure_ascii=False, indent=1).encode()


TYPES = {".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".woff2": "font/woff2"}


class Handler(BaseHTTPRequestHandler):
    def send(self, body: bytes, ctype="text/html; charset=utf-8", code=200, cache=False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        cf = " https://challenges.cloudflare.com" if TURNSTILE_SITE else ""  # Turnstile's script and its frame
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; "
                         f"script-src 'self'{cf}; frame-src {cf.strip() or repr('none')}; font-src 'self'; "
                         "img-src data:; connect-src 'self'; form-action 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "max-age=3600" if cache else "no-store")
        self.end_headers()
        self.wfile.write(body)

    def go(self, where: str):
        self.send_response(303)
        self.send_header("Location", where)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def result(self, m, note: str, again: str = "dodaj"):
        """Post/Redirect/Get: the result lives at its own address, Back and refresh do not send the form again."""
        token = secrets.token_urlsafe(9)
        results[token] = (m, note, again)
        while len(results) > 200:  # shortcut: kept in memory only, a restart forgets them; enough for a demo
            results.popitem(last=False)
        return self.go(f"/wynik/{token}")

    def do_GET(self):
        path = unquote(urlsplit(self.path).path)
        query = parse_qs(urlsplit(self.path).query)
        if path == "/":
            return self.send(index(query))
        if path == "/graf":
            return self.send(graph(query))
        if path == "/graf.json":
            return self.send(json.dumps(graph_data(query), ensure_ascii=False).encode(), "application/json; charset=utf-8")
        if path == "/eksport.json":
            return self.send(export(), "application/json; charset=utf-8")
        if path.startswith("/static/") and (f := STATIC / clean(path[8:])).is_file() and f.suffix in TYPES:
            return self.send(f.read_bytes(), TYPES[f.suffix], cache=True)
        if path.startswith("/m/") and (m := state["base"].by_id.get(path[3:])
                                       or next((x for x in pending if x.id == path[3:]), None)):
            return self.send(material(m))
        if path.startswith("/wynik/") and (r := results.get(path[7:])):
            note, wait = saved_note(r[0], r[1])
            return self.send(material(r[0], note=note, again=r[2], wait=wait))
        if path.startswith("/wynik/"):
            return self.send(page("Wynik wygasł", '<section class="wrap hero"><h1>Ten wynik już wygasł.</h1>'
                                                  '<p class="lead"><a href="/#dodaj">Dodaj materiał jeszcze raz</a></p></section>'), code=404)
        self.send(page("Brak", '<section class="wrap hero"><h1>Nie ma takiej strony.</h1></section>'), code=404)

    def do_POST(self):
        origin = self.headers.get("Origin")
        if origin and urlsplit(origin).netloc != self.headers.get("Host"):  # another site's form cannot drive this one
            return self.send(b"", code=403)
        size = int(self.headers.get("Content-Length") or 0)
        if size > MAX_UPLOAD:
            return self.send(page("Za duże", '<section class="wrap hero"><h1>Za duże: limit to 2 GB.</h1></section>'), code=413)
        work_dir = Path(tempfile.mkdtemp(prefix="wgrane-"))
        try:
            with open(body := work_dir / "body", "wb") as out:
                left = size
                while left > 0 and (chunk := self.rfile.read(min(left, 1 << 20))):
                    out.write(chunk)
                    left -= len(chunk)
            ctype = self.headers.get("Content-Type", "")
            if ctype.startswith("multipart/"):
                (spool := work_dir / "spool").mkdir()
                form, files = parse_multipart(body, ctype, spool)
            else:
                form = {x: v[0] for x, v in parse_qs(body.read_text("utf-8", "replace")).items()}
                files = []
            body.unlink()
            if self.path == "/usun":
                drop_later(form.get("id"))
                return self.go("/#materialy")
            if self.path == "/wyczysc":
                with work:
                    commit([])
                return self.go("/")
            if self.path == "/kolektor":
                if not KOLEKTOR.is_file():
                    return self.send(page("Brak", '<section class="wrap hero"><h1>Baza kolektora nie jest podłączona.</h1></section>'), code=404)
                state["status"] = "Wczytuję zablokowane domeny z kolektora"  # before the redirect, so the page refreshes
                threading.Thread(target=run_import, args=(min(int(form.get("ile") or 0) or MAX_IMPORT, MAX_IMPORT) if MAX_IMPORT else int(form.get("ile") or 0) or None,), daemon=True).start()
                return self.go("/#kampanie")
            if self.path == "/zglos":
                raw = form.get("domena", "").strip()
                dom = k.domain_of(k.host_of(raw if "://" in raw else "https://" + raw))
                if not dom:
                    return self.send(page("Zła domena", '<section class="wrap hero"><h1>To nie wygląda na domenę.</h1>'
                                                       '<p class="lead"><a href="/#zglos">Wróć do formularza</a></p></section>'), code=400)
                sent = to_auditors(dom, form.get("uwaga", ""), form.get("cf-turnstile-response", ""),
                                   self.headers.get("Cf-Connecting-Ip", ""))
                old, note = known(dom)
                # always fetch the live page; analyse_one merges the base record of a known domain into it
                m = ingest({"url": f"https://{dom}/", "tekst": form.get("uwaga", "")}, [], work_dir)[0]
                if not old:
                    add_later(m)
                    note = SAVED
                return self.result(m, e(" ".join(filter(None, (note, AUDITORS.get(sent))))), "zglos")
            if self.path != "/analizuj":
                return self.send(page("Brak", '<section class="wrap hero"><h1>Nie ma takiej strony.</h1></section>'), code=404)
            entries = expand(files, spool) if files else []
            if not (form.get("url", "").strip() or form.get("tekst", "").strip() or entries):
                return self.send(page("Pusto", '<section class="wrap hero"><h1>Podaj adres, tekst albo pliki.</h1>'
                                               '<p class="lead"><a href="/#dodaj">Wróć do formularza</a></p></section>'), code=400)
            keep = bool(form.get("dodaj"))
            one = form.get("url", "").strip() or form.get("tekst", "").strip()
            if not one and len(group(entries, False)) > 1:  # a set of incidents: read in the background, page refreshes
                state["status"] = "Rozpakowuję wgrane pliki"  # set before the redirect, so the page knows to refresh
                threading.Thread(target=run_batch, args=(form, entries, work_dir), daemon=True).start()
                work_dir = None
                return self.go("/#kampanie")
            m = ingest(form, entries, work_dir)[0]
            state["status"] = ""
            if keep and (old := twin(m, [*state["base"].materials, *pending])):
                return self.result(m, f"Ten materiał już jest w bazie jako {mlink(old.id, '')}, więc nie zapisaliśmy go "
                                      "drugi raz. Poniżej jego ocena.")
            if keep:
                add_later(m)
            # shortcut: placed against the base without it, so its narration (TF-IDF) does not count; enough to place one
            return self.result(m, SAVED if keep else
                               "Tego materiału nie zapisano w bazie. Pokazujemy, gdzie by pasował.")
        except Exception as err:
            state["status"] = ""
            self.send(page("Błąd", f'<section class="wrap hero"><h1>Nie udało się przeanalizować.</h1>'
                                   f'<p class="lead">{e(err.__class__.__name__)}: {e(str(err))}</p></section>'), code=500)
        finally:
            if work_dir:
                shutil.rmtree(work_dir, ignore_errors=True)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    load()
    host, port = os.environ.get("HOST", "0.0.0.0"), int(os.environ.get("PORT", "8501"))
    print(f"kampanie: http://127.0.0.1:{port}", flush=True)
    ThreadingHTTPServer((host, port), Handler).serve_forever()
