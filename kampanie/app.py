"""GUI of kampanie: http://127.0.0.1:8501. The user uploads materials in the browser (files, a folder, a ZIP, a URL or
an ad text); their features are kept in /data/baza.json and every new one is compared with all the others."""
import email.parser
import email.policy
import html
import json
import math
import mmap
import os
import re
import shutil
import tempfile
import textwrap
import threading
import zipfile
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit

import baza
import kampanie as k

BAZA = Path(os.environ.get("BAZA", "/data/baza.json"))
ONLINE = os.environ.get("ONLINE", "1") == "1"  # RDAP ages of landing domains; 0 = nothing leaves the container
KOLEKTOR = Path(os.environ.get("KOLEKTOR", "/verdicts/verdicts.db"))  # the collector's verdicts, mounted read-only
STATIC = Path(__file__).with_name("static")
MAX_UPLOAD = 2_000_000_000  # a whole incident set with its videos; the body goes to disk, never to memory
MAX_UNZIP, MAX_FILES = 3_000_000_000, 20_000  # a ZIP bomb stops here
work = threading.Lock()  # one writer at a time: uploads and deletes
state = {"base": k.Base([]), "campaigns": [], "status": "", "error": ""}


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
    if text := form.get("tekst", "").strip():
        k.add_text(m, text)
        for dom in k.DOMAIN_TEXT.findall(text.lower()):  # an address in the ad's caption is where it leads
            k.add_url(m, "https://" + dom, landing=True)
        m.sources.append("tekst z formularza")
    k.from_files(m, paths, root)
    if ONLINE:
        k.look_up_ages(m)
    return m


def ingest(form: dict, entries: list[tuple[str, Path]], work_dir: Path, keep: bool) -> list[k.Material]:
    """Analyse every group into a material; with `keep` each one joins the base as soon as it is read."""
    one = bool(form.get("url", "").strip() or form.get("tekst", "").strip())
    groups = group(entries, one)
    taken = set(state["base"].by_id)
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
        if keep:
            commit(state["base"].materials + [m])
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


def known(dom: str):
    """The material of a reported domain already in the base, and what was decided about it."""
    m = next((m for m in state["base"].materials if m.id == dom or dom in m.landing), None)
    if not m:
        return None, ""
    decision = next((s for s in m.sources if s.startswith("decyzja w bazie")), "")
    return m, (f"Domena {dom} jest już w bazie. "
               + (decision.replace("decyzja w bazie: block", "Kolektor ją zablokował").rstrip(". ") + "." if decision
                  else "Zgłoszono ją lub wgrano wcześniej.") + " Poniżej jej werdykt i kampania.")


def run_batch(form, entries, work_dir):
    try:
        with work:
            ingest(form, entries, work_dir, keep=True)
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


def num(x: float) -> str:
    return f"{x:.2f}".replace(".", ",")


def page(title: str, body: str, here: str = "", refresh: bool = False) -> bytes:
    def nav(href, text, key):
        return f'<a href="{href}"{" aria-current=page" if key == here else ""}>{text}</a>'
    busy = (f'<div class="busy" role="status"><div class="wrap"><i></i>{e(state["status"])}. Strona odświeża się sama.'
            f'</div></div>') if state["status"] else ""
    return f"""<!doctype html><html lang="pl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">{'<meta http-equiv="refresh" content="3">' if refresh and state["status"] else ''}
<title>{e(title)} · grannyInternet</title><link rel="stylesheet" href="/static/app.css?v=3">
<link rel="preload" href="/static/fonts/atkinson-next-latin.woff2" as="font" type="font/woff2" crossorigin>
<script src="/static/app.js?v=2" defer></script></head>
<body><a class="skip" href="#tresc">Przejdź do treści</a>{busy}
<header class="wrap top"><a class="mark" href="/"><i></i>grannyInternet <span>/ kampanie</span></a>
<nav aria-label="Główna">{nav("/#kampanie", "Kampanie", "k")}{nav("/#materialy", "Materiały", "m")}{nav("/graf", "Graf powiązań", "g")}
{nav("/eksport.json", "Eksport JSON", "x")}<a class="nav-cta" href="/#zglos">Zgłoś domenę</a></nav></header>
<main id="tresc">{body}</main>
<footer class="foot"><div class="wrap"><div class="foot-row"><a class="mark" href="/"><i></i>grannyInternet</a>
<span>Wynik to wstępna ocena z przesłankami, nie wyrok. Decyzję podejmuje człowiek.</span></div>
<p>Przesłanki: identyfikatory reklamowe, domeny i przekierowania, schemat parametrów linku, adres IP, obrazy (dHash),
tekst i narracja, szablon HTML, osoby, marki, temat. Składają się jak niezależne poszlaki. Brak danych nie jest przesłanką
przeciw. Metodyka: README repozytorium.</p></div></footer></body></html>""".encode()


def mlink(mid: str, cls="chip") -> str:
    return f'<a class="{cls}" href="/m/{quote(mid)}">{e(mid)}</a>'


def chips(items, cls="chip") -> str:
    items = [x for x in items if x]
    return (f'<div class="chips">{"".join(f"<span class={chr(34)}{cls}{chr(34)}>{e(str(x))}</span>" for x in items)}</div>'
            if items else '<span class="none">brak</span>')


def stamp(m, big=False) -> str:
    _, points = k.verdict(m)
    cls, text = ("hi", "Wysokie ryzyko") if points >= 4 else ("mid", "Podejrzane") if points >= 2 else ("ok", "Brak sygnałów")
    return f'<span class="stamp {cls}{" stamp-big" if big else ""}">{text}</span><span class="pts">{points} pkt</span>'


def reasons(ev) -> str:
    return '<ul class="why">' + "".join(
        f"<li><small>{e(kind)}</small><span>{e(why)}<em>siła {num(s)}</em></span></li>" for s, kind, why in ev) + "</ul>"


def pair(score, who: str, ev) -> str:
    return (f'<li class="pair"><div><div class="pair-who">{who}</div><div class="score"><b>{num(score)}</b>'
            f'<i style="--s:{score:.3f}"></i></div></div>{reasons(ev)}</li>')


def campaign_of(campaigns) -> dict:
    return {mid: c for c in campaigns for mid in c["members"]}


REPORT = """<section class="sec" id="zglos" aria-labelledby="zglos-t"><div class="wrap">
<div class="sec-head"><h2 id="zglos-t">Zgłoś podejrzaną domenę</h2><p>Wystarczy domena albo adres strony z reklamy. Jeśli
domena już jest w bazie, zobaczysz jej decyzję i to, kto ją podjął. Nowa dostaje wstępny werdykt i miejsce w kampanii.</p></div>
<form class="report" method="post" action="/zglos">
<label class="field"><span>Domena</span><input type="text" name="domena" required maxlength="2000" placeholder="np. oferta-dnia.top"
inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false"></label>
<label class="field"><span>Co wzbudziło podejrzenie (opcjonalnie)</span><input type="text" name="uwaga" maxlength="4000"
placeholder="Np. obiecany cudowny lek, znana osoba w reklamie" autocomplete="off"></label>
<button class="btn btn-ink">Zgłoś domenę <span aria-hidden="true">→</span></button></form>{collector}</div></section>"""

COLLECTOR = """<form class="pull" method="post" action="/kolektor"><p><b>Baza kolektora jest podłączona.</b> Wczytaj domeny,
które kolektor zablokował, z reklamą, stroną, serwerami i identyfikatorami. Każda pokaże swoją decyzję: reguła, model albo człowiek.</p>
<label class="field"><span>Ile najnowszych</span><select name="ile"><option value="300">300</option><option value="1000">1000</option>
<option value="0">wszystkie (kilka minut)</option></select></label>
<button class="btn btn-line">Wczytaj zablokowane domeny</button></form>"""

FORM = """<section class="sec" id="dodaj" aria-labelledby="dodaj-t"><div class="wrap">
<div class="sec-head"><h2 id="dodaj-t">Dodaj materiał</h2><p>Pliki jednego incydentu dają jeden materiał. Folder albo ZIP
z podfolderami daje tyle materiałów, ile jest podfolderów. Czytamy zrzuty ekranu (OCR), zapisane strony (.html, .mhtml),
HAR, metadane wideo (.info.json) i tekst. Wideo jest tylko odnotowane.</p></div>
<form class="add" method="post" action="/analizuj" enctype="multipart/form-data">
<div class="drop" data-drop><input type="file" name="pliki" multiple aria-label="Pliki materiału">
<b>Upuść tu pliki, folder albo ZIP</b><span class="files" data-files>albo kliknij, żeby wybrać pliki</span>
<div class="pick"><label class="btn btn-line btn-sm">Wybierz folder<input type="file" name="pliki" webkitdirectory multiple
aria-label="Folder z materiałami"></label></div></div>
<div class="fields">
<label class="field"><span>Adres reklamy lub strony</span><input type="text" name="url" placeholder="https://" inputmode="url" autocomplete="off"></label>
<label class="field"><span>Tekst reklamy albo inna wskazówka</span><textarea name="tekst" placeholder="Np. podpis reklamy, nazwa produktu, adres z paska"></textarea></label>
<label class="check"><input type="checkbox" name="dodaj" value="1" checked>Zapisz w bazie. Kolejne materiały będą z nim porównywane.</label>
<button class="btn btn-ink">Analizuj materiał <span aria-hidden="true">→</span></button>
<p class="hint">{online}</p></div></form></div></section>"""


def index() -> bytes:
    base, campaigns = state["base"], state["campaigns"]
    ms = base.materials
    many = [c for c in campaigns if len(c["members"]) > 1]
    where = campaign_of(campaigns)
    high = sum(1 for m in ms if k.verdict(m)[1] >= 4)
    lone = len(ms) - sum(len(c["members"]) for c in many)
    error = f'<div class="notice" role="alert">{e(state["error"])}</div>' if state["error"] else ""
    hero = f"""<section class="wrap hero"><p class="eyebrow">Kolekcjoner fejków · demonstrator</p>
<h1>Od pojedynczej reklamy <span>do kampanii.</span></h1>
<p class="lead">Wgraj zrzut reklamy, zapisaną stronę, HAR albo cały folder incydentów. Każdy materiał od razu dostaje
wstępny werdykt, a potem trafia do kampanii albo zostaje nowym wzorcem. Przy każdym powiązaniu widać, na jakiej podstawie.</p>
{error}<dl class="stats"><div><dt>Materiały</dt><dd>{len(ms)}</dd></div><div><dt>Kampanie</dt><dd>{len(many)}</dd></div>
<div class="hot"><dt>Wysokie ryzyko</dt><dd>{high}</dd></div><div><dt>Nowe wzorce</dt><dd>{lone}</dd></div></dl></section>"""
    form = REPORT.format(collector=COLLECTOR if KOLEKTOR.is_file() else "") + FORM.format(online="Adresy stron i wiek domen (RDAP) sprawdzamy w sieci. Pliki nie opuszczają kontenera."
                       if ONLINE else "Tryb offline: nic nie opuszcza kontenera, adres strony jest tylko zapisany.")
    cards = []
    for c in many:
        dups = ", ".join(f"{a} = {b}" for a, b in c["duplicates"])
        pairs = "".join(pair(s, f"{mlink(a, '')} ~ {mlink(b, '')}", ev[:3]) for s, a, b, ev in c["pairs"][:4])
        cards.append(f"""<article class="camp" id="{e(c['id'])}"><div class="camp-side"><span class="camp-id">{e(c['id'])}</span>
<h3>{e(c['label'])}</h3><p>{many_of(len(c['members']))} · rodzina {e(c['family'])}</p></div>
<div class="camp-main"><dl class="facts"><div><dt>Materiały</dt><dd><div class="chips">{''.join(mlink(x) for x in c['members'])}</div></dd></div>
<div><dt>Łączy je</dt><dd>{chips(c['linked_by'], 'chip sig')}</dd></div>
<div class="wide"><dt>Domeny stron</dt><dd>{chips(c['domains'])}</dd></div>
{f'<div class="wide"><dt>Duplikaty</dt><dd>{chips(dups.split(", "))}</dd></div>' if dups else ''}</dl>
<ol class="pairs" aria-label="Najsilniejsze powiązania">{pairs}</ol></div></article>""")
    if not ms:
        camps = '<p class="lead muted">Baza jest pusta. Dodaj pierwsze materiały w formularzu wyżej.</p>'
    else:
        camps = "".join(cards) or '<p class="lead muted">Żadne dwa materiały nie mają jeszcze powiązania ≥ 0,5.</p>'
    rows = []
    for m in ms:
        c = where.get(m.id)
        camp = (f'<a href="/#{e(c["id"])}">{e(c["id"])}</a>' if c and len(c["members"]) > 1
                else '<span class="muted">nowy wzorzec</span>')
        rows.append(f"""<tr><td class="id">{mlink(m.id, '')}<small>{e(m.name) if m.name != m.id else ''}</small></td>
<td>{stamp(m)}</td><td>{camp}</td><td>{chips(m.landing[:3])}</td><td>{chips(m.persons + m.claimed)}</td>
<td>{chips(m.topics)}</td><td class="num">{len(m.missing) or '–'}</td></tr>""")
    table = (f"""<div class="table"><table><thead><tr><th>Materiał</th><th>Wstępny werdykt</th><th>Kampania</th>
<th>Domena strony</th><th>Osoby i marki</th><th>Temat</th><th>Braki danych</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>"""
             if ms else '<p class="lead muted">Nic tu jeszcze nie ma.</p>')
    clear = ('<form class="rm" method="post" action="/wyczysc" data-confirm="Usunąć wszystkie materiały z bazy?">'
             '<button class="btn btn-line btn-sm">Wyczyść bazę</button></form>') if ms else ""
    return page("Kampanie", f"""{hero}{form}
<section class="sec" id="kampanie" aria-labelledby="kampanie-t"><div class="wrap"><div class="sec-head"><h2 id="kampanie-t">Kampanie</h2>
<p>Materiał należy do kampanii, gdy ma w niej co najmniej jedno powiązanie o sile ≥ {num(k.LINK)}. Kampanie, których
materiały są średnio podobne w stopniu ≥ {num(k.FAMILY)}, tworzą rodzinę. {many_of(lone)} bez takiego powiązania to nowe wzorce.</p></div>
<div class="camps">{camps}</div></div></section>
<section class="sec" id="materialy" aria-labelledby="materialy-t"><div class="wrap"><div class="sec-head"><h2 id="materialy-t">Materiały</h2>
<p>Wstępny werdykt to suma punktów za cechy oszustwa: od 4 punktów wysokie ryzyko, od 2 podejrzane. Kliknij materiał,
żeby zobaczyć powody, braki danych i podobne materiały.</p></div>{table}{clear}</div></section>""", "k", refresh=True)


def features(m) -> str:
    rows = [("Tytuł strony", e(m.title) or '<span class="none">brak</span>'), ("Domeny stron", chips(m.landing)),
            ("Wiek domen (RDAP)", chips(f"{d}: {a} dni" for d, a in m.ages.items() if a is not None)),
            ("Przekierowania", chips(" → ".join(c) for c in m.redirects)), ("Identyfikatory", chips(m.trackers)),
            ("Schemat parametrów linku", chips(m.params)), ("IP serwera", chips(m.ips)),
            ("Osoby", chips(m.persons)), ("Udawane marki", chips(m.claimed)), ("Temat", chips(m.topics)),
            ("Pola formularzy", chips(m.forms)), ("Obrazy (dHash)", f'<span class="num">{len({n for _, n in m.images})}</span>'),
            ("Inne domeny", chips(m.domains[:25])), ("Pliki strony", chips(m.assets[:20])), ("Przeczytane", chips(m.sources))]
    dl = "".join(f"<div><dt>{a}</dt><dd>{b}</dd></div>" for a, b in rows)
    text = f'<div class="text">{e(m.text[:3000])}</div>' if m.text else ""
    return f'<dl class="feat">{dl}</dl>{text}'


def material(m, placed=None, base=None, note="") -> bytes:
    base = base or state["base"]
    flags = "".join(f"<li><b>+{p}</b><span>{e(why)}</span></li>" for p, why in k.flags(m))
    flags = f'<ol class="flags">{flags}</ol>' if flags else '<p class="muted">Nic z cech, które znamy z oszustw.</p>'
    placed = placed or base.place(m, state["campaigns"])
    if placed["campaign"]:
        avg, top = placed["fit"][placed["campaign"]]
        where = (f'<a class="place-id" href="/#{e(placed["campaign"])}">{e(placed["campaign"])}</a>'
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
    note = f'<div class="notice" role="status">{note}</div>' if note else ""
    return page(m.id, f"""<section class="wrap hero"><div class="case-head"><div><p class="eyebrow">Materiał {e(m.id)}</p>
<h1>{e(m.name)}</h1></div><div>{stamp(m, big=True)}</div></div>{note}
<div class="case-grid"><div class="panel"><h2>Co zwraca uwagę</h2>{flags}</div>
<div class="panel place"><h2>Kampania</h2>{where}{gaps}</div></div></section>
<section class="sec"><div class="wrap"><div class="sec-head"><h2>Podobne materiały</h2><p>Każde powiązanie z przesłankami
i ich siłą. Przesłanki składają się jak niezależne poszlaki: 1 − ∏(1 − siła).</p></div>{similar}</div></section>
<section class="sec"><div class="wrap"><div class="sec-head"><h2>Wyodrębnione cechy</h2><p>To, co odczytaliśmy z plików,
strony i tekstu. Z tych cech biorą się przesłanki.</p></div>{features(m)}{remove}</div></section>""")


def graph() -> bytes:
    base, campaigns = state["base"], state["campaigns"]
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
    lines, ms = [], base.materials
    for i in range(len(ms)):
        for j in range(i + 1, len(ms)):
            s, ev = base.compare(ms[i], ms[j])
            if s >= k.FAMILY and ms[i].id in pos and ms[j].id in pos:
                (x1, y1), (x2, y2) = pos[ms[i].id], pos[ms[j].id]
                why = f"{ms[i].id} ~ {ms[j].id}: {num(s)}\n" + "\n".join(w for _, _, w in ev[:4])
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
           f'{"".join(parts)}{"".join(lines)}{"".join(nodes)}</svg>') if ms else '<p class="muted">Baza jest pusta.</p>'
    return page("Graf powiązań", f"""<section class="wrap hero"><p class="eyebrow">Graf powiązań</p>
<h1>Kto z kim <span>i dlaczego.</span></h1><p class="lead">Okrąg to kampania. Linia łączy parę o podobieństwie
≥ {num(k.FAMILY)}: im grubsza, tym silniejsza. Najedź na linię, żeby zobaczyć przesłanki, kliknij materiał, żeby go otworzyć.</p></section>
<section class="wrap"><div class="graph">{svg}</div><ul class="legend"><li><i class="hi"></i>wysokie ryzyko</li>
<li><i></i>podejrzane</li><li><i class="ok"></i>brak sygnałów</li><li><i class="ln"></i>powiązanie</li></ul></section>""", "g")


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
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; "
                         "script-src 'self'; font-src 'self'; img-src data:; connect-src 'self'; form-action 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "max-age=3600" if cache else "no-store")
        self.end_headers()
        self.wfile.write(body)

    def go(self, where: str):
        self.send_response(303)
        self.send_header("Location", where)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = unquote(urlsplit(self.path).path)
        if path == "/":
            return self.send(index())
        if path == "/graf":
            return self.send(graph())
        if path == "/eksport.json":
            return self.send(export(), "application/json; charset=utf-8")
        if path.startswith("/static/") and (f := STATIC / clean(path[8:])).is_file() and f.suffix in TYPES:
            return self.send(f.read_bytes(), TYPES[f.suffix], cache=True)
        if path.startswith("/m/") and (m := state["base"].by_id.get(path[3:])):
            new = "nowy" in parse_qs(urlsplit(self.path).query)
            return self.send(material(m, note="Zapisano w bazie. Kampanie są przeliczone." if new else ""))
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
                with work:
                    commit([m for m in state["base"].materials if m.id != form.get("id")])
                return self.go("/#materialy")
            if self.path == "/wyczysc":
                with work:
                    commit([])
                return self.go("/")
            if self.path == "/kolektor":
                if not KOLEKTOR.is_file():
                    return self.send(page("Brak", '<section class="wrap hero"><h1>Baza kolektora nie jest podłączona.</h1></section>'), code=404)
                state["status"] = "Wczytuję zablokowane domeny z kolektora"  # before the redirect, so the page refreshes
                threading.Thread(target=run_import, args=(int(form.get("ile") or 0) or None,), daemon=True).start()
                return self.go("/#kampanie")
            if self.path == "/zglos":
                raw = form.get("domena", "").strip()
                dom = k.domain_of(k.host_of(raw if "://" in raw else "https://" + raw))
                if not dom:
                    return self.send(page("Zła domena", '<section class="wrap hero"><h1>To nie wygląda na domenę.</h1>'
                                                       '<p class="lead"><a href="/#zglos">Wróć do formularza</a></p></section>'), code=400)
                with work:
                    m, note = known(dom)
                    if m:
                        return self.send(material(m, note=e(note)))
                    m = ingest({"url": f"https://{dom}/", "tekst": form.get("uwaga", "")}, [], work_dir, keep=True)[0]
                    state["status"] = ""
                return self.go(f"/m/{quote(m.id)}?nowy=1")
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
            with work:
                m = ingest(form, entries, work_dir, keep)[0]
                state["status"] = ""
                if keep:
                    return self.go(f"/m/{quote(m.id)}?nowy=1")
                base = k.Base(state["base"].materials + [m])
                return self.send(material(m, base.place(m, base.campaigns()), base,
                                          "Tego materiału nie zapisano w bazie. Pokazujemy, gdzie by pasował."))
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
