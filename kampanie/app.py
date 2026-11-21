"""GUI of kampanie: http://127.0.0.1:8501. Reads the materials in /dane at start, keeps features in /data/baza.json,
analyses a new URL, ad text, screenshot or saved page against them."""
import email.parser
import email.policy
import html
import json
import math
import os
import re
import tempfile
import threading
import zlib
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

import kampanie as k

DANE = Path(os.environ.get("DANE", "/dane"))
BAZA = Path(os.environ.get("BAZA", "/data/baza.json"))
ONLINE = os.environ.get("ONLINE", "1") == "1"  # RDAP ages of landing domains; 0 = nothing leaves the container
MAX_UPLOAD = 60_000_000
lock = threading.Lock()
state = {"base": k.Base([]), "campaigns": [], "status": "start", "log": []}


def signature(root: Path) -> str:
    if not root.is_dir():
        return ""
    files = sorted(f"{p.relative_to(root)}:{p.stat().st_size}:{int(p.stat().st_mtime)}"
                   for p in root.rglob("*") if p.is_file())
    return f"{zlib.crc32(chr(10).join(files).encode()):08x}"


def save(materials):
    BAZA.parent.mkdir(parents=True, exist_ok=True)
    tmp = BAZA.with_suffix(".tmp")
    tmp.write_text(json.dumps({"sig": signature(DANE), "materials": [asdict(m) for m in materials]},
                              ensure_ascii=False), encoding="utf-8")
    tmp.replace(BAZA)  # never a half-written base


def rebuild(materials):
    base = k.Base(materials)
    campaigns = base.campaigns()
    with lock:
        state.update(base=base, campaigns=campaigns, status="gotowe")


def load(force=False):
    def log(line):
        state["log"] = (state["log"] + [line])[-30:]
        state["status"] = line
    try:
        old = json.loads(BAZA.read_text(encoding="utf-8")) if BAZA.exists() else {"sig": None, "materials": []}
        kept = [k.Material(**m) for m in old["materials"]]
        added = [m for m in kept if m.origin == "dodane"]
        if force or old["sig"] != signature(DANE):
            fresh = k.load_folder(DANE, log) if DANE.is_dir() else []
            if ONLINE:
                for m in fresh:
                    log(f"RDAP: {m.id}")
                    k.look_up_ages(m)
            kept = fresh + added
            save(kept)
        log("grupowanie")
        rebuild(kept)
    except Exception as e:
        state["status"] = f"błąd: {e.__class__.__name__}: {e}"
        raise


# ---------- HTML ----------

e = html.escape
CSS = """
:root{--bg:#fbfaf7;--fg:#1d1d1b;--mut:#6b6a64;--line:#dedbd2;--card:#fff;--hi:#b3261e;--mid:#b06000;--ok:#2e7d32;--acc:#1f4e9c}
@media (prefers-color-scheme:dark){:root{--bg:#161614;--fg:#ecebe6;--mut:#a3a29b;--line:#3a3934;--card:#1f1f1c;--hi:#ff8a80;--mid:#ffb74d;--ok:#81c784;--acc:#90b4ff}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:16px}
a{color:var(--acc)} h1{font-size:22px;margin:8px 0} h2{font-size:18px;margin:24px 0 8px} h3{font-size:16px;margin:0 0 4px}
nav a{margin-right:16px} .card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:10px 0}
.mut{color:var(--mut);font-size:13px} .hi{color:var(--hi)} .mid{color:var(--mid)} .ok{color:var(--ok)}
table{border-collapse:collapse;width:100%} td,th{border-bottom:1px solid var(--line);padding:6px;text-align:left;vertical-align:top;font-size:14px}
.tag{display:inline-block;border:1px solid var(--line);border-radius:10px;padding:0 8px;margin:2px;font-size:13px}
input[type=text],textarea{width:100%;box-sizing:border-box;padding:6px;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px}
button{padding:8px 16px;border-radius:6px;border:1px solid var(--acc);background:var(--acc);color:#fff;cursor:pointer}
ul{margin:4px 0;padding-left:20px} .wrap{overflow-x:auto} pre{white-space:pre-wrap;font-size:13px;max-height:240px;overflow:auto}
"""


def page(title: str, body: str) -> bytes:
    return f"""<!doctype html><html lang="pl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(title)}</title><style>{CSS}</style></head>
<body><main><nav><a href="/">Kampanie</a><a href="/graf">Graf powiązań</a><a href="/eksport.json">Eksport JSON</a></nav>
{body}</main></body></html>""".encode()


def mlink(mid: str) -> str:
    return f'<a href="/m/{quote(mid)}">{e(mid)}</a>'


def tags(items) -> str:
    return "".join(f'<span class="tag">{e(str(x))}</span>' for x in items) or '<span class="mut">brak</span>'


def risk(m) -> str:
    text, points = k.verdict(m)
    cls = "hi" if points >= 4 else "mid" if points >= 2 else "ok"
    return f'<b class="{cls}">{e(text)}</b> <span class="mut">({points} pkt)</span>'


def evidence(ev) -> str:
    return "<ul>" + "".join(f"<li>{e(why)} <span class='mut'>[{e(kind)}, siła {s:.2f}]</span></li>"
                            for s, kind, why in ev) + "</ul>"


FORM = """<div class="card"><h2 style="margin-top:0">Analizuj nowy materiał</h2>
<form method="post" action="/analizuj" enctype="multipart/form-data">
<p><label>Adres URL reklamy lub strony<br><input type="text" name="url" placeholder="https://..."></label></p>
<p><label>Tekst reklamy, nazwa produktu lub inna wskazówka<br><textarea name="tekst" rows="3"></textarea></label></p>
<p><label>Pliki: zrzut ekranu, zapisana strona (.html, .mhtml), HAR, .info.json, .txt<br>
<input type="file" name="pliki" multiple></label></p>
<p><label><input type="checkbox" name="dodaj" value="1" checked> dodaj do bazy (kolejne materiały będą z nim porównywane)</label></p>
<button>Analizuj</button></form></div>"""


def index() -> bytes:
    base, campaigns = state["base"], state["campaigns"]
    busy = "" if state["status"] == "gotowe" else f'<div class="card mid">Trwa: {e(state["status"])} (odśwież)</div>'
    rows = []
    for c in campaigns:
        dups = ", ".join(f"{a} = {b}" for a, b in c["duplicates"])
        best = "".join(f"<li>{mlink(a)} ~ {mlink(b)}: <b>{s:.2f}</b> {e('; '.join(w for _, _, w in ev[:3]))}</li>"
                       for s, a, b, ev in c["pairs"][:4])
        rows.append(f"""<div class="card"><h3>{e(c['id'])}: {e(c['label'])}
<span class="mut">({len(c['members'])} mat., rodzina {e(c['family'])})</span></h3>
<div>Materiały: {', '.join(mlink(x) for x in c['members'])}</div>
<div>Łączy je: {tags(c['linked_by'])}</div><div>Domeny stron: {tags(c['domains'])}</div>
{f'<div>Duplikaty: {e(dups)}</div>' if dups else ''}{f'<ul>{best}</ul>' if best else ''}</div>""")
    table = "".join(f"<tr><td>{mlink(m.id)}</td><td>{risk(m)}</td><td>{tags(m.landing[:3])}</td>"
                    f"<td>{tags(m.persons + m.claimed)}</td><td>{tags(m.topics)}</td>"
                    f"<td class='mut'>{len(m.missing)}</td></tr>" for m in base.materials)
    return page("Kampanie", f"""<h1>Od pojedynczych reklam do kampanii</h1>{busy}{FORM}
<h2>Kampanie ({len(campaigns)}) z {len(base.materials)} materiałów</h2>
<p class="mut">Kampania: każdy materiał ma w niej co najmniej jedno powiązanie ≥ {k.LINK}; rodzina kampanii: średnie podobieństwo ≥ {k.FAMILY}.</p>{''.join(rows)}
<h2>Materiały i wstępny werdykt</h2><div class="wrap"><table><tr><th>Materiał</th><th>Werdykt</th><th>Domena strony</th>
<th>Osoby / marki</th><th>Temat</th><th>Braki</th></tr>{table}</table></div>
<form method="post" action="/przelicz"><p><button>Przeanalizuj zbiór od nowa</button></p></form>""")


def features(m) -> str:
    rows = [("Tytuł", e(m.title) or "–"), ("Domeny stron", tags(m.landing)),
            ("Wiek domen (RDAP)", tags(f"{d}: {a} dni" for d, a in m.ages.items() if a is not None)),
            ("Przekierowania", tags(" → ".join(c) for c in m.redirects)), ("Identyfikatory", tags(m.trackers)),
            ("Schemat parametrów linku", tags(m.params)), ("IP serwera", tags(m.ips)),
            ("Osoby", tags(m.persons)), ("Udawane marki", tags(m.claimed)), ("Temat", tags(m.topics)),
            ("Pola formularzy", tags(m.forms)), ("Inne domeny", tags(m.domains[:25])),
            ("Obrazy (dHash)", f"{len(m.images)}"), ("Pliki strony", tags(m.assets[:20])),
            ("Przeczytane", tags(m.sources)), ("Braki danych", tags(m.missing))]
    table = "".join(f"<tr><th>{a}</th><td>{b}</td></tr>" for a, b in rows)
    return f"<table>{table}</table><h3 style='margin-top:12px'>Tekst (początek)</h3><pre>{e(m.text[:1500])}</pre>"


def material(m, placed=None, base=None) -> bytes:
    base = base or state["base"]
    flags = "".join(f"<li>+{p} {e(why)}</li>" for p, why in k.flags(m)) or "<li class='mut'>brak</li>"
    placed = placed or base.place(m, state["campaigns"])
    if placed["campaign"]:
        avg, top = placed["fit"][placed["campaign"]]
        where = f"<b>{e(placed['campaign'])}</b> (najsilniejsze powiązanie {top:.2f}, średnio {avg:.2f})"
    else:
        best = max(placed["fit"].items(), key=lambda x: x[1][1], default=None)
        where = ("<b>nowy wzorzec</b>: brak powiązania ≥ " + str(k.LINK) +
                 (f" (najbliżej {e(best[0])}: {best[1][1]:.2f})" if best else ""))
    similar = []
    for score, other in placed["similar"]:
        if score < 0.05:
            break
        ev = base.compare(m, base.by_id[other])[1]
        similar.append(f"<div class='card'><b>{score:.2f}</b> {mlink(other)} {evidence(ev)}</div>")
    return page(m.id, f"""<h1>{e(m.name)}</h1>
<div class="card"><h3>Wstępny werdykt: {risk(m)}</h3><ul>{flags}</ul><div>Kampania: {where}</div></div>
<h2>Podobne materiały i przesłanki</h2>{''.join(similar) or '<p class="mut">brak</p>'}
<h2>Wyodrębnione cechy</h2><div class="card wrap">{features(m)}</div>""")


def graph() -> bytes:
    base, campaigns = state["base"], state["campaigns"]
    cols = max(1, math.ceil(math.sqrt(len(campaigns))))
    cell, pos, parts = 260, {}, []
    for i, c in enumerate(campaigns):
        cx, cy = cell * (i % cols) + cell / 2, cell * (i // cols) + cell / 2
        r = 0 if len(c["members"]) == 1 else 40 + 12 * len(c["members"])
        r = min(r, cell / 2 - 50)  # room for the label above the ring
        parts.append(f'<circle cx="{cx}" cy="{cy}" r="{r + 22}" fill="none" stroke="var(--line)" stroke-dasharray="4"/>'
                     f'<text x="{cx}" y="{cy - r - 28}" text-anchor="middle" font-size="13" fill="var(--mut)">'
                     f'{e(c["id"])} {e(c["label"][:34])}</text>')
        for j, mid in enumerate(c["members"]):
            a = 2 * math.pi * j / len(c["members"])
            pos[mid] = (cx + r * math.cos(a), cy + r * math.sin(a))
    lines = []
    ms = base.materials
    for i in range(len(ms)):
        for j in range(i + 1, len(ms)):
            s, ev = base.compare(ms[i], ms[j])
            if s >= k.FAMILY and ms[i].id in pos and ms[j].id in pos:
                (x1, y1), (x2, y2) = pos[ms[i].id], pos[ms[j].id]
                why = f"{ms[i].id} ~ {ms[j].id}: {s:.2f}\n" + "\n".join(w for _, _, w in ev[:4])
                lines.append(f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" stroke="var(--acc)" '
                             f'stroke-width="{1 + 5 * s:.1f}" opacity="{0.25 + 0.6 * s:.2f}"><title>{e(why)}</title></line>')
    nodes = []
    for m in ms:
        if m.id not in pos:
            continue
        x, y = pos[m.id]
        pts = k.verdict(m)[1]
        color = "var(--hi)" if pts >= 4 else "var(--mid)" if pts >= 2 else "var(--ok)"
        nodes.append(f'<a href="/m/{quote(m.id)}"><circle cx="{x:.0f}" cy="{y:.0f}" r="14" fill="{color}">'
                     f'<title>{e(m.name)}</title></circle><text x="{x:.0f}" y="{y + 4:.0f}" text-anchor="middle" '
                     f'font-size="11" fill="#fff">{e(m.id[:4])}</text></a>')
    rows = max(1, math.ceil(len(campaigns) / cols))
    svg = (f'<svg viewBox="0 0 {cols * cell} {rows * cell}" width="100%" style="max-width:{cols * cell}px">'
           f'{"".join(parts)}{"".join(lines)}{"".join(nodes)}</svg>')
    return page("Graf powiązań", f"""<h1>Graf powiązań</h1><p class="mut">Kółko przerywane = kampania. Linia = para
o podobieństwie ≥ {k.FAMILY} (grubsza = silniejsza; najedź, by zobaczyć przesłanki). Kolor = werdykt.</p>
<div class="card wrap">{svg}</div>""")


def export() -> bytes:
    base = state["base"]
    out = {"campaigns": [{**{x: c[x] for x in ("id", "family", "label", "members", "linked_by", "domains", "duplicates")},
                          "pairs": [{"a": a, "b": b, "score": round(s, 3), "evidence": [w for _, _, w in ev]}
                                    for s, a, b, ev in c["pairs"]]} for c in state["campaigns"]],
           "materials": [{**{x: v for x, v in asdict(m).items() if x not in ("shingles", "template", "text")},
                          "verdict": k.verdict(m)[0], "flags": [w for _, w in k.flags(m)]} for m in base.materials]}
    return json.dumps(out, ensure_ascii=False, indent=1).encode()


def analyse(form: dict, files: list[tuple[str, bytes]]) -> bytes:
    with lock:
        n = sum(1 for m in state["base"].materials if m.origin == "dodane") + 1
    name = (form.get("url") or (files[0][0] if files else "") or form.get("tekst", "")[:40] or "materiał").strip()
    m = k.Material(id=f"nowy-{n}", name=name, origin="dodane")
    with tempfile.TemporaryDirectory() as tmp:
        paths = []
        for fname, data in files:
            safe = re.sub(r"[^\w.\- ]", "_", Path(fname).name)[:120] or "plik"
            (p := Path(tmp) / safe).write_bytes(data)
            paths.append(p)
        if url := form.get("url", "").strip():
            try:
                k.fetch(m, url if "://" in url else "https://" + url)
            except Exception as err:  # the page is gone or refuses: its address still says something
                m.missing.append(f"strona {url}: niedostępna ({err.__class__.__name__}: {str(err)[:120]})")
                k.add_url(m, url if "://" in url else "https://" + url, landing=True)
        if text := form.get("tekst", "").strip():
            k.add_text(m, text)
            for dom in k.DOMAIN_TEXT.findall(text.lower()):  # an address in the ad's caption is where it leads
                k.add_url(m, "https://" + dom, landing=True)
            m.sources.append("tekst z formularza")
        k.from_files(m, paths, Path(tmp))
    if ONLINE:
        k.look_up_ages(m)
    with lock:
        materials = state["base"].materials + [m]
    base = k.Base(materials)
    campaigns = base.campaigns()
    placed = base.place(m, campaigns)
    if form.get("dodaj"):
        save(materials)
        with lock:
            state.update(base=base, campaigns=campaigns)
    return material(m, placed, base)


class Handler(BaseHTTPRequestHandler):
    def send(self, body: bytes, ctype="text/html; charset=utf-8", code=200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = unquote(urlsplit(self.path).path)
        if path == "/":
            return self.send(index())
        if path == "/graf":
            return self.send(graph())
        if path == "/eksport.json":
            return self.send(export(), "application/json; charset=utf-8")
        if path.startswith("/m/") and (m := state["base"].by_id.get(path[3:])):
            return self.send(material(m))
        self.send(page("Brak", "<h1>Nie ma takiej strony</h1>"), code=404)

    def do_POST(self):
        size = int(self.headers.get("Content-Length") or 0)
        if size > MAX_UPLOAD:
            return self.send(page("Za duże", "<h1>Pliki są za duże (limit 60 MB)</h1>"), code=413)
        body = self.rfile.read(size)
        if self.path == "/przelicz":
            threading.Thread(target=load, kwargs={"force": True}, daemon=True).start()
            self.send_response(303)
            self.send_header("Location", "/")
            return self.end_headers()
        if self.path != "/analizuj":
            return self.send(page("Brak", "<h1>Nie ma takiej strony</h1>"), code=404)
        msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
            b"Content-Type: " + self.headers.get("Content-Type", "").encode() + b"\r\n\r\n" + body)
        form, files = {}, []
        for part in msg.iter_parts() if msg.is_multipart() else []:
            name = part.get_param("name", header="content-disposition")
            data = part.get_payload(decode=True) or b""
            if part.get_filename():
                if data:
                    files.append((part.get_filename(), data))
            elif name:
                form[name] = data.decode("utf-8", "replace")
        if not (form.get("url", "").strip() or form.get("tekst", "").strip() or files):
            return self.send(page("Pusto", "<h1>Podaj adres, tekst albo plik</h1>"), code=400)
        try:
            self.send(analyse(form, files))
        except Exception as err:
            self.send(page("Błąd", f"<h1>Nie udało się przeanalizować</h1><pre>{e(repr(err))}</pre>"), code=500)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    threading.Thread(target=load, daemon=True).start()
    host, port = os.environ.get("HOST", "0.0.0.0"), int(os.environ.get("PORT", "8501"))
    print(f"kampanie: http://127.0.0.1:{port}", flush=True)
    ThreadingHTTPServer((host, port), Handler).serve_forever()
