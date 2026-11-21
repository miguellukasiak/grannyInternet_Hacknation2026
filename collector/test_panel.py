"""Self-check of the decision panel (no network): python test_panel.py"""

import json
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sqlite3

import collector
import lists
import panel

published = []
panel.publish_soon = lambda reload=False: published.append(reload)  # no Blocky here

with tempfile.TemporaryDirectory() as tmp:
    collector.LISTS = collector.SHOTS = Path(tmp)
    collector.VERDICTS = Path(tmp) / "verdicts.db"
    panel.LISTS_DB = Path(tmp) / "lists.db"  # the lists service's base: CERT's list and our own
    with sqlite3.connect(panel.LISTS_DB) as sources:
        sources.executescript(lists.SCHEMA)
        sources.executemany("INSERT INTO sources (name, package) VALUES (?, ?)", [("cert", "scam"), ("kolektor-fb", "scam")])
        sources.executemany("INSERT INTO entries VALUES (?, ?, ?)", [
            ("kolektor-fb", "krem.shop", "krem.shop"), ("cert", "w.shop", "w.shop")])
    sources.close()
    (collector.LISTS / "watpliwe.txt").write_text("# doubtful\n*.glp.diet\n", encoding="utf-8")
    db = collector.open_db(collector.VERDICTS)
    panel.accounts(db)  # as serve() does at start: the tabs count the remarks too
    ad = {"ad_creative_bodies": ["Krem na żylaki <script>alert(1)</script>"] * 3,
          "ad_creative_link_captions": ["krem.shop"]}
    reason = 'no company named; to check by hand: file, not opened "Regulamin" -> https://krem.shop/r.pdf'
    db.execute("INSERT INTO verdicts (domain, verdict, score, reason, ad_id, page, seen_at, ad) VALUES "
               "('krem.shop', 'review', 3, ?, '42', 'Krem-store', '2026-10-26T20:00:00+00:00', ?)",
               (reason, json.dumps(ad)))
    db.commit()

    [card] = panel.cards(db, "review")
    assert panel.cards(db, "sample") == [] and panel.counts(db)["sample"] == 0  # a queued domain is no sample
    db.execute("INSERT INTO verdicts (domain, verdict, ad) VALUES ('a.shop', 'block', '{}'), ('b.shop', 'pass', '{}')")
    db.execute("INSERT INTO verdicts (domain, verdict, ad, decided_by) VALUES ('c.shop', 'pass', '{}', 'human')")
    assert {c["domain"] for c in panel.cards(db, "sample")} == {"a.shop", "b.shop"}  # c.shop: a human saw it
    assert panel.counts(db)["sample"] == 2
    db.execute("INSERT INTO verdicts (domain, verdict, ad) VALUES ('d.shop', 'pass', '{}')")  # came after the draw
    db.execute("UPDATE verdicts SET decided_by = 'human' WHERE domain = 'a.shop'")
    assert [c["domain"] for c in panel.cards(db, "sample")] == ["b.shop"] and panel.counts(db)["sample"] == 1  # counts down
    db.execute("UPDATE verdicts SET decided_by = 'human' WHERE domain = 'b.shop'")
    assert [c["domain"] for c in panel.cards(db, "sample")] == ["d.shop"]  # batch done: the next one
    db.execute("DELETE FROM verdicts WHERE domain LIKE '_.shop'")
    assert card["manual"] == ["https://krem.shop/r.pdf"] and card["library"].endswith("?id=42")
    assert card["caption"] is None and card["landing"] is None  # the caption is the home page, listed anyway
    groups = [panel.urgency({"reason": r, "age_days": a}) for r, a in (
        ("llm: Fake shop", 9000), ("NIP 1 is made up", 4000), ("no company named", 30), ("no company named", "hidden"),
        ("no company named", 4000), ("llm passed it; social icons lead nowhere: Youtube", 30),
        ("llm passed it but wrote: no shop", 30), ("company named on the page (email, NIP), the model claimed none", 30),
        ("page hidden behind a bot check, a human looks", "hidden"), ("llm passed it but wrote: x; same server as blocked a.pl", 30),
        ("llm passed it, but the ad tells a closing-down story: likwidacja sklepu", 4000))]
    assert groups == [0, 0, 1, 1, 2, 3, 3, 3, 3, 0, 0]  # fraud signs first, then age, what humans pass anyway last
    linked = {"ad_creative_link_captions": ["Wyzwanie.Krem.shop"],
              "links": {"krem.shop": "https://wyzwanie.krem.shop/w2/"}}
    clicked = panel.card(("krem.shop", "review", 0, "", "1", "", "", json.dumps(linked), None, None))
    assert clicked["caption"] == "https://wyzwanie.krem.shop/" and clicked["landing"] == "https://wyzwanie.krem.shop/w2/"
    survey = {"ad_creative_link_captions": ["reha-oferta.krem.shop/s/Jan-Kowalski"]}
    assert panel.card(("krem.shop", "review", 0, "", "1", "", "", json.dumps(survey), None, None))["caption"] == (
        "https://reha-oferta.krem.shop/s/Jan-Kowalski")  # the page the collector opened, not the bare host
    linked["destinations"] = ["https://wyzwanie.krem.shop/w2/", "https://scam.shop/p"]
    both = panel.card(("krem.shop", "review", 0, "", "1", "", "", json.dumps(linked), None, None))
    assert both["others"] == ["https://scam.shop/p"] and both["saved"]  # every target for the auditor
    assert both["age_days"] is None  # judged before ages were kept
    linked["age_days"] = {"krem.shop": 12}
    assert panel.card(("krem.shop", "review", 0, "", "1", "", "", json.dumps(linked), None, None))["age_days"] == 12
    linked["age_days"] = {"krem.shop": None}
    assert panel.card(("krem.shop", "review", 0, "", "1", "", "", json.dumps(linked), None, None))["age_days"] == "hidden"
    page = {"likes": 16, "categories": ["Obutev"], "profile": "https://www.facebook.com/61594037744659/"}
    assert panel.card(("krem.shop", "review", 0, "", "1", "", "", json.dumps({"fb_page": page}), None, None))["fb_page"] == page
    assert panel.card(("krem.shop", "review", 0, "", "1", "", "", json.dumps({"page_id": "1057432520784272"}), None, None)
                      )["fb_id"] == "https://www.facebook.com/1057432520784272"  # the ad gone, the page's id still opens it
    assert not panel.card(("old.pl", "doubtful", 0, "", "1", "", "", json.dumps({"links": {}}), None, None))["saved"]
    # a NIP GUS gave for the site's KRS comes with what it stands for, so the card says the site gives no NIP
    courted = {"number": {"krs.pl": "1234563218"}, "number_by": {"krs.pl": "KRS 0000123456"}}
    shown = panel.card(("krs.pl", "pass", 0, "llm: ok", "1", "", "a", json.dumps(courted), None, None))
    assert (shown["number"], shown["number_by"]) == ("1234563218", "KRS 0000123456")
    why = "KRS 0000123456 (no NIP on the site; GUS gives NIP 1234563218) belongs to X, the site never names it"
    shown = panel.card(("krs2.pl", "review", 0, why, "1", "", "b", "{}", None, None))
    assert (shown["number"], shown["number_by"]) == ("1234563218", "KRS 0000123456")
    numbered = {"number": {"nip.pl": "1234563218"}}  # a NIP the site gives itself: nothing to add
    assert panel.card(("nip.pl", "pass", 0, "llm: ok", "1", "", "c", json.dumps(numbered), None, None))["number_by"] is None
    assert card["text"] == "Krem na żylaki <script>alert(1)</script>"  # once; the page sets it as text only

    assert panel.decide(db, "krem.shop", "doubtful")
    doubtful = (collector.LISTS / "watpliwe.txt").read_text(encoding="utf-8")
    assert doubtful.splitlines() == ["# doubtful", "*.glp.diet", "*.krem.shop"] and published
    assert db.execute("SELECT verdict, decided_by FROM verdicts").fetchone() == ("doubtful", "human")
    assert panel.decide(db, "krem.shop", "review", undo=True)  # undo: off the doubtful list, no human label
    assert "*.krem.shop" not in (collector.LISTS / "watpliwe.txt").read_text(encoding="utf-8")
    assert db.execute("SELECT verdict, decided_by, decided_at FROM verdicts").fetchone() == ("review", None, None)
    assert not panel.decide(db, "unknown.com", "block")
    fronted = {"ad_creative_link_captions": ["glp.diet"],
               "destinations": ["https://krem.shop/x", "https://x.grwebsite.pl/", "https://nowhere.shop/"]}
    assert panel.related(db, "glp.diet", fronted) == [  # no platform: its block would hit every site
        {"domain": "krem.shop", "verdict": "review", "decided_by": None, "decided_at": None, "spare": False},
        {"domain": "nowhere.shop", "verdict": None, "decided_by": None, "decided_at": None, "spare": False}]
    reason_before = db.execute("SELECT reason FROM verdicts WHERE domain = 'krem.shop'").fetchone()[0]
    db.execute("UPDATE verdicts SET reason = 'the ad shows krem.shop but leads to glp.diet' WHERE domain = 'krem.shop'")
    assert panel.related(db, "glp.diet", fronted)[0]["spare"]  # a brand the scam wears (ccc.eu): unticked at first
    panel._popular = {"nowhere.shop"}
    assert panel.related(db, "glp.diet", fronted)[1]["spare"]  # popular, never judged (amazon.nl): unticked too
    panel._popular = set()
    db.execute("UPDATE verdicts SET reason = ? WHERE domain = 'krem.shop'", (reason_before,))
    assert db.execute("SELECT verdict, by FROM history").fetchall() == [("doubtful", "human"), ("review", "undo")]
    assert panel.decide(db, "krem.shop", "verified")  # passed after a phone call: a pass, but no label to learn from
    assert db.execute("SELECT verdict, decided_by FROM verdicts WHERE domain = 'krem.shop'").fetchone() == ("pass", "verified")
    assert db.execute("SELECT verdict, reason, by FROM history ORDER BY rowid DESC").fetchone() == (
        "pass", "checked outside the site", "human")
    assert panel.decide(db, "krem.shop", "review", undo=True)
    db.execute("UPDATE verdicts SET ad = ? WHERE domain = 'krem.shop'",
               (json.dumps(ad | {"destinations": ["https://zly.shop/x"]}),))
    assert not panel.decide(db, "inny.shop", "block", card="krem.shop")  # not that ad's: no row for any name sent
    assert panel.decide(db, "zly.shop", "block", card="krem.shop")  # homla.pl's ad opening dailycartplus.shop
    assert db.execute("SELECT verdict, decided_by, ad_id, reason FROM verdicts WHERE domain = 'zly.shop'").fetchone() == (
        "block", "human", "42", "decided on the card of krem.shop")
    panel.accounts(db)  # the batches' table: an auditor's decision checks it first
    assert "właściciel dał blokadę" in panel.outranked(db, "zly.shop", "pass", "a@x.pl")  # the owner's block stays
    collector.log(db, "zly.shop", "block", None, "human", "a@x.pl")  # then an auditor's block
    assert panel.outranked(db, "zly.shop", "review", "b@x.pl") == "zly.shop: inny audytor dał blokadę, surowsza decyzja zostaje"
    assert panel.outranked(db, "zly.shop", "doubtful", "b@x.pl")  # nor a milder one
    assert panel.outranked(db, "zly.shop", "pass", "a@x.pl") is None  # their own: may change their mind
    assert panel.outranked(db, "zly.shop", "block", "b@x.pl") is None and panel.outranked(db, "zly.shop", "pass", None) is None
    assert panel.outranked(db, "krem.shop", "pass", "b@x.pl") is None  # the collector's verdict always gives way
    db.execute("DELETE FROM verdicts WHERE domain = 'zly.shop'")
    db.execute("DELETE FROM history WHERE domain = 'zly.shop'")
    db.execute("UPDATE verdicts SET ad = ? WHERE domain = 'krem.shop'", (json.dumps(ad),))
    db.commit()

    found = panel.lookup(db, "https://Sub.Krem.shop/oferta")  # lower-cased by the page; any address works
    assert found["domain"] == "sub.krem.shop" and found["card"]["domain"] == "krem.shop"
    assert found["lists"] == [{"source": "kolektor-fb", "package": "scam", "entry": "krem.shop"}]  # through the parent
    assert found["allowed_by"] is None and [h["verdict"] for h in found["history"]] == ["doubtful", "review", "pass", "review"]
    assert panel.lookup(db, "../verdicts.db") is None and panel.lookup(db, "") is None
    assert panel.similar(db, "krem") == ["krem.shop"] and panel.similar(db, "https://krme.shop/x") == ["krem.shop"]
    assert panel.similar(db, "kr") == [] and panel.similar(db, "%") == []  # too short to mean anything
    published.clear()
    (collector.LISTS / "allow.txt").write_text("# by hand\n*.krem.shop\n", encoding="utf-8")
    assert panel.lookup(db, "a.krem.shop")["allowed_by"] == "*.krem.shop"
    panel.unallow(db, "krem.shop")
    assert panel.allowed_by("krem.shop") is None and published[-1] is True
    assert (collector.LISTS / "allow.txt").read_text(encoding="utf-8") == "# by hand\n"
    assert [h["verdict"] for h in panel.lookup(db, "krem.shop")["history"]][-1] == "unallow"

    for domain, reason, by in [("x.shop", "decoy: 首页", None), ("y.shop", "llm: fake shop", None),
                               ("z.shop", "llm: fake shop", "human"), ("w.shop", "decoy: 首页", None),
                               ("v.shop", "decoy: no website", None)]:
        db.execute("INSERT INTO verdicts (domain, verdict, reason, seen_at, decided_by) VALUES (?, 'block', ?, ?, ?)",
                   (domain, reason, f"2026-10-27T1{len(domain)}:00:00+00:00", by))
    # y.shop: only a small model's word; w.shop: on CERT's list already; v.shop: nothing there to block
    assert sorted(c["domain"] for c in panel.cert_queue(db)) == ["x.shop", "z.shop"]
    assert panel.reported(db, ["x.shop", "y.pl"]) == 1 and [c["domain"] for c in panel.cert_queue(db)] == ["z.shop"]
    for domain, reason, by in [("brand.pl", "the ad shows brand.pl but leads to x.top", "human"),
                               ("old.pl", "llm: fake shop", "human"), ("copy.com", "same page as x.shop", None)]:
        db.execute("INSERT INTO verdicts (domain, verdict, reason, seen_at, ad, decided_by) VALUES (?, 'block', ?, ?, ?, ?)",
                   (domain, reason, "2026-10-28T10:00:00+00:00", json.dumps({"age_days": {domain: 9000}}), by))
    # brand.pl: the victim a scam ad showed; old.pl: an old firm on a model's word; copy.com: a scam's copied page
    assert [c["domain"] for c in panel.cert_queue(db)] == ["z.shop", "copy.com"]
    db.execute("DELETE FROM verdicts WHERE domain IN ('brand.pl', 'old.pl', 'copy.com')")
    db.executemany("INSERT INTO trainings VALUES (?, 'words', ?, ?, 0.8, 0.1)", [("2026-11-14", 100, 0.7), ("2026-11-15", 120, 0.9)])
    assert 'scamdns_model_accuracy{model="words"} 0.9\n' in panel.metrics(db)  # the latest measure only
    assert 'scamdns_model_cards{model="words"} 120\n' in panel.metrics(db)
    assert "scamdns_cert_reported 1\n" in panel.metrics(db) and 'scamdns_verdicts{verdict="block"} 5\n' in panel.metrics(db)
    queue, real = panel.cert_domains(db), panel.lists_db

    def locked():  # lists.py rewriting a source in one transaction: 3 crashes of /metrics and the tabs in 48 h
        raise sqlite3.OperationalError("database is locked")

    panel.lists_db = locked
    assert panel.cert_domains(db) == queue and "scamdns_cert_queue" in panel.metrics(db)  # the last answer stays
    panel.lists_db = real
    db.close()

    server = panel.ThreadingHTTPServer(("127.0.0.1", 0), panel.Panel)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    root = f"http://127.0.0.1:{server.server_port}"

    def post(body: dict, headers: dict) -> int:
        request = urllib.request.Request(f"{root}/api/decide", json.dumps(body).encode(), headers, method="POST")
        try:
            return urllib.request.urlopen(request).status
        except urllib.error.HTTPError as e:
            return e.code

    assert b"Panel decyzji" in urllib.request.urlopen(f"{root}/").read()
    assert panel.decide(collector.open_db(collector.VERDICTS), "krem.shop", "review", undo=True)
    data = json.load(urllib.request.urlopen(f"{root}/api/cards?view=review"))
    assert data["counts"] == {"review": 1, "block": 5, "doubtful": 0, "cert": 1, "sample": 4, "remarks": 0} and data["cards"][0]["domain"] == "krem.shop"
    assert data["cards"][0]["shot"] is None
    assert [c["domain"] for c in json.load(urllib.request.urlopen(f"{root}/api/cards?view=cert"))["cards"]] == ["z.shop"]
    assert json.load(urllib.request.urlopen(f"{root}/api/domain?q=krem.shop"))["card"]["verdict"] == "review"
    assert [m["domain"] for m in json.load(urllib.request.urlopen(f"{root}/api/domain?q=kre"))["matches"]] == ["krem.shop"]
    assert json.load(urllib.request.urlopen(f"{root}/api/suggest?q=kre")) == {"users": [], "domains": ["krem.shop"]}
    assert b"scamdns_review_oldest_seconds" in urllib.request.urlopen(f"{root}/metrics").read()
    (collector.SHOTS / "krem.shop.jpg").write_bytes(b"\xff\xd8jpeg")
    assert json.load(urllib.request.urlopen(f"{root}/api/cards?view=review"))["cards"][0]["shot"] == "/shots/krem.shop.jpg"
    assert urllib.request.urlopen(f"{root}/shots/krem.shop.jpg").read() == b"\xff\xd8jpeg"
    shot = urllib.request.urlopen(f"{root}/shots/krem.shop.jpg")
    try:  # the browser's copy is still good: no picture sent again
        urllib.request.urlopen(urllib.request.Request(f"{root}/shots/krem.shop.jpg",
                                                      headers={"If-Modified-Since": shot.headers["Last-Modified"]}))
        raise AssertionError("no 304")
    except urllib.error.HTTPError as e:
        assert e.code == 304
    real_sleep, real_number = panel.time.sleep, collector.company_number
    def stop(_):
        raise InterruptedError
    panel.time.sleep = stop
    try:  # warm() saves the company numbers; after a restart it reads them, not the pages again
        try:
            panel.warm()
        except InterruptedError:
            pass
        assert collector.VERDICTS.with_name("panel_numbers.json").is_file()
        panel._numbers.clear()
        collector.company_number = lambda *a, **k: (_ for _ in ()).throw(AssertionError("numbers looked up again"))
        try:
            panel.warm()
        except InterruptedError:
            pass
        assert panel._numbers
    finally:
        panel.time.sleep, collector.company_number = real_sleep, real_number

    def status(path: str) -> int:
        try:
            return urllib.request.urlopen(root + path).status
        except urllib.error.HTTPError as e:
            return e.code

    assert status("/shots/..%2Fverdicts.db") == status("/shots/../watpliwe.txt") == status("/shots/x.jpg") == 404
    assert status("/api/domain?q=..%2Fetc") == 400
    assert post({"domain": "krem.shop", "decision": "block"}, {}) == 403  # another site cannot decide
    # nor one pointing its own name at 127.0.0.1 (DNS rebinding): to the browser that is the same site, X-Panel and all
    assert post({"domain": "krem.shop", "decision": "pass"}, {"X-Panel": "1", "Host": "evil.example:8081"}) == 403
    assert status("/api/counts") == 200 and urllib.request.urlopen(urllib.request.Request(
        f"{root}/api/counts", headers={"Host": "panel:8080"})).status == 200  # Prometheus' name for it
    try:
        urllib.request.urlopen(urllib.request.Request(f"{root}/api/cards", headers={"Host": "evil.example"}))
        raise AssertionError("a foreign Host read the cards")
    except urllib.error.HTTPError as e:
        assert e.code == 403
    assert post({"domain": "krem.shop", "decision": "delete"}, {"X-Panel": "1"}) == 400
    assert post({"domain": "krem.shop", "decision": "block"}, {"X-Panel": "1"}) == 200
    assert json.load(urllib.request.urlopen(f"{root}/api/cards?view=block"))["counts"]["block"] == 6
    assert json.load(urllib.request.urlopen(f"{root}/api/counts"))["block"] == 6  # the numbers alone, after a decision
    recent = json.load(urllib.request.urlopen(f"{root}/api/recent?n=2"))  # start_gui.py's last verdicts
    assert len(recent) == 2 and len(recent[0]) == 5
    assert len(json.load(urllib.request.urlopen(f"{root}/api/recent?n=x"))) <= 5
    served = json.load(urllib.request.urlopen(f"{root}/api/lists"))  # what home's DNS copies
    assert "*.glp.diet" in served["watpliwe.txt"] and set(served) <= set(collector.SERVED)

    def post_to(path: str, body: dict) -> int:
        request = urllib.request.Request(root + path, json.dumps(body).encode(), {"X-Panel": "1"}, method="POST")
        try:
            return urllib.request.urlopen(request).status
        except urllib.error.HTTPError as e:
            return e.code

    with socket.create_connection(("127.0.0.1", server.server_port), timeout=5) as raw:  # read(-1) would wait for good
        raw.sendall(b"POST /api/allow HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Panel: 1\r\nContent-Length: -1\r\n\r\n{}")
        assert b" 400 " in raw.makefile("rb").read()
    assert post_to("/api/allow", {"domain": "*.pl\n*.com", "allow": False}) == 400  # one domain, never a pattern
    assert post_to("/api/allow", {"domain": "myshoplaza.com", "allow": True}) == 403  # adding is by hand only
    assert post_to("/api/allow", {"domain": "krem.shop", "allow": False}) == 200
    assert post_to("/api/reported", {"domains": "z.shop"}) == 400 and post_to("/api/reported", {"domains": ["z.shop"]}) == 200

    # auditors through the Cloudflare tunnel: sign up, wait for the owner, then decide on cards and nothing else
    panel.PUBLIC = "panel.example"
    with panel.base() as accounts_db:
        panel.accounts(accounts_db)

    def ask(path: str, body: dict | None = None, cookie: str = "", ip: str = "203.0.113.5", host: str = "panel.example",
            origin: str = ""):
        headers = {"Host": host, "Cf-Connecting-Ip": ip, "X-Panel": "1", "Cookie": cookie} | ({"Origin": origin} if origin else {})
        data = json.dumps(body, ensure_ascii=False).encode() if body is not None else None  # UTF-8, as browsers send
        request = urllib.request.Request(root + path, data, headers, method="POST" if body is not None else "GET")
        try:
            response = urllib.request.urlopen(request)
            return response.status, response.headers, response.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    assert ask("/api/cards")[0] == 401 and ask("/api/lists")[0] == ask("/metrics")[0] == 403
    status_, headers_, body_ = ask("/api/liczby")  # the landing's numbers: no login, totals only
    figures_ = json.loads(body_)
    assert status_ == 200 and headers_["Access-Control-Allow-Origin"] == "https://grannyinternet.me" and headers_["Vary"] == "Origin"
    assert ask("/api/liczby", origin="https://jury.grannyinternet.me")[1]["Access-Control-Allow-Origin"] == "https://jury.grannyinternet.me"
    assert ask("/api/liczby", origin="https://evil.example")[1]["Access-Control-Allow-Origin"] == "https://grannyinternet.me"
    assert set(figures_) == {"checked", "blocked", "human", "asked", "since", "at"} and figures_["checked"] >= figures_["blocked"]
    status_, headers_, _ = ask("/login")
    assert status_ == 200 and headers_["X-Frame-Options"] == "DENY" and headers_["Referrer-Policy"] == "no-referrer"
    assert ask("/api/cards", host="localhost")[0] == 403  # Cloudflare's header: never local, whatever the Host says
    jan = {"login": "jan@example.com", "password": "długie hasło 123", "note": "Jan, CERT"}
    assert ask("/api/signup", jan, ip="192.0.2.70")[0] == 503  # no Turnstile key: a mail would go to anyone typed
    assert ask("/zglos")[0] == 200 and ask("/api/suspect", {"url": "zly.shop"})[0] == 503
    panel.TURNSTILE_SECRET, real_check, real_mail = "test", panel.human_check, panel.mail
    panel.human_check = lambda token, ip: token == "ok"
    mails = []
    panel.mail = lambda to, subject, text: mails.append((to, subject, text)) or True
    human = {"cf-turnstile-response": "ok"}
    assert b"TURNSTILE_SITE" not in ask("/login")[2]  # the site key put in, as on /zglos
    try:
        assert ask("/api/signup", jan | {"cf-turnstile-response": "bot"}, ip="192.0.2.71")[0] == 403
        assert ask("/api/signup", jan | {"password": "krótkie"} | human)[0] == 400
        assert ask("/api/signup", jan | human)[0] == 200
        for _ in range(50):  # the confirmation goes out beside the answer
            if mails:
                break
            time.sleep(.02)
        assert mails == [("jan@example.com", *panel.MAILS["received"])] and "CERT" not in mails[0][2]  # nothing typed
        assert ask("/api/signup", jan | {"login": "Jan@example.com"} | human)[0] == 400  # taken
        # attacks on the form: a note past 1000, an address that would break a mailto: link or a mail header
        assert ask("/api/signup", jan | {"login": "ewa@example.com", "note": "x" * 1001} | human, ip="192.0.2.72")[0] == 400
        for i, bad in enumerate(('"><script>@example.com', "a?cc=ofiara@example.com", "a,b@example.com",
                                 "a@example.com\r\nBcc: x@example.com", "<img src=x onerror=alert(1)>@example.com")):
            assert ask("/api/signup", jan | {"login": bad} | human, ip=f"192.0.2.{80 + i}")[0] == 400, bad
        with panel.base() as check:
            assert check.execute("SELECT count(*) FROM auditors").fetchone() == (1,)
        assert panel.typed(" a‮b\x00c​\r\n\td \n") == "abc\n\td" and panel.typed("żółw <b>") == "żółw <b>"
        assert ask("/api/login", {"login": "jan@example.com", "password": "długie hasło 123"})[0] == 401  # not approved yet
        # the owner lets them in on /konta, with a mail they wrote; never through the tunnel
        assert ask("/konta")[0] == ask("/api/accounts")[0] == 403
        assert ask("/api/account", {"login": "jan@example.com", "action": "approve", "message": "x"})[0] == 403
        listed = json.load(urllib.request.urlopen(f"{root}/api/accounts"))
        assert [(a["login"], a["note"], a["approved"]) for a in listed["accounts"]] == [("jan@example.com", "Jan, CERT", None)]
        assert set(listed["templates"]) == {"approve", "reject"} and urllib.request.urlopen(f"{root}/konta").status == 200
        assert post_to("/api/account", {"login": "jan@example.com", "action": "zrób", "message": ""}) == 400
        assert post_to("/api/account", {"login": "JAN@example.com", "action": "approve", "message": "Witaj!"}) == 200
        assert mails[-1] == ("jan@example.com", panel.MAILS["approve"][0], "Witaj!")
        assert post_to("/api/account", {"login": "jan@example.com", "action": "approve", "message": "x"}) == 404  # once
        assert post_to("/api/account", {"login": "nikt@example.com", "action": "reject", "message": ""}) == 404
    finally:
        panel.mail = real_mail
    assert ask("/api/login", {"login": "jan@example.com", "password": "złe hasło 1234"})[0] == 401
    status_, headers_, _ = ask("/api/login", {"login": "jan@example.com", "password": "długie hasło 123"})
    cookie = headers_["Set-Cookie"].split(";")[0]
    assert status_ == 200 and "HttpOnly" in headers_["Set-Cookie"] and "Secure" in headers_["Set-Cookie"]
    assert ask("/api/cards?view=review", cookie=cookie)[0] == 403  # the shared queues are the owner's
    assert ask("/api/cards?view=batch", cookie=cookie)[0] == 200
    assert ask("/api/lists", cookie=cookie)[0] == ask("/api/recent", cookie=cookie)[0] == 403  # the server's own
    assert ask("/api/allow", {"domain": "krem.shop", "allow": False}, cookie)[0] == 403
    assert ask("/api/reported", {"domains": ["z.shop"]}, cookie)[0] == 403
    assert ask("/api/decide", {"domain": "krem.shop", "decision": "doubtful"})[0] == 401  # no session
    status_, _, refused = ask("/api/decide", {"domain": "krem.shop", "decision": "doubtful"}, cookie)
    assert status_ == 409 and "właściciel dał blokadę" in json.loads(refused)["error"]  # the owner's block above stays
    status_, _, said_ = ask("/api/decide", {"domain": "krem.shop", "decision": "block"}, cookie)
    assert status_ == 200 and "block-1" in {b["id"] for b in json.loads(said_)["fresh"]}  # the first block: a badge
    assert ask("/api/decide", {"domain": "krem.shop", "decision": "doubtful"}, cookie)[0] == 200  # now their own
    with panel.base() as check:
        assert check.execute("SELECT by, who FROM history ORDER BY rowid DESC").fetchone() == ("human", "jan@example.com")
        assert check.execute("SELECT count(*) FROM auditors WHERE password LIKE '%hasło%'").fetchone() == (0,)
    assert post({"domain": "krem.shop", "decision": "doubtful"}, {"X-Panel": "1"}) == 200  # the owner: no login, no who
    with panel.base() as check:
        assert check.execute("SELECT who FROM history ORDER BY rowid DESC").fetchone() == (None,)
    for _ in range(10):
        ask("/api/login", {"login": "jan@example.com", "password": "zgadywane hasło"}, ip="198.51.100.9")
    assert ask("/api/login", {"login": "jan@example.com", "password": "długie hasło 123"}, ip="198.51.100.7")[0] == 429
    me = json.loads(ask("/api/me", cookie=cookie)[2])
    assert me["points"] == 1 and me["from"] == {"decision": 1} and me["rank"] == "nowicjusz"  # doubtful twice: one point
    assert ask("/api/me")[0] == 401 and json.loads(urllib.request.urlopen(f"{root}/api/suspects").read()) == []
    # a suspect site from anyone: Turnstile first, nothing opened, no address kept
    try:
        assert ask("/api/suspect", {"url": "zly.shop", "cf-turnstile-response": "bot"}, ip="192.0.2.50")[0] == 403
        for bad in ("", "127.0.0.1", "jan@example.com", "http://🦊.pl", "a" * 300 + ".pl"):
            assert ask("/api/suspect", {"url": bad, "cf-turnstile-response": "ok"}, ip="192.0.2.51")[0] == 400, bad
        assert ask("/api/suspect", {"url": "https://Krem.shop/promo?x=1", "note": "<b>tanio</b>",
                                    "cf-turnstile-response": "ok"}, ip="192.0.2.52")[0] == 200
        assert ask("/api/suspect", {"url": "żółw.pl", "cf-turnstile-response": "ok"}, ip="192.0.2.52")[0] == 200
        assert ask("/api/suspect", {"url": "inny.pl"}, cookie)[0] == 200  # an auditor: no Turnstile, a point
        assert ask("/api/suspect", {"url": "www.krem.shop", "cf-turnstile-response": "ok"}, ip="192.0.2.54")[0] == 200
        for _ in range(4):
            ask("/api/suspect", {"url": "x.pl", "cf-turnstile-response": "ok"}, ip="192.0.2.53")
        assert ask("/api/suspect", {"url": "x.pl", "cf-turnstile-response": "ok"}, ip="192.0.2.53")[0] == 200
        assert ask("/api/suspect", {"url": "x.pl", "cf-turnstile-response": "ok"}, ip="192.0.2.53")[0] == 429
    finally:
        panel.TURNSTILE_SECRET, panel.human_check = "", real_check
    sent = {s["domain"]: s for s in json.loads(ask("/api/suspects", cookie=cookie)[2])}
    assert sent["krem.shop"]["verdict"] == "doubtful" and sent["krem.shop"]["notes"] == ["<b>tanio</b>"]
    assert sent["www.krem.shop"]["verdict"] == "doubtful"  # verdicts hold the domain, the report the host typed
    assert "xn--w-uga1v8h.pl" in sent and sent["x.pl"]["times"] == 5
    assert json.loads(ask("/api/me", cookie=cookie)[2])["from"] == {"decision": 1, "suspect": 1}
    # badges: got ones kept when the count drops, a secret not got shows no name, each announced once
    me = json.loads(ask("/api/me", cookie=cookie)[2])
    shelf_ = {b["id"]: b for b in me["badges"]}
    assert len(shelf_) == len(panel.BADGES) and shelf_["block-1"]["at"] and shelf_["doubtful-1"]["at"]
    assert me["decisions"] == {"doubtful": 1} and not shelf_["pass-1"]["at"] and shelf_["pass-50"]["name"]
    assert shelf_["pass-secret"]["secret"] and "name" not in shelf_["pass-secret"] and "why" not in shelf_["pass-secret"]
    assert {"block-1", "doubtful-1"} <= {b["id"] for b in me["fresh"]}
    assert ask("/api/seen", {"ids": "block-1"}, cookie)[0] == 400
    assert ask("/api/seen", {"ids": [b["id"] for b in me["fresh"]]}, cookie)[0] == 200
    assert json.loads(ask("/api/me", cookie=cookie)[2])["fresh"] == []
    # the public name: made up at sign-up, changed by the auditor, never a staff look-alike, never taken twice
    assert me["name"] and "@" not in me["name"]
    for bad in ("ab", " -Jan", "Jan<b>", "Administrator", "Granny Team", "x" * 25, 5):
        assert ask("/api/name", {"name": bad}, cookie)[0] == 400, bad
    assert ask("/api/name", {"name": "  Jan   Tester "}, cookie)[0] == 200
    assert json.loads(ask("/api/me", cookie=cookie)[2])["name"] == "Jan Tester"
    # batches: the size picked each time, only the taker decides them, one at a time
    with panel.base() as seed:
        seed.executemany("INSERT INTO verdicts (domain, verdict, seen_at) VALUES (?, 'review', ?)",
                         [(f"p{i}.shop", f"2026-11-1{i}T00:00:00+00:00") for i in range(3)])
        seed.execute("INSERT INTO auditors (login, password, note, asked, approved, name) VALUES "
                     "('ola@example.com', ?, '', '', '2026-11-14', 'Ola Testowa')", (panel.hashed("hasło Oli 12345"),))
        seed.commit()
    # another auditor's page: by the public name, never the e-mail; the search box finds people and sites apart
    assert ask("/api/name", {"name": "ola testowa"}, cookie)[0] == 400  # taken, any case
    assert json.loads(ask("/api/suggest?q=TEST", cookie=cookie)[2])["users"] == ["Jan Tester", "Ola Testowa"]
    assert json.loads(ask("/api/suggest?q=t", cookie=cookie)[2])["users"] == []
    status_, _, seen_ = ask("/api/auditor?name=jan%20tester", cookie=cookie)
    assert status_ == 200 and "@" not in seen_.decode() and json.loads(seen_)["me"] and json.loads(seen_)["name"] == "Jan Tester"
    assert ask("/api/auditor?name=nikt", cookie=cookie)[0] == 404 and ask("/api/auditor?name=Ola%20Testowa")[0] == 401
    # the secret ones: a pass checked by phone, a doubtful one after midnight in Warsaw, 10 blocks in 10 minutes
    with panel.base() as check:
        check.execute("INSERT INTO auditors (login, asked, approved, name) VALUES "
                      "('ewa@example.com', '2025-12-31', '2026-01-02', 'Ewa Nocna')")
        start = datetime(2026, 11, 15, 23, 30, tzinfo=timezone.utc)  # 0:30 in Warsaw
        done_ = [("a.shop", "pass", "checked outside the site"), ("b.shop", "doubtful", None)]
        done_ += [(f"c{i}.shop", "block", None) for i in range(10)]
        check.executemany("INSERT INTO history (domain, verdict, reason, by, at, who) VALUES (?, ?, ?, 'human', ?, 'ewa@example.com')",
                          [(d, v, r, (start + timedelta(minutes=i)).isoformat()) for i, (d, v, r) in enumerate(done_)])
        panel.earn(check, "ewa@example.com")
        got_ = {b for b, in check.execute("SELECT badge FROM badges WHERE login = 'ewa@example.com'")}
        assert got_ == {"pass-1", "pass-secret", "doubtful-1", "doubtful-secret", "block-1", "block-secret"}  # 2025: no pioneer
        check.execute("UPDATE history SET at = ? WHERE domain = 'c9.shop'", ((start + timedelta(hours=1)).isoformat(),))
        check.execute("DELETE FROM badges WHERE login = 'ewa@example.com'")
        panel.earn(check, "ewa@example.com")
        assert not check.execute("SELECT 1 FROM badges WHERE badge = 'block-secret' AND login = 'ewa@example.com'").fetchone()
        for table, column in (("history", "who"), ("badges", "login"), ("auditors", "login")):
            check.execute(f"DELETE FROM {table} WHERE {column} = 'ewa@example.com'")
        check.commit()
    data = json.loads(ask("/api/cards", cookie=cookie)[2])
    assert data["cards"] == [] and data["counts"] == {"batch": 0} and data["lease"]["pool"] >= 3
    for size in (0, 51, "10", True, None, 2.5):
        assert ask("/api/batch", {"size": size}, cookie)[0] == 400, size
    status_, _, body_ = ask("/api/batch", {"size": 2}, cookie)
    assert status_ == 200 and json.loads(body_)["taken"] == 2 and json.loads(body_)["lease"]["batch"] == 2
    assert json.loads(ask("/api/batch", {"size": 5}, cookie)[2])["taken"] == 0  # the first one not done yet
    mine = [c["domain"] for c in json.loads(ask("/api/cards", cookie=cookie)[2])["cards"]]
    assert len(mine) == 2
    ola = ask("/api/login", {"login": "ola@example.com", "password": "hasło Oli 12345"}, ip="192.0.2.90")[1]["Set-Cookie"]
    ola = ola.split(";")[0]
    seen_ = json.loads(ask("/api/auditor?name=Jan%20Tester", cookie=ola)[2])
    assert not seen_["me"] and seen_["decisions"] == {"doubtful": 1} and "login" not in seen_
    status_, _, refused = ask("/api/decide", {"domain": mine[0], "decision": "pass"}, ola)
    assert status_ == 409 and "w paczce innego audytora" in json.loads(refused)["error"]
    assert ask("/api/batch", {"size": 50}, ola)[0] == 200
    hers = [c["domain"] for c in json.loads(ask("/api/cards", cookie=ola)[2])["cards"]]
    assert hers and not set(mine) & set(hers)
    assert ask("/api/decide", {"domain": mine[0], "decision": "block"}, cookie)[0] == 200
    left = json.loads(ask("/api/cards", cookie=cookie)[2])
    assert [c["domain"] for c in left["cards"]] == mine[1:] and left["lease"]["taken"] == 2 and left["counts"] == {"batch": 1}
    assert ask("/api/release", {}, cookie)[0] == 200 and json.loads(ask("/api/cards", cookie=cookie)[2])["cards"] == []
    assert ask("/api/decide", {"domain": mine[1], "decision": "pass"}, ola)[0] == 200  # handed back: anyone's
    assert ask("/api/decide", {"domain": hers[0], "decision": "pass"}, ola)[0] == 200
    # technical remarks: the card as the auditor saw it, to the owner's "uwagi" tab with their e-mail
    assert ask("/api/remark", {"domain": hers[0], "note": "  "}, ola)[0] == 400
    assert ask("/api/remark", {"domain": "nieznana.shop", "note": "to platforma"}, ola)[0] == 400
    assert ask("/api/remark", {"domain": hers[0], "note": 5}, ola)[0] == 400
    assert ask("/api/remark", {"domain": hers[0], "note": "simplybook.it to platforma"}, ola)[0] == 200
    assert ask("/api/remark-done", {"id": 1}, cookie)[0] == 403  # through the tunnel: the owner's only
    assert ask("/api/cards?view=remarks", cookie=ola)[0] == 403
    open_ = json.load(urllib.request.urlopen(f"{root}/api/cards?view=remarks"))
    assert open_["counts"]["remarks"] == 1 and len(open_["cards"]) == 1
    said = open_["cards"][0]
    assert said["domain"] == hers[0] and said["verdict"] == "pass"  # as she saw it: her decision came first
    assert said["remark"]["who"] == "ola@example.com" and said["remark"]["note"] == "simplybook.it to platforma"
    assert post_to("/api/remark-done", {"id": "1"}) == 400 and post_to("/api/remark-done", {"id": said["remark"]["id"]}) == 200
    assert json.load(urllib.request.urlopen(f"{root}/api/cards?view=remarks"))["cards"] == []
    # attacks: past 2000 characters, SQL in the domain, markup and hidden characters kept as plain text
    assert ask("/api/remark", {"domain": hers[0], "note": "x" * 2001}, ola)[0] == 400
    assert ask("/api/remark", {"domain": "x' OR '1'='1", "note": "to platforma"}, ola)[0] == 400
    assert ask("/api/remark", {"domain": [hers[0]], "note": "to platforma"}, ola)[0] == 400
    attack = "<img src=x onerror=alert(1)>‮\x00 " + "ż" * 1970  # 2001 sent, 1999 kept: the hidden two out
    assert ask("/api/remark", {"domain": hers[0], "note": attack}, ola)[0] == 200  # kept for forget() below
    with panel.base() as check:
        kept = check.execute("SELECT note FROM remarks ORDER BY rowid DESC").fetchone()[0]
        assert kept == "<img src=x onerror=alert(1)> " + "ż" * 1970  # shown with textContent: no tag runs
    # who decided: "ty" for oneself, nothing about others, the login for the owner only
    seen = lambda found: [h["who"] for h in found["history"] if h["by"] == "human"]
    assert seen(json.loads(ask(f"/api/domain?q={mine[0]}", cookie=cookie)[2])) == ["ty"]
    assert seen(json.loads(ask(f"/api/domain?q={mine[0]}", cookie=ola)[2])) == [None]
    assert seen(json.load(urllib.request.urlopen(f"{root}/api/domain?q={mine[0]}"))) == ["jan@example.com"]
    me = json.loads(ask("/api/me", cookie=cookie)[2])
    assert me["decisions"] == {"doubtful": 1, "block": 1} and me["suspects"] == 1  # the last one on each domain
    assert me["since"] and me["lease"]["batch"] == 0
    with panel.base() as check:
        jan_ = next(a for a in panel.waiting(check) if a["login"] == "jan@example.com")
        assert (jan_["decisions"], jan_["points"]) == (2, me["points"])
    # the password: the current one first, then every other session ends
    assert ask("/api/password", {"password": "złe hasło 0000", "new": "nowe hasło 12345"}, cookie)[0] == 403
    assert ask("/api/password", {"password": "długie hasło 123", "new": "krótkie"}, cookie)[0] == 400
    ola2 = ask("/api/login", {"login": "ola@example.com", "password": "hasło Oli 12345"}, ip="192.0.2.91")[1]["Set-Cookie"]
    assert ask("/api/password", {"password": "hasło Oli 12345", "new": "nowe hasło Oli 1"}, ola)[0] == 200
    assert ask("/api/me", cookie=ola2.split(";")[0])[0] == 401 and ask("/api/me", cookie=ola)[0] == 200
    # deleting the account: her decisions stay without her e-mail, her batch back to everyone
    assert ask("/api/forget", {"password": "hasło Oli 12345"}, ola)[0] == 403
    status_, headers_, _ = ask("/api/forget", {"password": "nowe hasło Oli 1"}, ola)
    assert status_ == 200 and "Max-Age=0" in headers_["Set-Cookie"] and ask("/api/me", cookie=ola)[0] == 401
    with panel.base() as check:
        assert check.execute("SELECT count(*) FROM history WHERE who = 'ola@example.com'").fetchone() == (0,)
        assert check.execute("SELECT count(*) FROM history WHERE who = ?", (panel.GONE,)).fetchone() == (2,)
        assert check.execute("SELECT count(*) FROM leases WHERE login = 'ola@example.com'").fetchone() == (0,)
        assert check.execute("SELECT who FROM remarks").fetchall() == [(panel.GONE,), (panel.GONE,)]
        assert check.execute("SELECT count(*) FROM auditors WHERE login = 'ola@example.com'").fetchone() == (0,)
    panel.manage("usun", "jan@example.com")
    assert ask("/api/cards", cookie=cookie)[0] == 401  # removed: the session ends at once
    # a blocked site's owner appeals: Turnstile, a blocked domain only, to the "uwagi" tab, a fixed mail back
    with panel.base() as setup:
        setup.execute("INSERT INTO verdicts (domain, verdict, ad) VALUES ('zablokowany.pl', 'block', '{}'), "
                      "('sklep.bookero.pl', 'block', '{}'), ('dobry.pl', 'pass', '{}')")
        setup.commit()
    state = lambda q: (lambda r: (r[0], json.loads(r[2])))(ask(f"/api/blokada?q={urllib.parse.quote(q)}"))
    assert state("https://www.zablokowany.pl/x") == (200, {"host": "www.zablokowany.pl", "domain": "zablokowany.pl",
                                                           "verdict": "block"})
    assert state("sklep.bookero.pl")[1]["domain"] == "sklep.bookero.pl" and state("krem.shop")[1]["verdict"] == "doubtful"
    assert state("dobry.pl")[1]["verdict"] is None and state("nieznany.pl")[1]["verdict"] is None
    assert state("ab@zablokowany.pl")[0] == state("")[0] == 400
    plea = {"url": "https://www.zablokowany.pl/kontakt", "email": "Szef@Firma.pl", "note": "Działamy od 2010, NIP 123",
            "cf-turnstile-response": "ok"}
    assert ask("/odwolanie")[0] == 200 and ask("/api/appeal", plea, ip="192.0.2.60")[0] == 503  # no Turnstile key
    panel.TURNSTILE_SECRET, panel.human_check, panel.mail = "test", lambda token, ip: token == "ok", \
        lambda to, subject, text: mails.append((to, subject, text)) or True
    longest = {"url": "https://zablokowany.pl/" + "a" * 2025, "note": "ż" * 2000}  # both at their limit
    mails.clear()
    try:
        assert b"TURNSTILE_SITE" not in ask("/odwolanie")[2]
        assert ask("/api/appeal", plea | {"cf-turnstile-response": "bot"}, ip="192.0.2.61")[0] == 403
        for i, bad in enumerate(({"email": "a?cc=b@x.pl"}, {"email": ""}, {"url": "nieznany.pl"}, {"url": "dobry.pl"},
                                 {"note": "krótko"}, {"note": "x" * 2001}, {"url": ["zablokowany.pl"]},
                                 {"url": "zablokowany.pl/" + "a" * 2034})):
            assert ask("/api/appeal", plea | bad, ip=f"192.0.2.{62 + i}")[0] == 400, bad
        assert ask("/api/appeal", plea, ip="192.0.2.70")[0] == 200
        assert ask("/api/appeal", plea | {"url": "sklep.bookero.pl"}, ip="192.0.2.70")[0] == 200  # the host itself
        assert ask("/api/appeal", plea | longest, ip="192.0.2.70")[0] == 200
        assert ask("/api/appeal", plea, ip="192.0.2.70")[0] == 429
        for _ in range(50):
            if len(mails) == 3:
                break
            time.sleep(.02)
        assert mails == [("szef@firma.pl", *panel.MAILS["appeal"])] * 3  # nothing they typed goes back out
    finally:
        panel.TURNSTILE_SECRET, panel.human_check, panel.mail = "", real_check, real_mail
    pleas = [p for p in json.load(urllib.request.urlopen(f"{root}/api/cards?view=remarks"))["cards"]
             if p["remark"]["note"].startswith(panel.APPEAL)]
    assert sorted(p["domain"] for p in pleas) == ["sklep.bookero.pl", "zablokowany.pl", "zablokowany.pl"]
    assert all(p["remark"]["who"] == "szef@firma.pl" and p["remark"]["note"] in (panel.APPEAL + "Działamy od 2010, NIP 123", panel.APPEAL + longest["note"])
               for p in pleas)
    panel.PUBLIC = ""
    assert ask("/api/cards", cookie=cookie)[0] == 403  # no public name set: no way in through the tunnel
    server.shutdown()
    server.server_close()

    collector.STATS["scamdns_ads_total"] = 2  # the collector's own counters, on :9100 in Docker
    stats = panel.ThreadingHTTPServer(("127.0.0.1", 0), collector.Metrics)
    threading.Thread(target=stats.serve_forever, daemon=True).start()
    assert urllib.request.urlopen(f"http://127.0.0.1:{stats.server_port}/metrics").read() == b"scamdns_ads_total 2\n"
    stats.shutdown()
    stats.server_close()

collector.gus_subject = lambda nip: {"name": "KASA BANK SA", "ended": ""}
collector.vat_subject = lambda nip: None  # MF did not answer: no KRS number either
collector.http_json = lambda url: {"isValid": True, "name": "ИНА КОЗМЕТИКС - ЕООД", "address": "София", "extra": 1}
assert panel.registry("NIP: 123-456-32-18") == {"nip": "1234563218", "gus": {"name": "KASA BANK SA", "ended": ""}, "mf": None,
                                                 "krs": None, "ceidg": None}  # no CEIDG token in tests
assert panel.registry("1234567890") == {"nip": "1234567890", "made_up": True}  # wrong check digit: no registry asked
collector.gus_subject = lambda number, kind="Nip": {"name": "KASA BANK SA", "ended": "", "nip": "1234563218" if kind == "Krs" else ""}
assert panel.registry("KRS 0000123456") | {"ceidg": None} == {  # a site giving only KRS: the NIP GUS finds behind it
    "nip": "1234563218", "by": "KRS 0000123456", "gus": {"name": "KASA BANK SA", "ended": "", "nip": ""}, "mf": None,
    "krs": None, "ceidg": None}
collector.gus_subject = lambda number, kind="Nip": {}
assert panel.registry("REGON 123456785")["gus"] == {} and panel.registry("REGON 123456785")["nip"] is None
# a company closed in GUS whose site's KRS shows it was merged into another (hossanova.pl)
collector.gus_subject = lambda nip: {"name": "HOSSANOVA 1 SP. Z O.O.", "ended": "2022-10-20", "nip": nip}
collector.krs_heir = lambda krs: {"name": "HOSSANOVA SP. Z O.O.", "krs": "0000088922"} if krs == "0000751127" else None
assert panel.registry("8943133285", "0000751127")["heir"] == {"name": "HOSSANOVA SP. Z O.O.", "krs": "0000088922"}
assert "heir" not in panel.registry("8943133285") and "heir" not in panel.registry("8943133285", "0000000001")
# section 6 of the court record: a liquidation ended by a resolution is over (czlowiekuruszsie.pl, 2021), an empty
# heading is nothing (hossanova.pl's "rozwiazanieUniewaznienie")
assert panel.section6({"likwidacja": [{"otwarcieLikwidacji": "UCHWAŁA 07.04.2021", "zakonczenieLikwidacji": "UCHWAŁA 08.12.2021"}],
                       "rozwiazanieUniewaznienie": {"okreslenieOkolicznosci": []}}) == ([], ["likwidacja"])
assert panel.section6({"likwidacja": [{"otwarcieLikwidacji": "UCHWAŁA 07.04.2021", "zakonczenieLikwidacji": ""}]}) == (["likwidacja"], [])
collector.gus_subject = lambda nip: {"name": "KASA BANK SA", "ended": ""}
collector.gus_subject = lambda nip: {"name": "KASA BANK SA", "ended": ""}
assert panel.registry("bg 206957657")["vies"] == {"isValid": True, "name": "ИНА КОЗМЕТИКС - ЕООД", "address": "София",
                                                  "userError": None}
assert panel.registry("krem.shop") is None and panel.registry("QQ123456") is None
# a Polish-looking NIP with a wrong check digit that is a Slovak VAT number without SK (Packeta on naturu.pl)
answers = {"SK/vat/2120099014": {"isValid": True, "name": "PACKETA SLOVAKIA s. r. o."},
           "SK/vat/2120099047": {"isValid": False, "userError": "INVALID"}}
collector.http_json = lambda url: answers["/".join(url.split("/")[-3:])]
assert panel.registry("2120099014")["vat"] == "SK2120099014"
assert panel.registry("2120099014")["vies"]["name"] == "PACKETA SLOVAKIA s. r. o."
assert panel.registry("2120099047") == {"nip": "2120099047", "made_up": True}  # fits SK, VIES knows no such firm
assert collector.company_number("NIP 9223089450 belongs to FIT FIVE") == "9223089450"
assert collector.company_number("Sklep: Global E-Commerce 84, Numer VAT: NL004926265B60") == "NL004926265B60"
assert collector.company_number("Krem na stawy, tylko 99 zł") is None
for footer, number in [("Paleta Beauty · NIP (VAT): 6252495518 W razie pytań", "6252495518"),
                       ("31-523 Kraków, Polska, NIP/VAT ID: PL6751823857. W sprawach", "6751823857"),
                       ("ASEMA Sp. z o.o.KRS: 0000876618NIP: 7792522018ul. J. Matejki", "7792522018"),
                       ("Marta Nowak sp. z o.o., NIP: 4739787022Poznań", "4739787022"),
                       ("Turzovka, Słowacja · NIP UE: SK2020134193 info@nikostorty.sk", "SK2020134193"),
                       ("Formularz: NIP opcjonalne, numer telefonu 500100200", None)]:
    assert collector.company_number(footer) == number, footer
meblotico = "Płatności: Google Pay © 2026 Meblotico · GRAND OAK SYSTEMS Sp. z o.o. · NIP 5833313671"
assert collector.company_number(meblotico) is None  # the courier and payment cut takes it, as in the collector's checks
assert collector.company_number(meblotico, own=False) == "5833313671"  # the panel's last try: the registry says whose
assert collector.company_number("PayU S.A. NIP 7792308495", own=False) is None  # PayU's own number never
odpis = {"odpis": {"naglowekA": {"dataRejestracjiWKRS": "22.01.2025"}, "dane": {
    "dzial1": {"kapital": {"wysokoscKapitaluZakladowego": {"wartosc": "5000,00"}}}, "dzial6": {"likwidacja": [{"otwarcieLikwidacji": "UCHWAŁA, 02.10.2026"}]}}}}
collector.http_json = lambda url: odpis
collector.vat_subject = lambda nip: {"name": "ECOM SP. Z O.O.", "statusVat": "Czynny", "krs": "0001151152", "x": 1}
assert panel.registry("8571941295")["krs"] == {"since": "22.01.2025", "capital": "5000,00", "events": ["likwidacja"],
                                                 "closed": []}

print("ok")
