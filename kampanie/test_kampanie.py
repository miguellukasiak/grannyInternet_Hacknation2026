"""Synthetic materials only (the organiser's set may not be published): python -m unittest test_kampanie"""
import tempfile
import unittest
from pathlib import Path

from PIL import Image, ImageDraw

import kampanie as k

STORY = ("Rafał Brzoska ujawnia w wywiadzie, jak zarobić na nowej platformie inwestycyjnej. Zamach na jego życie "
         "był ostrzeżeniem, bo banki nie chcą, żeby zwykli ludzie poznali ten sposób na pasywny dochód. Wystarczy "
         "zarejestrować się dziś, a doradca zadzwoni i pokaże, jak wypłacić pierwszy zysk już po tygodniu. ") * 3


def news(domain: str, pixel: str, extra: str = "") -> str:
    return (f"<!-- saved from url=(0040)https://{domain}/?utm_id=a&utm_medium=b&utm_campaign=c -->"
            f"<html><head><title>Wywiad — Gazeta.pl</title><script>fbq('init', '{pixel}');</script></head><body>"
            f"<div class='art main'><p>{STORY}{extra}</p><img src='brzoska-avatar.jpg'>"
            f"<form><input type='tel' name='phone'></form><p>Lubię to · Odpowiedz</p></div></body></html>")


def picture(path: Path, seed: int):
    img = Image.new("RGB", (200, 120), "white")
    d = ImageDraw.Draw(img)
    for i in range(6):
        d.rectangle([seed * 7 + i * 30 % 180, i * 18, seed * 7 + i * 30 % 180 + 25, i * 18 + 15], fill="black")
    img.save(path)


def material(tmp: Path, name: str, html: str | None = None, text: str | None = None, seed: int | None = None):
    folder = tmp / name
    (folder / "strona_files").mkdir(parents=True)
    if html:
        (folder / "strona.html").write_text(html, encoding="utf-8")
    if text:
        (folder / "reklama.txt").write_text(text, encoding="utf-8")
    if seed is not None:
        picture(folder / "strona_files" / "hero.png", seed)  # a page asset: hashed, never OCR-ed
    return k.from_folder(folder)


class Campaigns(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            cls.ms = [
                material(tmp, "a", news("civicdaybook.live", "1071875908635809"), seed=1),
                material(tmp, "b", news("acrosscommunities.live", "1071875908635809"), seed=1),
                material(tmp, "c", news("novumfy.com", "2222222222222", " Inne zdanie na końcu."), seed=1),
                material(tmp, "d", text="Słodka Bonanza kasyno: bonus 500 zł i darmowe spiny, jackpot czeka. "
                                        "Zakręć slotem i odbierz wygraną już dziś!"),
                material(tmp, "e", text="Sklep z rowerami w Krakowie. Serwis, części i doradztwo od 1998 roku."),
            ]
        cls.base = k.Base(cls.ms)
        cls.by = {m.id: m for m in cls.ms}

    def test_features(self):
        a = self.by["a"]
        self.assertEqual(a.landing, ["civicdaybook.live"])
        self.assertIn("piksel Meta 1071875908635809", a.trackers)
        self.assertIn("Rafał Brzoska", a.persons)
        self.assertIn("Gazeta.pl", a.claimed)
        self.assertIn("utm_campaign,utm_id,utm_medium", a.params)
        self.assertEqual({n for _, n in a.images}, {"hero.png"})

    def test_verdict(self):
        self.assertEqual(k.verdict(self.by["a"])[0], "wysokie ryzyko: wygląda na oszustwo")
        self.assertTrue(any("Gazeta.pl" in why and "civicdaybook.live" in why for _, why in k.flags(self.by["a"])))
        self.assertEqual(k.verdict(self.by["e"])[0], "brak wyraźnych sygnałów")

    def test_campaigns(self):
        groups = {frozenset(c["members"]) for c in self.base.campaigns()}
        self.assertIn(frozenset("abc"), groups)  # clones on three domains, two with one pixel
        self.assertIn(frozenset("e"), groups)  # an honest shop joins nothing
        score, ev = self.base.compare(self.by["a"], self.by["b"])
        self.assertGreater(score, 0.95)
        self.assertIn("identyfikator", [kind for _, kind, _ in ev])
        self.assertIn(("a", "b"), self.base.campaigns()[0]["duplicates"])

    def test_fast_matrix_is_exact(self):
        ms = self.ms
        slow = [[self.base.compare(a, b)[0] if a is not b else 1.0 for b in ms] for a in ms]
        self.assertEqual(self.base.matrix().round(9).tolist(), [[round(x, 9) for x in r] for r in slow])

    def test_soft_clues_make_no_campaign(self):
        x, y = k.finish(k.Material(id="x", name="x")), k.finish(k.Material(id="y", name="y"))
        base = k.Base([x, y])
        base._pairs[("x", "y")] = (0.8, [(0.7, "narracja", ""), (0.35, "osoba", "")])  # one story, one celebrity
        self.assertEqual(base.link(x, y), 0.0)
        base._pairs[("x", "y")] = (0.8, [(0.6, "parametry", ""), (0.48, "tekst", "")])  # UTM and a checkout footer
        self.assertEqual(base.link(x, y), 0.0)
        base._pairs[("x", "y")] = (0.97, [(0.95, "identyfikator", ""), (0.35, "osoba", "")])
        self.assertEqual(base.link(x, y), 0.97)

    def test_cropped_picture_is_one_picture(self):
        with tempfile.TemporaryDirectory() as t:
            picture(full := Path(t) / "a.png", 3)
            with Image.open(full) as im:
                w, h = im.size
                im.crop((w // 10, h // 10, w - w // 10, h - h // 10)).save(cut := Path(t) / "b.png")
            picture(other := Path(t) / "c.png", 9)
            x, y, z = (k.Material(id=i, name=i) for i in "xyz")
            for m, p in ((x, full), (y, cut), (z, other)):
                k.add_image(m, p, screenshot=False)
        base = k.Base([k.finish(m) for m in (x, y, z)])
        self.assertIn("obraz", [kind for _, kind, _ in base.compare(x, y)[1]])
        self.assertNotIn("obraz", [kind for _, kind, _ in base.compare(x, z)[1]])

    def test_missing_data_is_no_counter_evidence(self):
        empty = k.finish(k.Material(id="x", name="x"))
        self.assertEqual(self.base.compare(self.by["a"], empty)[0], 0)
        self.assertTrue(empty.missing)

    def test_new_material(self):
        new = k.finish(k.Material(id="n", name="n"))
        k.add_html(new, news("freshdomain.live", "1071875908635809"), source="test")
        base = k.Base(self.ms + [new])
        placed = base.place(new, base.campaigns())
        self.assertIsNotNone(placed["campaign"])
        self.assertIn(placed["similar"][0][1], "abc")
        shop = k.finish(k.Material(id="s", name="s"))
        k.add_text(shop, "Piekarnia na rogu: chleb na zakwasie i drożdżówki codziennie od rana.")
        k.finish(shop)
        base = k.Base(self.ms + [shop])
        self.assertIsNone(base.place(shop, base.campaigns())["campaign"])

    def test_one_kit_on_two_domains(self):
        """Two landers, no common ID or text: the same backend API and the same own stylesheet link them."""
        import json
        css = ("body{margin:0}" * 60).encode()
        lib = ("/*! jQuery */" * 60).encode()

        def har(folder: Path, dom: str, page: str):
            def entry(method, url, mime="text/html", body=b""):
                return {"request": {"method": method, "url": url}, "response": {"status": 200, "content": {
                    "mimeType": mime, "text": __import__("base64").b64encode(body).decode(), "encoding": "base64"}}}
            folder.mkdir()
            (folder / "s.har").write_text(json.dumps({"log": {"entries": [
                entry("GET", f"https://{dom}/?ad_id=120250558396250564&utm_id=1&utm_source=fb&x=1", body=page.encode()),
                entry("GET", f"https://{dom}/main.css", "text/css", css),
                entry("GET", f"https://{dom}/jquery.min.js", "text/javascript", lib),  # a library: not the author's
                entry("GET", f"https://{dom}/wp-content/themes/a/style.css", "text/css", lib),  # a theme: neither
                entry("GET", "https://vz-6110f311-389.b-cdn.net/v.mp4", "video/mp4"),
                entry("POST", f"https://{dom}/api/v1/trigger/field/01a11f55-dea2-71c8-81fb-5bdfdd77fe0b/"),
                entry("POST", f"https://{dom}/api/v1/agent/persist-session-record/01a11f55-dea2-71c8-81fb")]}}))
            (folder / "ad.info.json").write_text(json.dumps({"title": "x", "playlist_uploader_id": "1183383648198728"}))
            return k.from_folder(folder)

        with tempfile.TemporaryDirectory() as t:
            x = har(Path(t) / "x", "civicdaybook.live", "<html><p>Pierwsza historia o czymś zupełnie innym.</p></html>")
            y = har(Path(t) / "y", "novumfy.com", "<html><p>Druga strona, inne zdania, inna osoba.</p></html>")
        self.assertEqual(x.kit, ["POST /api/v1/trigger/field/*/", "POST /api/v1/agent/persist-session-record/*"])
        self.assertEqual([f.split()[1] for f in x.files], ["main.css"])
        self.assertIn("reklama Meta 120250558396250564", x.trackers)
        self.assertIn("strona FB 1183383648198728", x.trackers)
        self.assertIn("vz-6110f311-389.b-cdn.net", x.domains)  # one CDN account, not all of b-cdn.net
        self.assertEqual(k.domain_of("www.b-cdn.net"), "b-cdn.net")
        k.add_trackers(g := k.Material(id="g", name="g"), "gtag('config','AW-18463917747');"
                                                          "https://www.google.com/pagead/1p-conversion/18463917747/")
        self.assertEqual(g.trackers, ["Google Ads 18463917747"])
        x.trackers = y.trackers = []  # without the shared ad IDs, the kit and the file alone must link them
        base = k.Base([x, y])
        kinds = [kind for _, kind, _ in base.compare(x, y)[1]]
        self.assertTrue({"zestaw", "pliki"} <= set(kinds))
        self.assertGreaterEqual(base.link(x, y), k.LINK)

    def test_shared_marks_link_shops(self):
        """22.11 base: one generated link word, one e-mail and one unusual robots.txt on shops of one owner."""
        robots = "User-agent: *\nDisallow: /gservice/\nDisallow: /service/\nDisallow: /checkout/\nSitemap: https://{}/s.xml"

        def shop(folder: Path, dom: str, text: str):
            folder.mkdir()
            (folder / "s.html").write_text(
                f"<!-- saved from url=(0080)https://{dom}/index/detail.html?sno=&coll_id=7&cskpopsybriyibc=9&opt_id= -->"
                f"<html><p>{text}</p><a href='mailto:Obsluga.Sklepu@gmail.com'>kontakt</a>"
                f"<script>Sentry.init({{dsn:'x@o1.ingest.sentry.io'}})</script></html>", encoding="utf-8")
            (folder / "robots.txt").write_text(robots.format(dom))
            return k.from_folder(folder)

        with tempfile.TemporaryDirectory() as t:
            x = shop(Path(t) / "x", "bangzli.com", "Buty sportowe, wyprzedaż dziś.")
            y = shop(Path(t) / "y", "dornsek.com", "Kurtka zimowa i czapka w zestawie.")
        self.assertEqual(x.marks, y.marks)  # the Sitemap line names the site: left out, so the files are one
        self.assertEqual(sorted(m.split(" #")[0] for m in x.marks), ["e-mail", "robots.txt", "słowo w linku"])
        self.assertNotIn("obsluga", " ".join(x.marks).lower())  # hashed: no e-mail or token in clear
        self.assertIn("GET /index/detail.html?coll_id", x.kit)
        base = k.Base([x, y])
        self.assertTrue({"słowo w linku", "robots.txt", "e-mail", "zestaw"} <= {kind for _, kind, _ in base.compare(x, y)[1]})
        self.assertGreaterEqual(base.link(x, y), k.LINK)
        self.assertTrue(k.generated("csupzpzygjirirc") and k.generated("ctnptptygwijrwc"))
        self.assertFalse(any(map(k.generated, ["affiliateid", "trackingcode", "fbclid", "utm_campaign", "orderref"])))
        for plain in ("User-agent: *\nDisallow: /", "User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/a.php\nDisallow: /x"):
            k.add_robots(z := k.Material(id="z", name="z"), plain)
            self.assertEqual(z.marks, [])

    def test_page_tells_are_flags(self):
        m = k.Material(id="t", name="t")
        k.add_robots(m, "User-agent: *\nDisallow: /")
        k.add_url(m, "https://tani-sklep.com/aB3xY9q", landing=True)
        k.add_url(m, "https://tani-sklep.com/x?name=%D0%98%D0%BC%D1%8F")
        k.add_html(m, "<html><body><script>var s='WYŁĄCZONY'</script></body></html>")
        k.add_text(m, "Cena：99 zł. Pierwszych 500 klientów otrzyma podwójne zamówienie, zamów już dziś")
        k.finish(m)
        why = " | ".join(w for _, w in k.flags(m))
        for part in ("Disallow", "tokenu", "WYŁĄCZONY", "Cyrylica", "Chiński dwukropek", "pierwszych 500 klient"):
            self.assertIn(part, why)
        self.assertEqual(k.verdict(m)[0], "wysokie ryzyko: wygląda na oszustwo")
        plain = k.Material(id="p", name="p")
        for url in ("https://sklep.pl/kontakt", "https://sklep.pl/produkty/", "https://sklep.pl/"):
            k.add_url(plain, url, landing=True)
        k.add_text(plain, "中文：这是一个中文网站，没有波兰语")
        k.finish(plain)
        self.assertEqual(plain.hints, [])
        self.assertEqual(k.flags(plain), [])
        k.add_text(one := k.Material(id="o", name="o"), "Gotówka przy odbiorze, tylko dziś!")
        self.assertEqual(k.verdict(k.finish(one)), ("słaby sygnał", 1))
        page = "<html><body>" + "<div><p><a>x</a></p></div>" * 3 + "</body></html>"
        k.add_html(bare := k.Material(id="b", name="b"), page)
        self.assertIn("mierzenia ruchu", " ".join(w for _, w in k.flags(bare)))
        k.add_html(tagged := k.Material(id="g", name="g"), page.replace("</body>", "<script>gtag('config','G-AB12CD34EF')</script></body>"))
        self.assertNotIn("mierzenia ruchu", " ".join(w for _, w in k.flags(tagged)))

    def test_private_url_refused(self):
        with self.assertRaises(ValueError):
            k.fetch(k.Material(id="p", name="p"), "http://127.0.0.1:8501/")


class Upload(unittest.TestCase):
    """The GUI's upload path: multipart on disk, ZIPs, and how files become materials."""

    def test_multipart_zip_and_grouping(self):
        import io
        import zipfile

        import app
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                z.writestr("zestaw/inc1/shot.txt", "a")
                z.writestr("zestaw/inc2/page.html", "<html></html>")
                z.writestr("../../etc/evil.txt", "x")  # a path that tries to climb out stays inside
                z.writestr("zestaw\\inc1\\", "")  # a folder entry the Windows way: not a file
            parts = [("url", None, b""), ("pliki", "zestaw.zip", buf.getvalue()),
                     ("pliki", "luzny/ad.txt", "żółć\r\n--x".encode())]
            body = b"".join(b'--XB\r\nContent-Disposition: form-data; name="%s"%s\r\n\r\n%s\r\n'
                            % (n.encode(), f'; filename="{f}"'.encode() if f else b"", v) for n, f, v in parts) + b"--XB--\r\n"
            (d / "body").write_bytes(body)
            (spool := d / "spool").mkdir()
            form, files = app.parse_multipart(d / "body", "multipart/form-data; boundary=XB", spool)
            self.assertEqual(form, {"url": ""})
            self.assertEqual(files[1][1].read_bytes(), "żółć\r\n--x".encode())  # boundary-like bytes inside survive
            entries = app.expand(files, spool)
            names = sorted(r for r, _ in entries)
            self.assertEqual(names, ["luzny/ad.txt", "zestaw/etc/evil.txt", "zestaw/zestaw/inc1/shot.txt",
                                     "zestaw/zestaw/inc2/page.html"])
            self.assertEqual([n for n, _ in app.group(entries, False)], ["luzny", "zestaw"])
            inc = [(r, p) for r, p in entries if "inc" in r]
            self.assertEqual([n for n, _ in app.group(inc, False)], ["inc1", "inc2"])  # wrappers stripped
            self.assertEqual(len(app.group(inc, True)), 1)  # a URL or text makes it one material
            self.assertEqual(app.new_id("a b", {"a-b"}), "a-b-2")


class Collector(unittest.TestCase):
    """Blocked domains from the collector's verdicts.db, and a reported domain that is already among them."""

    def test_read_and_report(self):
        import json
        import sqlite3

        import app
        import baza
        ad = {"ad_creative_bodies": ["Lekarze ukrywają ten cudowny lek na żylaki!"], "trackers": {"a.top": ["fb:123", "GTM-XXXXXX"]},
              "page_id": "77", "ips": {"a.top": ["203.0.113.5"]}, "age_days": {"a.top": 9}}
        with tempfile.TemporaryDirectory() as d:
            db = sqlite3.connect(path := f"{d}/verdicts.db")
            db.execute("CREATE TABLE verdicts (domain, verdict, reason, decided_by, ad, seen_at, decided_at)")
            db.executemany("INSERT INTO verdicts VALUES (?,?,?,?,?,?,?)", [
                ("a.top", "block", "young domain", None, json.dumps(ad), "2026-11-20", None),
                ("b.pl", "block", "llm: scam", None, None, "2026-11-19", None),
                ("c.pl", "block", "fake shop", "human", None, "2026-11-18", "2026-11-21"),
                ("d.pl", "pass", "ok", None, None, "2026-11-21", None)])
            db.commit()
            db.close()
            found = baza.read(path)
        self.assertEqual([(who, m.id) for who, m in found], [("human", "c.pl"), ("rule", "a.top"), ("llm", "b.pl")])
        a = found[1][1]
        self.assertEqual(a.trackers, ["piksel Meta 123", "strona FB 77"])  # the GTM placeholder is no ID
        self.assertEqual((a.ips, a.ages), (["203.0.113.5"], {"a.top": 9}))
        self.assertGreaterEqual(k.verdict(a)[1], 2)
        app.state["base"] = k.Base([m for _, m in found])
        m, note = app.known("a.top")
        self.assertIs(m, a)
        self.assertIn("Kolektor ją zablokował, reguła: young domain", note)
        self.assertIsNone(app.known("e.pl")[0])
        self.assertEqual(k.domain_of("a.netlify.app"), "a.netlify.app")  # sites on one platform are not one domain
        self.assertTrue(k.on_cdn("188.114.96.3") and not k.on_cdn("203.0.113.5"))


class Paging(unittest.TestCase):
    def test_page_numbers_and_links(self):
        import app
        self.assertEqual(app.page_no({"k": ["9"]}, "k", 45, 20), (3, 3))  # past the end: the last page
        self.assertEqual(app.page_no({"k": ["x"]}, "k", 45, 20), (1, 3))  # junk: the first
        self.assertEqual(app.page_no({}, "k", 0, 20), (1, 1))
        self.assertEqual(app.pager({}, "k", 1, 1, "/"), "")
        nav = app.pager({"s": ["2"], "zle": ["<x>"]}, "k", 2, 3, "/", "#kampanie")
        self.assertIn('href="/?s=2&amp;k=1#kampanie"', nav)  # the other list keeps its page, nothing else passes
        self.assertIn('href="/?s=2&amp;k=3#kampanie"', nav)
        self.assertNotIn("zle", nav)
        many = app.chips([f"d{i}.pl" for i in range(8)])
        self.assertIn("Pokaż jeszcze 3", many)
        self.assertEqual(many.split("<details")[0].count("chip"), 6)  # the list's own class and the first five
        self.assertNotIn("<details", app.chips(["a.pl", "b.pl"]))

    def test_topic_filter(self):
        import app
        ms = [k.Material(id=f"m{i}", name=f"m{i}", topics=t) for i, t in
              enumerate((["hazard"], ["hazard", "zdrowie / suplement"], ["zdrowie / suplement"], [], []))]
        camps = [{"members": ["m0", "m1", "m2"]}, {"members": ["m3", "m4"]}]
        saved, app.state["base"] = app.state["base"], k.Base(ms)
        try:  # the mixed one sits under the topic most of its materials have
            got, nav = app.by_topic({"t": ["hazard"]}, camps, "/", "#kampanie")
            self.assertEqual(got, camps[:1])
            self.assertIn('href="/?t=hazard#kampanie" aria-current="true"', nav)
            self.assertIn("bez tematu <b>1</b>", nav)
            self.assertEqual(app.by_topic({"t": ["<x>"]}, camps, "/")[0], camps)  # junk: all of them
        finally:
            app.state["base"] = saved

    def test_material_column_filters(self):
        import app
        ms = [k.Material(id="m0", name="m0", persons=["Jan Kowalski"], topics=["hazard"], landing=["kasyno.top"], missing=["x"]),
              k.Material(id="m1", name="m1", claimed=["Orlen"], landing=["oferta.pl"]),
              k.Material(id="m2", name="m2", topics=["hazard"], landing=["gra.top"])]
        camp = {"id": "K1", "members": ["m0", "m2"]}
        where, pts = {"m0": camp, "m2": camp}, {"m0": 5, "m1": 2, "m2": 0}
        ids = lambda q: [m.id for m in app.mat_filter(q, ms, where, pts)[0]]
        self.assertEqual(ids({}), ["m0", "m1", "m2"])
        self.assertEqual(ids({"fd": [".top"], "ft": ["hazard"]}), ["m0", "m2"])  # filters add up
        self.assertEqual(ids({"fw": ["hi"]}), ["m0"])
        self.assertEqual(ids({"fk": ["nowy"]}), ["m1"])
        self.assertEqual(ids({"fk": ["w"], "fb": ["nie"]}), ["m2"])
        self.assertEqual(ids({"fo": ["Orlen"]}), ["m1"])
        self.assertEqual(ids({"ft": ["bez tematu"]}), ["m1"])
        _, heads, tools = app.mat_filter({"fo": ['<b>"x'], "k": ["2"], "zle": ["1"]}, ms, where, pts)
        self.assertIn('<option value="&lt;b&gt;&quot;x" selected>', heads)  # the asked value stays, escaped
        self.assertIn('<option value="Jan Kowalski">Jan Kowalski (1)</option>', heads)
        self.assertIn('name="k" value="2"', tools)  # the campaign list keeps its page
        self.assertNotIn("zle", tools)
        self.assertIn("Pasuje <b>0</b> z 3", tools)
        self.assertIn("fo=x", app.pager({"fo": ["x"]}, "s", 1, 2, "/"))  # the pages keep the filters

    def test_expandable_graph(self):
        import app
        ms = [k.Material(id="m0", name="m0", trackers=["piksel Meta 1"], persons=["Jan Kowalski"]),
              k.Material(id="m1", name="m1", trackers=["piksel Meta 1"]),
              k.Material(id="m2", name="m2", trackers=["piksel Meta 2"], persons=["Jan Kowalski"]),
              k.Material(id="m3", name="m3", trackers=["piksel Meta 2"])]
        base = k.Base(ms)
        saved = app.state["base"], app.state["campaigns"]
        app.state.update(base=base, campaigns=base.campaigns())
        try:  # two campaigns by their pixels; one person in both is too weak to merge them, enough for a dashed line
            top = app.graph_data({})
            self.assertEqual(sorted(h["n"] for h in top["hubs"]), [2, 2])
            self.assertEqual(len(top["links"]), 1)
            self.assertIn("te same osoby: Jan Kowalski", top["links"][0]["why"])
            one = app.graph_data({"c": [top["hubs"][0]["id"]]})
            self.assertEqual(len(one["members"]), 2)
            self.assertEqual(len(one["links"]), 1)
            m0 = app.graph_data({"m": ["m0"]})
            shared = {(t["kind"], t["name"]): [o["id"] for o in t["others"]] for t in m0["traits"]}
            self.assertEqual(shared, {("identyfikator", "piksel Meta 1"): ["m1"], ("osoba", "Jan Kowalski"): ["m2"]})
            self.assertEqual(m0["traits"][0]["kind"], "identyfikator")  # IDs first
            self.assertIn("error", app.graph_data({"m": ["nie-ma"]}))
            self.assertIn("error", app.graph_data({"c": ["K999"]}))
        finally:
            app.state.update(base=saved[0], campaigns=saved[1])

    def test_hosting_firms_of_a_campaign(self):
        import app
        book = {"192.0.2.4": ({"country": {"iso_code": "SG"}}, {"autonomous_system_organization": "Tani Hosting"}),
                "192.0.2.5": ({"country": {"iso_code": "SG"}}, {"autonomous_system_organization": "Tani Hosting"})}
        fake = [type("R", (), {"get": staticmethod(lambda ip, i=i: book.get(ip, ({}, {}))[i])})() for i in (0, 1)]
        ms = [k.Material(id=f"m{i}", name=f"m{i}", ips=ips) for i, ips in
              enumerate((["192.0.2.4", "192.0.2.5"], ["192.0.2.4"], ["104.16.0.1"], [], ["198.51.100.9"]))]
        saved, app._geo = app._geo, fake
        try:  # two addresses of one site count once; Cloudflare's is a CDN; an unknown one still has a row
            self.assertEqual(app.hosting(ms), ["Tani Hosting · SG · 2", "nieznany dostawca · ? · 1", "za CDN 1", "bez adresu 1"])
            app._geo = []
            self.assertEqual(app.hosting(ms), [])  # no files in the image: no row
        finally:
            app._geo = saved

    def test_failed_regroup_clears_busy_bar(self):
        import app
        saved = app.commit
        app.commit = lambda ms: 1 / 0
        app.pending.append(k.Material("zly", "zly"))
        app.state["status"] = "Przeliczam kampanie z nowymi materiałami"
        try:  # otherwise the page refreshes every 3 s for ever
            app.regroup()
            self.assertEqual(app.state["status"], "")
            self.assertFalse(app.work.locked())
        finally:
            app.commit = saved
            app.pending.clear()

    def test_form_answers_with_redirect(self):
        import app, http.client, threading
        from http.server import ThreadingHTTPServer
        srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:  # Back after a POST must not ask to send the form again
            c = http.client.HTTPConnection("127.0.0.1", srv.server_port)
            c.request("POST", "/analizuj", "tekst=Tylko+dzi%C5%9B+cudowny+lek",
                      {"Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse(); r.read()
            self.assertEqual(r.status, 303)
            self.assertTrue(r.getheader("Location").startswith("/wynik/"))
            c.request("GET", r.getheader("Location")); r2 = c.getresponse()
            self.assertEqual(r2.status, 200)
            self.assertIn("nie zapisano", body := r2.read().decode())
            self.assertIn('href="/#dodaj">Dodaj kolejny materiał', body)
            c.request("GET", "/wynik/nie-ma"); r3 = c.getresponse(); r3.read()
            self.assertEqual(r3.status, 404)
        finally:
            c.close()
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
