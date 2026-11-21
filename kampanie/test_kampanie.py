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


if __name__ == "__main__":
    unittest.main()
