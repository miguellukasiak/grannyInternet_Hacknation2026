"""Self-check of the scoring pipeline (no network): python test_collector.py"""

import base64
import contextlib
import gzip
import io
import json
import re
import socket
import sqlite3
import tempfile
import time
import urllib.error
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import collector
from collector import ad_domains, judge, score

collector._bert = False  # no ModernBERT in the self-check: words alone, as without the weights

scam = {
    "ad_creative_link_captions": ["WWW.Zysk-Orlen.SHOP"],
    "ad_creative_bodies": ["Brzoska ujawnia: inwestując 1000 zł zarabiasz 15 000 zł miesięcznie!"],
}
shop = {"ad_creative_link_captions": ["buty.pl"], "ad_creative_bodies": ["Wyprzedaż -70% na nową kolekcję"]}

assert ad_domains(scam) == {"zysk-orlen.shop"}
smyk = {"ad_creative_link_captions": ["Smyk.Brand-EU.com"]}
assert collector.ad_host(smyk, "brand-eu.com") == "smyk.brand-eu.com" and collector.ad_host({}, "a.pl") == "a.pl"
assert ad_domains({"ad_creative_link_captions": ["promo.netlify.app/x", "Dowiedz się więcej"]}) == {"promo.netlify.app"}
assert ad_domains({"ad_creative_link_captions": ["everdance.greatapps.co"]}) == {"everdance.greatapps.co"}  # an app alone
assert ad_domains({"ad_creative_link_captions": ["greatapps.co"]}) == set()  # the host itself never judged
assert ad_domains({"ad_creative_link_captions": ["potyczki.bookero.pl", "www.bookero.pl", "bookero.pl"]}) == {"potyczki.bookero.pl"}
assert ad_domains({"ad_creative_link_captions": ["yogashala-bialystok.cms.efitness.com.pl"]}) == {"yogashala-bialystok.cms.efitness.com.pl"}
assert not collector.has_registry("potyczki.bookero.pl") and collector.domain_age_days("potyczki.bookero.pl") is None
assert not "potyczki.bookero.pl".endswith(collector.FREE_HOSTS) and "x.coze.site".endswith(collector.FREE_HOSTS)
assert ad_domains({"ad_creative_link_captions": ["sites.google.com"]}) == {"google.com"}  # then caught by the allowlist
assert ad_domains({"ad_creative_link_captions": ["https://heca.art/k?utm_id={{campaign.id}}&utm_term={{adset.name}}#ad.name"]}) == {"heca.art"}

assert score(scam, "zysk-orlen.shop", age_days=5) == 2 + 2 + 3 + 1
assert score(shop, "buty.pl", age_days=4000) == 1
assert score(shop, "buty.pl", age_days=10) == 4  # new shop with a sale: borderline, not auto-blocked

real_age, real_decoy = collector.domain_age_days, collector.decoy
real_visit, real_walk, real_ad_link = collector.visit, collector.walk, collector.ad_link
real_forwards, collector.forwards = collector.forwards, lambda source, target: False  # no domain sends on to another
real_browse, tries = collector.browse, []  # a wall that stays: once more through WARP, when there is one
collector.browse = lambda url, expect, shot, light, warp=False: tries.append(warp) or (
    ("", "Sklep z butami", []) if warp else ("", "Proszę czekać na weryfikację żądania…", []))
collector.WARP = "socks5://warp:1080"
assert real_visit("https://x.pl/")[1] == "Sklep z butami" and tries == [False, True]
collector.WARP, tries[:] = None, []
assert real_visit("https://x.pl/")[1].startswith("Proszę") and tries == [False]
collector.browse = real_browse
collector.decoy = lambda domain: None
collector.walk, collector.ad_link = (lambda url, shot=None: None), (lambda ad, domain: None)  # no browser in this check
collector.visit = lambda url, expect=None, shot=None, light=False: None  # the card's other addresses: not loaded
real_ceidg, collector.ceidg_subject = collector.ceidg_subject, lambda nip: None  # nor CEIDG
real_vat_subject, collector.vat_subject = collector.vat_subject, lambda nip: None  # nor the MF white list
collector.OLLAMA = collector.GUS_KEY = None  # no LLM, no REGON: .env keys never reach this check
collector.domain_age_days = lambda domain: 5
assert judge(scam, "zysk-orlen.shop")[0] == "block"
assert judge(shop, "buty.pl")[0] == "review"
collector.domain_age_days = lambda domain: 4000
assert judge(shop, "buty.pl")[0] == "pass"
assert judge(scam, "zysk-orlen.shop")[0] == "review"  # yerbador.pl case: old shop with scammy wording
collector.domain_age_days = lambda domain: None
assert judge(scam, "zysk-orlen.shop")[0] == "review"  # RDAP down or date hidden: no proof the domain is new

collector.OLLAMA = "http://llm"
collector.domain_age_days = lambda domain: 10
collector.ask_llm = lambda ad, domain, age, site=None: {"scam": False, "reason": "regular shoe shop"}
assert judge(shop, "buty.pl") == ("review", 4, "page did not load, the model read only the ad: regular shoe shop")
collector.ask_llm = lambda ad, domain, age, site=None: {"scam": True, "reason": "fake shop"}
assert judge(shop, "buty.pl") == ("block", 4, "llm: fake shop")
chair = {"ad_creative_link_captions": ["fit-krzeslo.com"], "ad_creative_bodies": ["Schudnij siedząc! Tylko 397 zł"]}
assert score(chair, "fit-krzeslo.com", age_days=4000) == 0
assert judge(chair, "fit-krzeslo.com")[0] == "block"  # no keyword hit, the LLM still reads it
collector.domain_age_days = lambda domain: 4000
assert judge(scam, "zysk-orlen.shop")[0] == "review"  # LLM says scam about an old domain: a human decides
collector.domain_age_days = lambda domain: 5
collector.ask_llm = lambda ad, domain, age, site=None: {"scam": False, "reason": "real estate agency"}
assert judge(scam, "zysk-orlen.shop")[0] == "review"  # keywords alone never block (homiia.life), no page no pass
collector.domain_age_days = lambda domain: 10
collector.ask_llm = lambda ad, domain, age, site=None: None
collector.ask_llm = lambda ad, domain, age, site=None: {"scam": False, "reason": "Unknown domain, potentially fake"}
aged = dict(shop)
assert judge(aged, "buty.pl")[::2] == ("review", "llm passed it but wrote: Unknown domain, potentially fake")
assert aged["age_days"] == {"buty.pl": 10}  # stored with the ad for the panel card

collector.ask_llm = lambda ad, domain, age, site=None: None
walks = []
collector.walk = lambda url, shot=None: walks.append(url) or ("<p>Sklep</p>", "Buty sp. z o.o., 00-950 Warszawa. " * 20, [])
assert judge(shop, "buty.pl") is None  # LLM down: retry next cycle instead of guessing
collector.ask_llm = lambda ad, domain, age, site=None: {"scam": False, "reason": "regular shoe shop"}
assert judge(dict(shop), "buty.pl")[0] == "review" and len(walks) == 1  # the retry reuses the walk
assert judge(dict(shop), "buty.pl")[::2] == ("review", "young domain, llm passed it: regular shoe shop") and len(walks) == 2
collector.ask_llm = lambda ad, domain, age, site=None: {"scam": True, "reason": "Fake shop with no company details"}
assert judge(dict(shop), "buty.pl")[::2] == ("review", "company named on the page (address, legal form), the model claimed none")
collector.ask_llm = lambda ad, domain, age, site=None: {"scam": False, "reason": "Company details confirm a legitimate business"}
assert judge(dict(shop), "buty.pl")[::2] == ("review", "young domain, llm passed it: Company details confirm a legitimate business")
collector.ask_llm = lambda ad, domain, age, site=None: {"scam": True, "reason": "Fake shop with no company details"}
collector._gave_up.add("buty.pl")
assert judge(dict(shop), "buty.pl")[0] == "review"  # waited out NASK, but no NIP checked in the registries
real_nip, collector.nip_problem = collector.nip_problem, lambda text, domain="": None
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Buty sp. z o.o., NIP 123-456-32-18, Warszawa. " * 20, [])
numbered = dict(shop)
assert judge(numbered, "buty.pl")[0] == "pass"  # over 35 days old, its NIP passed GUS and MF
assert numbered["number"] == {"buty.pl": "1234563218"}  # for the panel's registry check
real_words, collector.words_score = collector.words_score, lambda ad, domain: 0.8
assert judge(dict(shop), "buty.pl")[0] == "review"  # reads like blocked ads: a human, NIP or not (glowme.pl)
collector.words_score = real_words
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Buty Ltd, company no 12345678, Warszawa. " * 20, [])
assert judge(dict(shop), "buty.pl")[0] == "review"  # a foreign number only (niebos.shop)
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Buty sp. z o.o., NIP 123-456-32-18, Warszawa. " * 20, [])
real_behind, collector.nip_behind = collector.nip_behind, lambda court: "1234563218"
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Buty sp. z o.o., KRS 0000123456, Warszawa. " * 20, [])
courted = {k: v for k, v in shop.items() if k not in ("number", "number_by")}
judge(courted, "buty.pl")  # only a KRS on the site: the panel gets the NIP GUS holds, always with what it stands for
assert courted["number"] == {"buty.pl": "1234563218"} and courted["number_by"] == {"buty.pl": "KRS 0000123456"}
collector.nip_behind = lambda court: None  # GUS silent: the KRS itself, which the panel turns into a NIP when asked
courted = {k: v for k, v in shop.items() if k not in ("number", "number_by")}
judge(courted, "buty.pl")
assert courted["number"] == {"buty.pl": "KRS 0000123456"} and "number_by" not in courted
collector.nip_behind = real_behind
collector.nip_problem, collector._gave_up = real_nip, set()
collector.walk = lambda url, shot=None: walks.append(url) or ("<p>Sklep</p>", "Buty sp. z o.o., 00-950 Warszawa. " * 20, [])
collector.domain_age_days = lambda domain: 4000
assert judge(dict(shop), "buty.pl")[0] == "pass"  # exeldomy.pl: NIP and REGON in the footer, 13 years old
collector.domain_age_days = lambda domain: 10
collector.ask_llm = lambda ad, domain, age, site=None: None
assert judge(shop, "buty2.pl", twin="buty.pl") == ("block", 4, "same ad as buty.pl")  # no LLM call for a clone
collector.domain_age_days = lambda domain: 4000
assert judge(dict(shop), "biedronka.pl", twin="buty.pl")[0] == "review"  # a firm the scam ad showed, not a bought one
collector.domain_age_days = lambda domain: 600
assert judge(shop, "buty2.pl", twin="buty.pl")[0] == "block"  # a domain bought aged for clones (lunarpiath.com)
collector.domain_age_days = lambda domain: 4000
collector.domain_age_days = lambda domain: 10

collector.domain_age_days = lambda domain: 4000
collector.decoy = lambda domain: "首页"
assert judge(shop, "rrieceffa.com") == ("block", 1, "decoy: 首页")  # an old, bought domain is no excuse
collector.decoy = lambda domain: None
collector.domain_age_days = lambda domain: 10

contact = "Kontakt: sklep@buty.pl, NIP 123-456-32-18, 00-950 Warszawa"
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Buty. " * 60 + contact, [])
seen = {}
collector.ask_llm = lambda ad, domain, age, site=None: seen.update(site) or {"scam": False, "reason": "real company"}
assert judge(shop, "buty.pl") == ("review", 4 - 3, "young domain, llm passed it: real company")  # each kind of company detail: one point off
assert seen["company_details"] == ["email", "address", "NIP"] and "NIP 123" in seen["landing_page"]
collector.ceidg_subject = lambda nip: {"since": "2023-10-11", "pkd": ["Wykonywanie pokryć dachowych", "Sprzedaż hurtowa"]}
judge(shop, "buty.pl")  # the model weighs the trades against the ad (melalucky.pl: a roofer's baby creams)
assert seen["company_register"]["registered_activities"] == ["Sprzedaż hurtowa", "Wykonywanie pokryć dachowych"]  # no main
assert seen["company_register"]["started_days_ago"] > 700  # days, not a date it may take for the future
collector.ceidg_subject = lambda nip: {"since": "2023-10-11", "pkd": ["Badanie rynku", "Pośrednictwo w sprzedaży detalicznej niewyspecjalizowanej"]}
judge(shop, "buty.pl")  # any goods: no list to misread (funidoo.pl, "consulting and market research, not retail")
assert "registered_activities" not in seen["company_register"] and seen["company_register"]["started_days_ago"] > 700
# a secondary PKD covers the ad: the model judges again seeing only it (twoj-kurs.pl: without any it wrote "unrelated")
courses = ["Pozostałe formy edukacji artystycznej", "Kursy i szkolenia związane ze zdobywaniem wiedzy"]
collector.ceidg_subject = lambda nip: {"since": "2009-01-05", "pkd": courses}
asked, real_covers, seeing = [], collector.pkd_covers, collector.ask_llm
collector.pkd_covers = lambda ad, domain, pkd: courses[1]
collector.ask_llm = lambda ad, domain, age, site=None: asked.append(list(site["company_register"]["registered_activities"])) or (
    {"scam": len(asked) == 1, "reason": "sells courses not in its PKD" if len(asked) == 1 else "a training company"})
assert judge(shop, "buty.pl")[2] == "young domain, llm passed it: a training company" and asked == [sorted(courses), [courses[1]]]
collector.pkd_covers, collector.ask_llm = real_covers, seeing
collector.ceidg_subject = real_ceidg
collector.ad_link = lambda ad, domain: "https://wyzwanie.buty.pl/w2/"
clicked = dict(shop)
judge(clicked, "buty.pl")
assert clicked["links"] == {"buty.pl": "https://wyzwanie.buty.pl/w2/"}  # stored with the ad for the panel
assert clicked["landing"]["buty.pl"].startswith("Buty. Buty.")  # the page text too, evidence for appeals
shots = []
collector.walk = lambda url, shot=None: shots.append(shot) or ("<p>Sklep</p>", "Buty. " * 60 + contact, [])
judge(shop, "buty.pl")
assert shots == [collector.SHOTS / "buty.pl.jpg"]
collector.ad_link = lambda ad, domain: None
spoof = {"ad_creative_link_captions": ["smyk.pl"], "ad_creative_bodies": ["Do -80% | Darmowa dostawa"],
         "destinations": ["https://bestmarketzone.shop/resources?u=njd45q", "https://buycenterpro.shop/r?u=w",
                          "https://wa.me/48500100200"]}  # WhatsApp is Meta's, no hidden shop
assert collector.hidden_domains(spoof) == ["bestmarketzone.shop", "buycenterpro.shop"]
assert judge(spoof, "smyk.pl")[::2] == ("review", "the ad shows smyk.pl but leads to bestmarketzone.shop, buycenterpro.shop")
assert spoof["links"] == {"smyk.pl": "https://bestmarketzone.shop/resources?u=njd45q"}  # the panel shows all of them
casino = {"ad_creative_link_captions": ["jola.xumi.net"] * 18, "id": "1",
          "ad_creative_bodies": [f"🎰 Bonus {lang} " + "Wygraj dziś! 💰 " * 140 for lang in ("pl", "de")] * 9,
          "destinations": ["https://crystal-peak.icu/go"], "fb_page": {"likes": 0, "categories": ["City"], "profile": "https://www.facebook.com/61551459309671/"}}
collector.domain_age_days = lambda domain: 4000  # any age (xumi.net, 32 days)
assert judge(dict(casino), "xumi.net")[::2] == ("block", "4222-character ad from a FB page with 0 likes")
assert judge(casino, "xumi.net") and casino["links"] == {"xumi.net": "https://crystal-peak.icu/go"}
unread = {k: v for k, v in casino.items() if k != "fb_page"}  # its FB page not found: never taken for 0 likes
assert "0 likes" not in judge(unread, "xumi.net")[2]
assert "0 likes" not in judge({**casino, "ad_creative_bodies": ["Nowa kolekcja 💰"]}, "xumi.net")[2]  # a short ad
mug = {**casino, "ad_creative_bodies": ["Twój jackpot czeka 💰"]}  # mug.com, 27 years old -> mellowhill.bar
assert judge(dict(mug), "mug.com")[::2] == ("block", "gambling (jackpot) from a FB page with 0 likes")
nun = {**casino, "ad_creative_bodies": ["Zobaczyłam matkę w domu opieki"], "page_name": "Nowa Kolekcja"}
assert judge(dict(nun), "med.com")[0] == "review"  # an old domain: a human (med.com, a caption, passed)
collector.domain_age_days = lambda domain: 30
assert judge(dict(nun), "vitallnexa.com")[::2] == ("block", "medicine, illness or old age (domu opieki) from a FB page with 0 likes")
named = {**casino, "ad_creative_bodies": ["Nowa kolekcja"], "page_name": "Hоmlа"}  # Cyrillic о and а
assert judge(dict(named), "homla.shop")[::2] == ("block", "FB page Hоmlа with foreign letters (оа) and 0 likes")
assert judge({**named, "page_name": "Triệu Khuê"}, "homla.shop")[2] == "FB page Triệu Khuê with foreign letters (ệê) and 0 likes"
assert judge({**named, "page_name": "Tâm Ăn"}, "homla.shop")[2] == "FB page Tâm Ăn with foreign letters (âĂ) and 0 likes"
assert judge({**named, "page_name": "𝐇𝐨𝐦𝐞 𝐒𝐭𝐨𝐫𝐞"}, "homla.shop")[0] == "block"  # math-bold letters
assert collector.unliked({**named, "page_name": "Łódzka Pączkarnia 🍩"}) is None  # Polish letters and emoji are no foreign ones
for page in ({"likes": 0, "categories": ["Profile"], "profile": "https://www.facebook.com/Vichy/"},  # always 0
             {"likes": 0, "categories": ["Shopping"], "profile": "https://www.instagram.com/_u/sklep"},
             {**casino["fb_page"], "likes": 3}):
    assert collector.unliked({**mug, "fb_page": page}) is None
collector.domain_age_days = lambda domain: 1
plain = {**casino, "ad_creative_bodies": ["Nowa kolekcja srebra"], "page_name": "Teresa Biżuteria"}
assert judge(dict(plain), "teresa-bizuteria.com")[::2] == ("block", "1-day-old domain from a FB page with 0 likes")
assert "0 likes" not in judge({**plain, "fb_page": {**casino["fb_page"], "likes": 3}}, "teresa-bizuteria.com")[2]
collector.domain_age_days = lambda domain: 7
assert "0 likes" not in judge(dict(plain), "teresa-bizuteria.com")[2]  # a week old: no longer newborn
collector.domain_age_days = lambda domain: 5
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Smyk sp. z o.o., NIP 123-456-32-18. " * 20, [])
spoofed = dict(spoof)
judge(spoofed, "smyk.pl")
assert spoofed["number"] == {"smyk.pl": "1234563218"}  # the caption's own site read for the human (goldenspa.pl)
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Buty. " * 60 + contact, [])
assert judge(spoof, "bestmarketzone.shop")[::2] == ("block", "hidden behind the caption smyk.pl")  # even with a company
collector.forwards = lambda source, target: (source, target) == ("smyk.pl", "bestmarketzone.shop")
assert judge(spoof, "bestmarketzone.shop")[2] != "hidden behind the caption smyk.pl"  # smyk.pl itself sends people there
assert judge(dict(spoof, links={}), "smyk.pl")[2] != "the ad shows smyk.pl but leads to bestmarketzone.shop, buycenterpro.shop"
opened = []
collector.walk = lambda url, shot=None: opened.append(url) or ("<p>Sklep</p>", "Buty. " * 60 + contact, [])
builder = {"ad_creative_link_captions": ["karolpieczka.pl"], "destinations": ["https://prezentkarolpieczka.grwebsite.pl/"]}
assert "leads to" not in judge(builder, "karolpieczka.pl")[2] and opened == ["https://karolpieczka.pl/"]
opened.clear()  # a shop on zgloszenia24.pl: the caption's own site judged, the platform never
ems = {"ad_creative_link_captions": ["easymotionskin.com.pl"],
       "destinations": ["https://zgloszenia24.pl/shop/emspro/ecommerce/product?id=6abb98ce9efc7&priceUuid=794"]}
assert "leads to" not in judge(ems, "easymotionskin.com.pl")[2] and opened == ["https://easymotionskin.com.pl/"]
assert "zgloszenia24.pl" in collector.TRUSTED  # in the collector's `allowed`: never judged, never blocked
opened.clear()  # an agency's landing for its client: the client judged, never the agency
izol = {"ad_creative_link_captions": ["Izolmax.pl"], "destinations": ["https://investboost.pl/izolmax"]}
assert "leads to" not in judge(izol, "izolmax.pl")[2] and opened == ["https://izolmax.pl/"]
assert {"investboost.pl"} <= collector.TRUSTED & collector.PLATFORMS
collector.forwards = lambda source, target: False
collector.domain_age_days = lambda domain: 4000
assert judge(spoof, "bestmarketzone.shop")[0] == "review"
collector.domain_age_days = lambda domain: 10
quiz = {"ad_creative_link_captions": ["a.quizgo.site"], "destinations": ["https://a.quizgo.site/", "https://szklarnie.pl/"]}
assert collector.hidden_domains(quiz) == ["szklarnie.pl"] and collector.lying_caption(quiz) == []
assert collector.hidden_domains({"ad_creative_link_captions": ["roaddiecast.pl"],
                                 "destinations": ["https://RoadDiecast.pl/pl/p/1"]}) == []  # the same domain, capitalised
# an emoji in a link's host crashed the collector in an HTTP header; a Polish IDN is fetched as punycode
assert collector.hidden_domains({"destinations": ["https://\U0001f449sklep.pl/", "https://zażółć.pl/"]}) == ["xn--za-6ja4f8n1l.pl"]
assert collector.walled("", "Żądanie z 203.0.113.7 nie może być obecnie obsłużone. Jeśli jesteś właścicielem serwera")
assert collector.walled("", "Page is protected To continue, you must confirm that you are not a robot. Proceed")
assert collector.walled("", "Сторінка захищена Щоб продовжити, ви повинні підтвердити, що ви не робот. Продовжити")
assert collector.walled("", "🛡️ Security Verification We need to verify that you're human before proceeding. Press and Hold Verify")
assert collector.walled("", "403 Forbidden nginx") and collector.walled("", "Forbidden You don't have permission to access this resource.")
assert not collector.walled("", "Forbidden Planet: komiksy i figurki")
assert judge(quiz, "szklarnie.pl")[2].startswith("young domain")  # a quiz's own shop is judged as usual, not as impersonation
smyk_page = dict(shop, page_name="ЅMҮК'Moda Dziecięca")  # Cyrillic Ѕ, Ү, К between Latin letters
assert judge(smyk_page, "buty.pl")[::2] == (
    "block", "FB page ЅMҮК'Moda Dziecięca: Cyrillic or Greek letters posing as Latin ones")  # even with a company
collector.domain_age_days = lambda domain: 4000
assert judge(smyk_page, "buty.pl")[0] == "review"
collector.domain_age_days = lambda domain: 10
for name in ("ЅМҮК Moda", "𝖡𝗂𝖾𝖽𝗋𝗈𝗇𝗄𝖺", "Rrieceffa-store", "Poligo-Shop PL", "Bostonct.mall"):
    assert collector.fake_page(name), name
for name, domain in (("Dr Piotr Kowalski", "essanova-pl.co"), ("Dr. Li Wei", "medicinejointhealth.com"),
                     ("Dr Krystyna Kowalczyk", "ceylon-9731.myshopify.com")):
    assert collector.fake_page(name, domain) == "a doctor's name on a shop not named after them", name
for name, domain in (("Dr. med. Mariusz Piątkowski Specjalistyczna Praktyka Lekarska", "drpiatkowski.pl"),
                     ("Dr Irena Eris", "drirenaeris.com"), ("Dr.Max", "drmax.pl"),
                     ("Drogeria Natura", "drogerianatura.pl"),
                     ("Profi Sklep", "sklep.com"), ("Dr Piotr Kowalski", "")):
    assert collector.fake_page(name, domain) is None, name
for name in ("Твой надежный обменник Velnox", "Wall printers⁺ - rozpocznij biznes", "HANDS UP shop", "Ремонт iPhone",
             "Bocian Polska Sklep", "SMYK", "Ελληνικά Νέα", ""):
    assert collector.fake_page(name) is None, name
assert collector.nip_problem("Dedoles Bratislava REGON: 46706305 NIP: 2023541630 VAT-UE: SK2023541630") is None
nip_shop = "Buty Kowalski sp. z o.o., NIP 123-456-32-18, ul. Łódzka 1, 00-950 Warszawa. " * 10
collector.walk = lambda url, shot=None: ("", nip_shop.replace("32-18", "32-19"), [])
assert judge(shop, "buty.pl")[::2] == ("block", "NIP 1234563219 is made up: wrong check digit")  # no MF call needed
collector.walk = lambda url, shot=None, everything=False: ("", nip_shop + "Kasa" * everything, [])
collector.vat_subject = lambda nip: {"name": "POWSZECHNA KASA OSZCZĘDNOŚCI BANK POLSKI SPÓŁKA AKCYJNA"}
assert judge(shop, "buty.pl")[::2] == ("block", "NIP 1234563218 belongs to POWSZECHNA KASA OSZCZĘDNOŚCI BANK POLSKI "
                                                "SPÓŁKA AKCYJNA, the site never names it")
collector.vat_subject = lambda nip: {"name": "KASA BANK"}  # named only on a legal page past the NIP (dataclub.pl)
assert judge(shop, "buty.pl")[2].startswith("young domain")
collector.vat_subject = lambda nip: {"name": "BUTY KOWALSKI SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ", "statusVat": "Czynny"}
assert judge(shop, "buty.pl")[2].startswith("young domain")  # the site's own company
collector.ceidg_subject = lambda nip: {"name": "BUTY KOWALSKI", "status": "ZAWIESZONY"}
assert judge(shop, "buty.pl")[::2] == ("block", "NIP 1234563218 belongs to BUTY KOWALSKI, suspended in CEIDG")
collector.ceidg_subject = lambda nip: None
assert collector.nip_problem("Firma BUTY Kowalski, Lodz. NIP 1234563218") is None  # case and Polish letters aside
collector.vat_subject = lambda nip: {"name": "PRZEDSIĘBIORSTWO HANDLOWO-USŁUGOWE ABC JAN NOWAK", "statusVat": "Czynny"}
assert collector.nip_problem("PHU ABC Jan Nowak, NIP 1234563218") is None  # a shortened name still counts
collector.vat_subject = lambda nip: {}
assert judge(shop, "buty.pl")[::2] == ("review", "NIP 1234563218 is not on the MF VAT white list")
collector.vat_subject = lambda nip: {"name": "BUTY KOWALSKI", "statusVat": "Niezarejestrowany"}
assert judge(shop, "buty.pl")[0] == "review"
collector.domain_age_days = lambda domain: 4000
collector.walk = lambda url, shot=None: ("", nip_shop.replace("32-18", "32-19"), [])
assert judge(shop, "buty.pl")[0] == "review"  # old domain: a human decides
collector.domain_age_days = lambda domain: 10
collector.vat_subject = lambda nip: None  # MF unreachable: the NIP counts as before
collector.walk = lambda url, shot=None: ("", nip_shop, [])
assert judge(shop, "buty.pl")[2].startswith("young domain")
assert collector.nip_problem("Płatności: PayU S.A., NIP 779-23-08-495") is None  # third parties are not checked
assert collector.company_number("Fakturownia sp. z o. o., Warszawa, KRS: 0000572426, NIP: 5213704420 w zakresie faktur") is None
assert collector.company_number("ul. Nowy Świat 54/56, 00-363 WarszawaNIP: 5253076071 | REGON") == "5253076071"
assert collector.company_number("turnip 5253076071") is None  # a lower-case word ending in nip is no NIP
real_http_json, asked = collector.http_json, []


def mf(url, body=None, timeout=30):  # status from api2, name from search; 1111111111 is on no list
    asked.append(url.split("/")[3])
    if "1111111111" in url:
        return {"result": {"subject": None}}
    status = "Niezarejestrowany" if "2222222222" in url else "Czynny"
    return {"result": {"subject": {"statusVat": status} | ({"name": "BUTY SA"} if "/search/" in url else {})}}


collector.http_json = mf
assert real_vat_subject("1234563218") == {"statusVat": "Czynny", "name": "BUTY SA"} and asked == ["api2", "api"]
assert real_vat_subject("1111111111") == {} and real_vat_subject("2222222222") == {"statusVat": "Niezarejestrowany"}
asked.clear()
collector._searches[next(iter(collector._searches))] = collector.SEARCHES_PER_DAY
assert real_vat_subject("1234563218") == {"statusVat": "Czynny"} and asked == ["api2"]  # names used up today
collector.http_json = lambda url, body=None, timeout=30: (_ for _ in ()).throw(OSError("429 limit"))
assert real_vat_subject("1234563218") is None  # MF silent and no searches left: no proof either way
collector._searches.clear()
collector.http_json = lambda url, body=None, timeout=30: mf(url) if "wl-api" in url else (_ for _ in ()).throw(OSError("403"))
asked.clear()  # the status API refused the server: the documented one answers, name and all
assert real_vat_subject("1234563218") == {"statusVat": "Czynny", "name": "BUTY SA"} and asked == ["api"]
assert collector._searches == {str(collector.datetime.now(collector.timezone.utc).date()): 1}
collector.http_json = real_http_json

gus = {"1234563218": "<root><dane><Nazwa>BUTY KOWALSKI SPÓŁKA Z O.O.</Nazwa><DataZakonczeniaDzialalnosci /></dane></root>",
       "7740001454": "<root><dane><Nazwa>STARA FIRMA</Nazwa>"
                     "<DataZakonczeniaDzialalnosci>2019-05-31</DataZakonczeniaDzialalnosci></dane></root>",
       "7740001508": "<root><dane><Nazwa>STARA FIRMA SPÓŁKA Z O.O.</Nazwa><DataZakonczeniaDzialalnosci /></dane></root>"}


def fake_bir(action, body, sid=""):  # GUS BIR1.1: a session, then the search; "" = bad session
    if action == "Zaloguj":
        return "sid1"
    nip = re.search(r"<dat:\w+>(\d+)<", body)[1]
    return gus.get(nip, "<root><dane><ErrorCode>4</ErrorCode></dane></root>") if sid == "sid1" else ""


real_bir, collector.bir = collector.bir, fake_bir
assert collector.gus_subject("1234563218") is None  # no key: the MF list stays in charge
collector.GUS_KEY = "key"
assert collector.gus_subject("1234563218") == {"name": "BUTY KOWALSKI SPÓŁKA Z O.O.", "ended": "", "nip": "", "regon": ""}
assert collector.gus_subject("1111111111") == {}
gus["9291906045"] = ("<root><dane><Nazwa>ALPHA FASHION SP.K.</Nazwa><DataZakonczeniaDzialalnosci /></dane>"
                     "<dane><Nazwa>ALPHA FASHION AR SP. Z O.O.</Nazwa>"
                     "<DataZakonczeniaDzialalnosci>2017-10-09</DataZakonczeniaDzialalnosci></dane></root>")
assert collector.gus_subject("9291906045") == {"name": "ALPHA FASHION SP.K.", "ended": "", "nip": "", "regon": ""}  # the live one (ozonee.pl)
assert collector.nip_problem("Buty Kowalski sp. z o.o., NIP 123-456-32-18") is None
assert collector.nip_problem("Krem, NIP 1111111111") == (True, "NIP 1111111111 is in no Polish business register (GUS REGON)")
real_vat, collector.vat_subject = collector.vat_subject, lambda nip: {"name": "MH HANDEL GMBH", "statusVat": "Czynny"}
assert collector.nip_problem("MH Handel GmbH, NIP 1111111111") is None  # a foreign firm on Polish VAT has no REGON (aosom.pl)
collector.vat_subject = lambda nip: {}
assert collector.nip_problem("Krem, NIP 1111111111") == (
    True, "NIP 1111111111 is in no Polish business register (GUS REGON, MF VAT list)")
collector.vat_subject = real_vat
assert collector.nip_problem("Stara Firma, NIP 7740001454")[0] is True  # closed in 2019, the shop sells today
# the footer keeps the closed sole trader, the terms name the company it became (y-s.eu)
assert collector.nip_problem("Stara Firma, NIP 7740001454. Regulamin: Stara Firma sp. z o.o., NIP 7740001508") is None
# someone else's sound NIP in the terms (a bank, a marketplace) does not stand for the shop
assert collector.nip_problem("Stara Firma, NIP 7740001454. Bank: Buty Kowalski sp. z o.o., NIP 1234563218")[1].startswith(
    "NIP 7740001454")
assert collector.nip_problem("Stara Firma, NIP 7740001454. Krem, NIP 1111111111")[1].startswith("NIP 7740001454")
assert collector.nip_problem("Krem Stawex, NIP 1234563218")[1].endswith("the site never names it")
# a suspended sole trader whose page names the live civil partnership she sells through (grupamocy.pl)
gus["8792555082"] = "<root><dane><Nazwa>Agnieszka Kaczor Fitfreak</Nazwa><DataZakonczeniaDzialalnosci /></dane></root>"
gus["9562394658"] = ("<root><dane><Nazwa>Fitfreak Agnieszka Kaczor, Krzysztof Kaczor spółka cywilna</Nazwa>"
                     "<DataZakonczeniaDzialalnosci /></dane></root>")
collector.ceidg_subject = lambda nip: {"name": "Agnieszka Kaczor Fitfreak", "status": "ZAWIESZONY"} if nip == "8792555082" else None
fitfreak = "Agnieszka Kaczor Fitfreak, NIP 8792555082"
assert collector.nip_problem(fitfreak) == (True, "NIP 8792555082 belongs to Agnieszka Kaczor Fitfreak, suspended in CEIDG")
assert collector.nip_problem(f"{fitfreak}, w spółce cywilnej Fitfreak Agnieszka Kaczor, Krzysztof Kaczor s.c., NIP 9562394658") is None
collector.ceidg_subject = lambda nip: None
# a company merged into another: the footer keeps its old KRS and NIP (hossanova.pl, absorbed in 2022)
gus["8943133285"] = ("<root><dane><Nazwa>HOSSANOVA 1 SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ</Nazwa>"
                     "<DataZakonczeniaDzialalnosci>2022-10-20</DataZakonczeniaDzialalnosci></dane></root>")
heir = {"name": "HOSSANOVA SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ", "krs": "0000088922"}
real_heir, collector.krs_heir = collector.krs_heir, lambda krs: heir if krs == "0000751127" else None
assert collector.nip_problem("Hossanova Sp. z o.o., KRS 0000751127 NIP 8943133285") is None  # the heir is named
assert collector.nip_problem("Apartamenty, KRS 0000751127 NIP 8943133285") == (False, "NIP 8943133285 belongs to HOSSANOVA 1 "
    "SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ, closed on 2022-10-20: merged into HOSSANOVA SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ (KRS 0000088922)")
assert collector.nip_problem("Hossanova, KRS 0000999999 NIP 8943133285")[0] is True  # no merger in the record: closed is closed
collector.krs_heir = real_heir
real_json, collector.http_json = collector.http_json, lambda url: {"odpis": {"dane": {"dzial6": {"polaczeniePodzialPrzeksztalcenie": [
    {"podmiotyPowstalePrzejmujace": [{"nazwa": [{"nazwa": "HOSSANOVA SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ,SPÓŁKA Z OGRANICZONĄ "
                                                         "ODPOWIEDZIALNOŚCIĄ"}], "krs": [{"krs": "0000088922"}]}]}]}}}}
assert collector.krs_heir("0000751127") == heir
collector.http_json = lambda url: {"odpis": {"dane": {"dzial6": {}}}}
assert collector.krs_heir("0000750298") is None
# a company renamed in KRS: the footer keeps its former name (renoma-agency.pl)
gus["5472253366"] = ("<root><dane><Regon>542088200</Regon><Nazwa>CENTRUM KOMPETENCJI PLUS SPÓŁKA Z OGRANICZONĄ "
                     "ODPOWIEDZIALNOŚCIĄ</Nazwa><Typ>P</Typ><DataZakonczeniaDzialalnosci /></dane></root>")
collector.bir = lambda action, body, sid="": ("<praw_numerWRejestrzeEwidencji>0001180870</praw_numerWRejestrzeEwidencji>"
                                              if action == "DanePobierzPelnyRaport" else fake_bir(action, body, sid))
collector.http_json = lambda url: {"odpis": {"dane": {"dzial1": {"danePodmiotu": {"nazwa": [
    {"nazwa": "BEAUTY MARKETING AGENCY SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ", "nrWpisuWykr": "7", "nrWpisuWprow": "1"},
    {"nazwa": "CENTRUM KOMPETENCJI PLUS SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ", "nrWpisuWprow": "7"}]}}}}} if "0001180870" in url else {}
assert collector.nip_problem("© 2026 Beauty Marketing Agency Sp. z o.o., NIP 5472253366") == (False, "NIP 5472253366 belongs to "
    "CENTRUM KOMPETENCJI PLUS SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ, the site names only its former name BEAUTY MARKETING "
    "AGENCY SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ (KRS), a human looks")
assert collector.nip_problem("Renoma Agency, NIP 5472253366")[1].endswith("the site never names it")
gus["0001180870"] = gus["5472253366"]  # a site giving only its KRS: the record asked straight
assert collector.registry_problem("Beauty Marketing Agency Sp. z o.o., KRS 0001180870")[0] is False
collector.bir = fake_bir
collector.http_json = real_json
# a site naming itself by KRS or REGON only: asked in GUS like a NIP 
gus["0000123456"] = ("<root><dane><Nazwa>BUTY KOWALSKI SPÓŁKA Z O.O.</Nazwa><Nip>1234563218</Nip>"
                     "<DataZakonczeniaDzialalnosci /></dane></root>")
assert collector.court_number("Buty Kowalski sp. z o.o., KRS: 0000123456, REGON 123456785") == "KRS 0000123456"
assert collector.court_number("Buty, REGON 123456785") == "REGON 123456785"
assert collector.court_number("Buty Kowalski, NIP 1234563218") is None
assert collector.registry_problem("Buty Kowalski sp. z o.o., KRS 0000123456") is None
# the NIP GUS holds behind it never goes without "no NIP on the site": the law wants the NIP in the offer
assert collector.registry_problem("Krem Stawex, KRS 0000123456") == (True, "KRS 0000123456 (no NIP on the site; GUS gives "
                                                                      "NIP 1234563218) belongs to BUTY KOWALSKI SPÓŁKA Z O.O., the site never names it")
assert collector.registry_problem("Krem, KRS 0000999999") == (
    True, "KRS 0000999999 (no NIP on the site) is in no Polish business register (GUS REGON)")
assert collector.registry_problem("Krem, REGON 123456789") == (True, "REGON 123456789 (no NIP on the site) is made up: wrong check digit")
assert collector.FAKE_NUMBER.search(collector.registry_problem("Krem, KRS 0000999999")[1])[1] == "0000999999"
assert collector.nip_behind("KRS 0000123456") == "1234563218" and collector.nip_behind("KRS 0000999999") is None
collector.bir = lambda action, body, sid="": (_ for _ in ()).throw(OSError("GUS down"))
assert collector.gus_subject("1234563218") is None
collector.bir, collector.GUS_KEY = real_bir, None

vies = {"DE/vat/811569869": {"isValid": True, "userError": "VALID", "name": "---"},
        "IT/vat/00743110157": {"isValid": True, "userError": "VALID", "name": "MOTOROLA SOLUTIONS ITALIA SRL"},
        "DE/vat/123456788": {"isValid": False, "userError": "INVALID", "name": "---"},
        "FR/vat/40303265045": {"isValid": False, "userError": "MS_MAX_CONCURRENT_REQ"}}
collector.http_json = lambda url, body=None, timeout=30: vies["/".join(url.split("/")[-3:])]
assert collector.EU_VAT.search("Numer VAT: SI 20992882 W firmie mamy")[2] == "20992882"  # the next word is no part
assert collector.EU_VAT.search("BTW NL123456789B01.")[2] == "123456789B01"
assert collector.company_number("Przelewy24.pl obługiwanej przez spółkę PayPro Spółka Akcyjna z siedzibą w Poznaniu przy ul. Pastelowej 8, 60-198 Poznań, wpisana do Rejestru Przedsiębiorców Krajowego Rejestru Sądowego prowadzonego przez Sąd Rejonowy Poznań Nowe Miasto i Wilda, VIII Wydział Gospodarczy Krajowego Rejestru Sądowego pod numerem KRS 0000347935, numer NIP 7792369887 PayPal (Europe)") is None  # PayPro's, not the shop's (katarzynagolebiewska.pl)
assert collector.eu_vat("NUMER REJESTRACYJNY: 8829420000, NUMER PODATKOWY: SI 75679060, TRR: SI56 1010") == ("SI", "75679060")  # mlandia.com
assert collector.company_number("UAB Edenred Finance Kod VAT: LT100008717218AdresSėlių st. 3A") == "LT100008717218"  # glued text
assert collector.vat_problem("XY GmbH, USt-IdNr.: DE 811 569 869, Amtsgericht") is None  # DE hides the name
assert collector.vat_problem("Shop SRL, P.IVA: IT00743110157") == (
    True, "VAT IT00743110157 belongs to MOTOROLA SOLUTIONS ITALIA SRL, the site never names it")
assert collector.vat_problem("Motorola Solutions Italia S.r.l., Partita IVA IT 00743110157") is None
assert not collector.unnamed("ИНА КОЗМЕТИКС - ЕООД", '"Ina Cosmetics" Sp. z o.o., VAT № BG 206957657')  # Cyrillic
assert collector.unnamed("ИНА КОЗМЕТИКС - ЕООД", "Sklep Krem, VAT BG 206957657")
assert collector.vat_problem("Shop, VAT DE123456788") == (False, "VAT DE123456788 is not valid in VIES")
assert collector.vat_problem("Shop, VAT DE123456789") == (True, "VAT DE123456789 is made up: wrong length or check digit")
assert collector.vat_problem("Via Zucchelli, 12 – Rome (Italy) VAT: IT1195720345 Business") == (
    True, "VAT IT1195720345 is made up: wrong length or check digit")  # 10 digits (globalgadgethub.com)
assert not collector.vat_malformed("IT", "007431101572024")  # a year run on after the number: no false alarm
slept, sleep = [], collector.time.sleep
collector.time.sleep = slept.append
assert collector.vat_problem("N° TVA intracommunautaire : FR40303265045") is None and slept == [2, 4]  # busy: no proof
busy = iter([{"userError": "MS_MAX_CONCURRENT_REQ"}, {"isValid": True, "userError": "VALID", "name": "SC X SRL"}])
collector.http_json = lambda url, body=None, timeout=30: next(busy)
assert collector.vies("RO", "39167080")["isValid"] and slept == [2, 4, 2]  # answered on the second try
collector.http_json, collector.time.sleep = lambda url, body=None, timeout=30: vies["/".join(url.split("/")[-3:])], sleep
assert collector.vat_problem("Ceny zawierają VAT de 23%, ab 100 zł") is None  # no EU prefix, no lookup
# a "NIP" with a wrong Polish check digit: a foreign VAT number without its prefix, asked in VIES (naturu.pl)
vies |= {"SK/vat/2120099014": {"isValid": True, "userError": "VALID", "name": "Packeta Slovakia s. r. o."},
         "SK/vat/2121833241": {"isValid": True, "userError": "VALID", "name": "Naturu s. r. o."},
         "CZ/vat/2121833241": {"isValid": False, "userError": "INVALID"},
         "SK/vat/2120099047": {"isValid": False, "userError": "INVALID"},
         "SK/vat/2120099036": {"isValid": False, "userError": "MS_UNAVAILABLE"}}
assert collector.foreign_vat("2120099014") == ["SK"] and collector.foreign_vat("1234563219") == []
assert collector.foreign_vat("2121833241") == ["SK", "CZ"]  # month 21: a Czech birth number too
assert collector.one_nip_problem("2121833241", "Naturu s. r. o., Bratislava, NIP: 2121833241", "naturu.pl") is None
assert collector.one_nip_problem("2120099014", "Sklep Krem, NIP: 2120099014", "krem.pl") == (
    True, "VAT SK2120099014 belongs to Packeta Slovakia s. r. o., the site never names it")
assert collector.one_nip_problem("2120099047", "Sklep Krem, NIP: 2120099047", "krem.pl") == (
    True, "NIP 2120099047 is made up: wrong check digit")  # fits SK's rule, VIES knows no such firm
assert collector.one_nip_problem("2120099036", "Sklep Krem, NIP: 2120099036", "krem.pl") is None  # SK off: no proof
naturu = ("Sprzedawca: Naturu s. r. o., REGON: 54973236, Bratislava. NIP: SK2121833241 Email: shop@naturu.pl. "
          + "Dane osobowe " * 30 + "przekazane: – Packeta Slovakia, s.r.o., Kopčianska 3338/82A, 851 01 Bratislava, "
          "REGON: 48136999, NIP: 2120099014, zarejestrowana w Rejestrze Handlowym Sądu Rejonowego Bratysława I, sekcja: s.r.o., numer wpisu: 105158/B"
          + " – Slovenská pošta, a.s, Partizánska cesta 9, 975 99 Banská Bystrica 1, REGON: 36631124, NIP: 2021879959")
assert collector.nip_problem(naturu, "naturu.pl") is None and collector.vat_problem(naturu, "naturu.pl") is None
assert collector.company_number(naturu) == "SK2121833241"  # the courier's number is cut out
assert collector.company_number("HOLY Softdrinks GmbH Numer VAT UE\nDE815887577 Kontakt") == "DE815887577"  # holy.com
assert collector.is_info("Dane Firmowe", "https://pl.holy.com/pages/dane-firmowe")
assert collector.vat_problem("Sofort (Operator płatności - SOFORT GmbH z siedzibą w 82131 Gauting, Wpisany w Sądzie Rejonowym w Monachium: HRB 218675, VAT UE: DE248376956)") is None  # the payment firm's number, not the shop's (pyszne.pl)
collector.http_json = real_http_json

assert collector.contradicts("Guaranteed profit and lack of effort") and collector.contradicts("Made-up brand name")
assert not collector.contradicts("No clear sign of fraud") and not collector.contradicts("Regular shoe shop")
assert collector.CLOSING.search("o moim małym butiku… Nie zamykamy się, ale musimy się zmniejszyć")
assert collector.CLOSING.search("Nie zamykamy się, ale musimy się zmniejszyć")
assert collector.CLOSING.search("LIKWIDACJA SKLEPU❗TOTALNA WYPRZEDAŻ") and collector.CLOSING.search("po 12 latach zamykamy sklep")
assert not collector.CLOSING.search("31 PAŹDZIERNIKA O 23:59 ZAMYKAM PROMOCJĘ! Zamykam zapisy do kursu")
assert collector.contradicts("wygraj bez wysiłku") and collector.contradicts("z gwarancją bez ryzyka") and collector.contradicts("Promotion of unlicensed pet food")
assert collector.clicked("https://www.sephora.pl/singles-day-pl/​", {}) == "https://www.sephora.pl/singles-day-pl/"
assert not collector.contradicts("It does not contain any suspicious language")
assert collector.contradicts("Company details don't match advertised business")  # a roofer's baby creams, passed
assert not collector.contradicts("No mismatch between the company and the ad")
assert not collector.contradicts("Shop doesn't match typical scam patterns")
assert not collector.contradicts("Promotion of a product with a low price and a guarantee")  # a warranty is no scam sign
# a "no" elsewhere in the reason is no denial of the sign (elnino-parfum.pl, fundednext.com passed)
assert all(collector.contradicts(r) for r in ("Fake shop with no company details", "Guaranteed profit with no effort",
                                              "Promotion of unproven medical product", "unsustainable income promise"))
assert not any(collector.contradicts(r) for r in (
    "It does not have any characteristics of a scam.", "nie ma podstaw do podejścia do oszustwa",
    "It's not enough to determine if it's a scam or not", "No company details or suspicious keywords",
    "W treści nie ma żadnych sygnałów, które sugerowałyby, że jest to oszustwo",
    "There is no indication of any suspicious or misleading information that would suggest it's a scam."))
assert all(collector.NO_COMPANY.search(r) for r in ("Unknown company with no NIP", "nie ma szczegółowych informacji o firmie",
                                                    "llm: nie ma firmowego numeru identyfikacyjnego", "Unknown developer",
                                                    "Missing company details", "company details are foreign and incomplete",
                                                    "Romanian domain with foreign registry and no Polish company details."))
assert all(collector.contradicts(r) for r in ("Company registered in Slovakia but lacks Polish registration details.",
                                              "Company registered for photography and hotels, not clothing retail."))
assert not any(collector.NO_COMPANY.search(r) for r in ("Company details and registration confirm a legitimate business.",
                                                        "Company details don't match advertised business"))
beniamin = "Sprzedawca: Beniamin Sp. z o.o. Sp. k., ul. Długa 1, 00-950 Warszawa"
assert collector.identified(collector.company(beniamin))
assert not collector.unnamed("BENIAMIN SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ SPÓŁKA KOMANDYTOWA", beniamin)
oto = "OTO ZŁOTO  ADRIANNA STEC-KONIECZNY, CYNTHIA STEC SPÓŁKA CYWILNA"  # REGON adds the owners of an s.c.
assert not collector.unnamed(oto, "OTOZŁOTO - sklep jubilerski, NIP: 627 280 52 64", "otozloto.com")  # the address spells it
assert not collector.unnamed("PRZEDSIĘBIORSTWO PRODUKCYJNO - USŁUGOWO - HANDLOWE KOMBINAT BUDOWLANY SPÓŁKA Z OGRANICZONĄ "
                             "ODPOWIEDZIALNOŚCIĄ", "PPUH Kombinat Budowlany Sp. z o. o., NIP 542-030-35-89", "kombinatbud.pl")
assert not collector.parses("https://[strona]/regulamin") and collector.parses("https://a.pl/x")
assert collector.unnamed(oto, "Krem na stawy, NIP: 627 280 52 64", "kremnastawy.shop")
mtp = "MIĘDZYNARODOWE TARGI POZNAŃSKIE SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ"
assert not collector.unnamed(mtp, "Hobbycon to wydarzenie Grupy MTP. NIP 7770000488")  # the initials name it
assert collector.unnamed(mtp, "Krem na stawy, NIP 7770000488")
assert collector.unnamed("POWSZECHNA KASA OSZCZĘDNOŚCI BANK POLSKI SPÓŁKA AKCYJNA", "Krem", "bank.shop")  # 4 letters: too short
collector.walk = lambda url, shot=None: ("<h1>Under Maintenance</h1>", "Under Maintenance", [])
assert judge(smyk, "brand-eu.com")[::2] == ("block", "decoy: Under Maintenance")  # visible only after JS
collector.walk = lambda url, shot=None: (("<h2>Witaj, świecie!</h2>", "Witaj, świecie!", []) if "//cms." in url
                                        else ("<p>Sklep</p>", "Buty sp. z o.o., NIP 123-456-32-18, Warszawa. " * 20, []))
assert not judge({"ad_creative_link_captions": ["cms.buty.pl"]}, "buty.pl")[2].startswith("decoy")  # the shop is on buty.pl
kept_decoy, collector.decoy = collector.decoy, lambda host: "Witaj, świecie!" if host.startswith("cms.") else None
assert collector.decoy_mark({"ad_creative_link_captions": ["cms.buty.pl"]}, "buty.pl") is None
collector.decoy = kept_decoy
collector.walk = lambda url, shot=None: ("", "Magdalena pisze… od 15 lat czytam karty tarota", [])
assert judge(shop, "buty.pl")[::2] == ("review", "quiz or fortune telling: tarot")  # young and nameless, still a human
assert judge(shop, "everdance.greatapps.co")[::2] == ("block", "quiz on a page with no domain of its own: tarot")
collector.walk = lambda url, shot=None: ("", "Plan Pilates maison Quiz de 1 minute Âge : 18-24 Âge : 25-39 Âge : 50+", [])
assert judge(shop, "buty.pl")[::2] == ("block", "quiz asking for age or sex: Âge :")  # justfit-pilates.com
collector.walk = lambda url, shot=None: ("", "Diet quiz. Diet for men Diet for women. Jaka płeć? Kobieta Mężczyzna", [])
assert judge(shop, "buty.pl")[2] == "quiz asking for age or sex: Kobieta Mężczyzna"
assert not collector.PERSONAL.search("Quiz: Diet for men Diet for women, manage: your plan")  # a menu is no question
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Krem na stawy, tylko dziś -70%. " * 20, [])
assert judge(shop, "buty.pl")[::2] == ("block", "no company named on the site or its legal pages")
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Zabawki z drewna. " * 20 + "Sprzedawca: Anna Nowak, działalność nierejestrowana", [])
assert judge(shop, "buty.pl")[::2] == ("review", "unregistered activity: na. Sprzedawca: Anna Nowak, działalność nierejestrowana")
collector.walk = lambda url, shot=None: ("<p>403</p>", "403 Forbidden nginx", [])
assert judge(shop, "buty.pl")[::2] == ("review", "page refuses the server (403 Forbidden), a human looks")
real_country_version, saved_walk = collector.country_version, collector.walk
collector.country_version = lambda domain, walked: "https://buty.pl/en-gb/"
collector.walk = lambda url, shot=None: ("", "Buty sp. z o.o., 00-950 Warszawa" if "en-gb" in url else "Krem na stawy. " * 30, [])
countried = dict(shop)
assert "no company" not in judge(countried, "buty.pl")[2] and countried["country"] == {"buty.pl": "https://buty.pl/en-gb/"}
collector.country_version = lambda domain, walked: None
collector.walk = lambda url, shot=None: ("", "Buty sp. z o.o., 00-950 Warszawa" if url == "https://buty.pl/" else "Załóż konto. " * 30, [])
assert "no company" not in judge({"ad_creative_link_captions": ["app.buty.pl/rejestracja"]}, "buty.pl")[2]  # graphik.pl
collector.country_version, collector.walk = real_country_version, saved_walk
shop_page = " ".join(f"{chr(97 + i % 26)}{chr(97 + i // 26 % 26)}ka" for i in range(400))  # 400 different words
collector._blocked_pages["zalandopl.com"] = collector.shingles(shop_page + " zalandopl.com 199 zł")
assert collector.same_page(shop_page + " domovoutlet.shop 149 zł", "domovoutlet.shop") == "zalandopl.com"
assert collector.same_page("Kontakt sklep@x.pl", "x.pl") is None  # a few lines are no fingerprint
assert collector.same_page(shop_page[:1200] + " ".join(f"inny{chr(97 + i % 26)}{chr(97 + i // 26)}" for i in range(300)), "x.pl") is None
collector.walk = lambda url, shot=None: ("", shop_page, [])
collector.domain_age_days = lambda domain: 4000
assert judge(dict(shop), "buty.pl")[::2] == ("block", "same page as zalandopl.com")  # old domains too
collector.domain_age_days = lambda domain: 10
collector._blocked_pages.clear()
collector.walk = saved_walk
broken = "Trochďż˝ o nas. Stworzone dla osďż˝b takich jak Ty, Ksiďż˝ďż˝ki i przepisy, uďż˝miechamy siďż˝. " * 8
collector.walk = lambda url, shot=None: ("", broken, [])
collector.domain_age_days = lambda domain: 4000
assert judge(dict(shop), "buty.pl")[::2] == ("block", "broken Polish letters (48x, e.g. ďż˝) and no company named")
collector.walk = lambda url, shot=None: ("", broken + " Kuchnia sp. z o.o., 00-950 Warszawa", [])
assert "broken" not in judge(dict(shop), "buty.pl")[2]  # mniammniam.com: an old site in ISO-8859-2, company named
icons = ('<a href="#" class="icon-facebook"></a><a href="https://www.instagram.com/"><svg aria-label="Instagram"></svg></a><a href="https://www.tiktok.com/@sklep">TikTok</a><a href="#" class="share-facebook">Udostępnij</a>')
assert collector.dead_socials(icons) == ["Facebook", "Instagram"]  # TikTok has a profile, a share button is "#"
assert collector.dead_socials('<a href="https://facebook.com/buty.pl">fb</a>') == []
assert collector.dead_socials('<a href="#">INSTAGRAM</a><a href="https://instagram.com/otozloto_">Instagram</a>') == []
assert collector.dead_socials('<a href="#" class="login-with">Zaloguj przez Facebook</a><script>i<a.length</script>') == []
collector.walk = lambda url, shot=None: (icons, "Krem na stawy. " * 30, [])
assert judge(dict(shop), "buty.pl")[2].endswith("; social icons lead nowhere: Facebook, Instagram")
collector.walk = saved_walk
collector.walk = saved_walk
assert collector.MOJIBAKE.findall("Ä… Ăł Ĺ› Ĺ‚ Ã³ Å› � zażółć gęślą jaźń") == ["Ä…", "Ăł", "Ĺ›", "Ĺ‚", "Ã³", "Å›", "�"]
collector.domain_age_days = lambda domain: 10
collector.domain_age_days = lambda domain: 4000
assert judge(shop, "buty.pl")[0] == "review"  # an old site naming no company: a human looks
collector.walk = lambda url, shot=None: ("", "Krem", ['"Regulamin" -> https://buty.pl/regulamin.pdf'])
assert judge(shop, "buty.pl")[::2] == ("review", 'no company named; to check by hand: '
                                                 '"Regulamin" -> https://buty.pl/regulamin.pdf')
collector.walk = lambda url, shot=None: ("", "Krem na stawy. " * 30 + "Pisz: help@krem.shop", [])
assert judge(shop, "buty.pl")[2] == "no company named on the site or its legal pages (only: email)"
assert collector.identified(collector.company("Buty sp. z o.o., ul. Prosta 1, 00-950 Warszawa"))
assert collector.identified(collector.company("Administratorem danych jest LOUIS S.C., ul. Polna 2, 00-950 Warszawa"))
assert "foreign registry" in collector.company("USt-IdNr.: DE 123456789")
romania = ("Prestatorul este ATELIER DÖME S.R.L., cu sediul în Sfântu Gheorghe. Număr de înregistrare la Registrul "
           "Comerţului J14/158/2013, cod unic de înregistrare RO32062435.")
assert collector.company(romania) == ["legal form", "foreign registry"]  # a terms page the collector missed
assert collector.company("Nr. Reg. Com. J40/1234/2020") == ["foreign registry"]
assert collector.company("CUI (odpowiednik polskiego NIP / VAT-EU): RO39167080") == ["foreign registry"]  # reelken.pl
assert collector.company("UAB „Rinkos tinklas” (numer rejestracyjny firmy 135927776, Kaunas") == ["foreign registry"]
assert collector.company_number("Wychowanek sp. z o.o. Dane rejestrowe firmy hostingowej: Hosty S.A. z siedzibą w Poznaniu, "
                                "KRS 0000123456, NIP 1234563218") is None  # the host's number, not the shop's (wiazarpolska.pl)
assert collector.EU_VAT.search(romania).groups() == ("RO", "32062435")  # asked of VIES like any EU VAT number
assert collector.company("WSA A/S, CVR 12345678") == ["legal form", "foreign registry"]
assert "foreign registry" in collector.company("prowadzony przez firmę Violetta Pugh, UTR 7594550663, 20 Merlin Way")
zanzibar = "LZDM Limited, REG No: Z00002666993, Zanzibar City, Tanzania, TIN: 185-158-438, info@angazanzibar.com"
assert {"legal form", "foreign registry"} <= set(collector.company(zanzibar))
france = ("SHOPADVENTURE, société par actions simplifiée (SAS), au capital social de 2 000 €, immatriculée au RCS "
          "de Limoges sous le numéro 904 295 003, dont le siège social est situé au 1 avenue d’Ester, 87069 Limoges")
assert {"legal form", "foreign registry"} <= set(collector.company(france))
assert "phone" not in collector.company(france) + collector.company(zanzibar)  # registry numbers are no phones
assert "phone" in collector.company("Infolinia 22 123 45 67 lub 501 234 567, NIP 1234567890")
abroad_ids = ["EIN: 12-3456789", "REG No: Z00002666993", "ABN 51 824 753 556", "CNPJ: 12.345.678/0001-90",
              "RCS Paris B 123 456 789",
              "N° TVA intracommunautaire : FR12345678901", "KvK-nummer 12345678", "Y-tunnus 1234567-8",
              "UID CHE-123.456.789", "REA MI-1234567", "Org.nr 556677-8899", "ИНН 7707083893",
              "GSTIN 27AAPFU0939F1ZV",
              "法人番号：1234567890123", "VAT Reg No: GB 123 4567 89", "Company Registration Number 08804411"]
assert [text for text in abroad_ids if "foreign registry" not in collector.company(text)] == []
everyday = ["Faktura VAT do zamówienia 123456789", "Ceny zawierają VAT i są cenami brutto 1999,00 zł",
            "Ein 100.000 Euro Gewinn", "nie 100 000 zł, tylko mniej", "Holiday Inn 2020-2021"]
assert [text for text in everyday if "foreign registry" in collector.company(text)] == []
assert "legal form" not in collector.company("Agnieszka, Incredible, programy dla kobiet")  # whole words only
uokik = "Skargi: Urząd Ochrony Konkurencji i Konsumentów (UOKiK), pl. Powstańców Warszawy 1, 00-950 Warszawa."
assert collector.company(uokik) == [] and collector.company("Płatności obsługuje PayU S.A., KRS 0000274399") == []
own = "Buty sp. z o.o., wpisana przez Sąd Rejonowy pod numerem KRS 0000123456. Płatności: PayU S.A., KRS 0000274399"
assert collector.company(own) == ["legal form", "KRS"]  # the shop's own KRS stays
collector.walk = lambda url, shot=None: ("", "Verifying your connection...", [])
assert judge(shop, "buty.pl")[0] == "review"  # never solved, a human looks
collector.walk = lambda url, shot=None: ('<iframe src="https://geo.captcha-delivery.com/captcha/">', "x" * 400, [])
assert judge(shop, "buty.pl")[0] == "review"  # DataDome: the wall is only in the html
collector.walk = lambda url, shot=None: ("", "404 Not Found nginx", [])
assert judge(shop, "buty.pl")[::2] == ("review", "dead page: 404 Not Found nginx")  # an error screen of an old firm: a human
collector.walk = lambda url, shot=None: ("", "StockDeal24 Archivi Tutti i diritti riservati", [])
assert judge(shop, "buty.pl")[::2] == ("review", "the page shows almost nothing: StockDeal24 Archivi Tutti i diritti riservati")
collector.walk = lambda url, shot=None: ("", "", [])
assert judge(shop, "buty.pl")[0] == "review"  # nothing at all on an old domain: a human (sephora.pl)
collector.domain_age_days = lambda domain: 10
assert judge(shop, "buty.pl")[0] == "block"  # on a young one the ad is active, the page is not
collector.domain_age_days = lambda domain: 4000
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Buty. " * 60 + contact, [])
homes = {"https://buty.pl/": ("", "", [])}  # the landing sells, the home page the card also links shows nothing
collector.visit = lambda url, expect=None, shot=None, light=False: homes.get(url)
collector.ad_link = lambda ad, domain: "https://buty.pl/p/1"
assert judge(dict(shop), "buty.pl")[2] != "the page shows almost nothing:  on https://buty.pl/"  # it names its company
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Buty. " * 60, [])
assert judge(dict(shop), "buty.pl")[::2] == ("review", "the page shows almost nothing:  on https://buty.pl/")  # nameless, old
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Buty. " * 60 + contact, [])
collector.ad_link = lambda ad, domain: None
collector.visit = lambda url, expect=None, shot=None, light=False: None


def gone(url, shot=None):
    raise collector.Dead("dead page: HTTP 502")


collector.walk = gone
assert judge(shop, "buty.pl")[::2] == ("review", "dead page: HTTP 502")  # Cloudflare 502 of an old firm: no model, a human


def catalog(home_text):
    def walk(url, shot=None):  # the ad's product page is gone, the shop's home page is there
        if url != "https://buty.pl/":
            raise collector.Dead("dead page: HTTP 404")
        return "<p>Sklep</p>", home_text, []
    return walk


collector.ad_link = lambda ad, domain: "https://buty.pl/p/1"
collector.walk = catalog("Buty. " * 60 + contact)
assert judge(dict(shop), "buty.pl")[2] != "dead page: HTTP 404"  # meskie-spodnie.pl: a named shop's product sold out
collector.walk = catalog("Buty. " * 60)
assert judge(dict(shop), "buty.pl")[::2] == ("review", "dead page: HTTP 404")  # a shop naming nobody: the 404 stands, old: a human
collector.ad_link = lambda ad, domain: None
collector.walk = gone
collector.domain_age_days = lambda domain: 10
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Buty. " * 60 + contact, [])
cod = [[220, 48, 32, 110_000], [255, 255, 102, 48_000], [94, 204, 62, 28_000], [231, 240, 245, 300_000]]
collector._looks["https://buty.pl/"] = cod  # the first screen of the shoe shop, as visit() measured it
assert judge(shop, "buty.pl")[::2] == ("block", "loud red, yellow and green blocks on the page")  # even with a company
assert collector.loud(cod) == {"red", "yellow", "green"}
collector._fonts["https://buty.pl/"] = [3818, 3667, {"Lato": "żęć"}]  # pitbullwestshop.shop, a fake Pitbull shop
assert judge(dict(shop), "buty.pl")[::2] == ("block", "3667 of 3818 letters in the browser's default font")
assert collector.bad_fonts([5158, 0, {"Assistant": "żćą"}]) == "a font without Polish letters: Assistant lacks żćą"
assert collector.bad_fonts([30530, 0, {"WooCommerce": "ó"}]) is None  # star ratings drawn in an icon font
assert collector.bad_fonts([5158, 0, {}]) is collector.bad_fonts(None) is collector.bad_fonts([150, 150, {}]) is None
collector.domain_age_days = lambda domain: 4000
collector._fonts["https://buty.pl/"] = [3818, 3667, {}]
assert judge(dict(shop), "buty.pl")[0] == "review"  # an old firm's page: a human
collector.domain_age_days = lambda domain: 10
assert collector.loud([[40, 167, 69, 30_000], [220, 53, 69, 5_000], [255, 255, 255, 900_000]]) == {"green"}  # a cart
assert collector.clicked("https://x.top/?a={{ad.id}}&b={{ campaign.name }}&s={{site_source_name}}", {"id": "42"}) == (
    "https://x.top/?a=42&b=pl&s=fb")
assert collector.company("NIP: 781 196 78 34, KRS 0000 123 456") == ["NIP", "KRS"]
for vat in ("VAT PL9562367302", "VAT-UE: PL9562367302", "Numer VAT: PL 956-236-73-02"):
    assert collector.company(vat) == ["NIP"], vat
assert collector.company("VAT DE 123456789") == ["foreign registry"]
footer = "Płatności obsługuje PayU S.A., NIP 779-23-08-495. " + "x " * 150 + "Kwant sp. z o.o., NIP 5170241998, KRS 0000297591"
assert collector.company_excerpt(footer).endswith("Kwant sp. z o.o., NIP 5170241998, KRS 0000297591")  # not PayU's
assert "PayU" not in collector.company_excerpt(footer) and collector.company_excerpt("Krem -80%") == ""
collector.walk = lambda url, shot=None: None
collector.domain_age_days = lambda domain: 10

links = [["Kontakt", "https://pl.shop.com/kontakt"], ["Regulamin", "https://shop.com/regulamin"],
         ["Kontakt", "https://evil.com/kontakt"], ["Buty", "https://shop.com/b"]]  # other site, not an info page
site = {
    "https://pl.shop.com/p/1": ("<p>p</p>", "Maść", links),
    "https://pl.shop.com/kontakt": ("<p>k</p>", "Adres", []),
    "https://shop.com/regulamin": ("<p>r</p>", "NIP 1234567890", []),
}
collector.visit = lambda url, expect=None, shot=None, light=False: site.get(url)
real_served, collector.served_text = collector.served_text, lambda url: ""
assert real_walk("https://pl.shop.com/p/1") == ("<p>p</p><p>k</p><p>r</p>", "Maść\nAdres\nNIP 1234567890", [])
site["https://shop.com/regulamin"] = ("<p>r</p>", "Wybierz oddział", [])  # a script swaps every page (kwant.net.pl)
collector.served_text = lambda url: "Regulamin. NIP 1234567890" if url == "https://shop.com/regulamin" else "Oddziały"
assert real_walk("https://pl.shop.com/p/1")[1] == "Maść\nAdres\nWybierz oddział\nRegulamin. NIP 1234567890"
collector.served_text = lambda url: ""
site["https://shop.com/regulamin"] = ("<p>r</p>", "NIP 1234567890", [])
assert collector.META_REFRESH.search('<meta http-equiv="refresh" content="0; url=https://booksy.com/biz/">')[1] == (
    "https://booksy.com/biz/")
contact = "Kowalski sp. z o.o., ul. Długa 5, 00-950 Warszawa, tel. +48 600 100 200, sklep@kowalski.pl"
site["https://pl.shop.com/kontakt"] = ("<p>k</p>", contact, [])  # named, the number only in the terms (wipcool.pl)
assert real_walk("https://pl.shop.com/p/1")[1] == f"Maść\n{contact}\nNIP 1234567890"
site["https://pl.shop.com/kontakt"] = ("<p>k</p>", "NIP 1234567890", [])
assert real_walk("https://pl.shop.com/p/1")[1] == "Maść\nNIP 1234567890"  # details found: the walk stops
assert real_walk("https://pl.shop.com/p/1", everything=True)[1] == "Maść\nNIP 1234567890\nNIP 1234567890"
assert real_walk("https://down.com/") is None
# the ad's link sends people on to another domain: its legal pages count (dawidkarierowo.com -> salespros.pl)
funnel = {"https://dawidkarierowo.com/optin": ("<p>o</p>", "Zapisz się", [["Polityka prywatności", "https://salespros.pl/polityka"]]),
          "https://salespros.pl/polityka": ("<p>p</p>", "Dawid Dziadkowiec, NIP: 7372221416", [])}
collector.visit = lambda url, expect=None, shot=None, light=False: funnel.get(url)
assert "7372221416" not in real_walk("https://dawidkarierowo.com/optin")[1]
collector._landed["https://dawidkarierowo.com/optin"] = "https://salespros.pl/start"
assert real_walk("https://dawidkarierowo.com/optin")[1] == "Zapisz się\nDawid Dziadkowiec, NIP: 7372221416"
assert not collector._landed
collector.visit = lambda url, expect=None, shot=None, light=False: site.get(url)
del site["https://pl.shop.com/kontakt"], site["https://shop.com/regulamin"]  # a bot guard cuts the next pages
assert real_walk("https://pl.shop.com/p/1")[2] == ['legal page did not load "Kontakt" -> https://pl.shop.com/kontakt',
                                                  'legal page did not load "Regulamin" -> https://shop.com/regulamin']
site["https://pl.shop.com/"] = ("", "Sklep", [["Polityka prywatności", "https://pl.shop.com/polityka"]])
site["https://pl.shop.com/polityka"] = ("", "NIP 1234567890", [])  # linked from the home page only (maasloop.com)
assert real_walk("https://pl.shop.com/p/1")[1] == "Maść\nSklep\nNIP 1234567890"


def downloads(url, expect=None, shot=None, light=False):  # a terms PDF by name, and a "page" that turns out to be a file
    if url == "https://shop.com/o-nas":
        raise collector.Download(url)
    return {"https://shop.com/": ("", "Krem", [["Regulamin PDF", "https://cdn.x.com/regulamin.pdf?v=2"],
                                              ["O nas", "https://shop.com/o-nas"]])}.get(url)


collector.visit = downloads
assert real_walk("https://shop.com/")[2] == ['file, not opened "Regulamin PDF" -> https://cdn.x.com/regulamin.pdf?v=2',
                                             'file, not opened "O nas" -> https://shop.com/o-nas']
terms = [["Regulamin sklepu", "https://lamania.com/regulaminy/sklep"]]  # a list of terms, not the terms
hub = {"https://lamania.com/": ("", "Sukienki", [["Regulaminy", "https://lamania.com/regulaminy"]]),
       "https://lamania.com/regulaminy": ("", "Wybierz", terms),
       "https://lamania.com/regulaminy/sklep": ("", "Lamania sp. z o.o., KRS 0000123456", [])}
collector.visit = lambda url, expect=None, shot=None, light=False: hub.get(url)
assert real_walk("https://lamania.com/")[1].endswith("KRS 0000123456")  # one level deeper
assert real_walk("https://lamania.com/")[2] == []
abroad = {"https://signia.net/pl-pl/": ("", "Aparaty", [["Kontakt", "https://signia.net/de-ch/kontakt"],
                                                       ["Kontakt", "https://signia.net/pl-pl/kontakt"]]),
          "https://signia.net/pl-pl/kontakt": ("", "WSAUD A/S, VAT DK 12345678", [])}
collector.visit = lambda url, expect=None, shot=None, light=False: abroad.get(url)
assert real_walk("https://signia.net/pl-pl/")[1].endswith("DK 12345678")  # de-ch skipped, pl-pl visited
abroad["https://signia.net/"] = ("", "Hearing", [["Contact", "https://signia.net/en/contact"],
                                                ["Kontakt", "https://signia.net/de/kontakt"],
                                                ["Privacy", "https://signia.net/en/privacy"]])
abroad["https://signia.net/en/contact"] = ("", "WSAUD A/S, VAT DK 12345678", [])
assert real_walk("https://signia.net/")[1].endswith("DK 12345678")  # global page: the most linked version
assert collector.is_info("Términos y condiciones", "https://x.com/ayuda/terminos-y-condiciones")
assert not collector.is_info("aire acondicionado", "https://x.com/aire-acondicionado")
assert not collector.is_info("SuperCoin", "https://x.com/supercoin?ctx=eyJjYXJkQ29udGV4dCI6eyJ")  # no "agb" in tokens
assert collector.is_info("AGB", "https://otto.de/service/agb/")
splash = {"https://bestbuy.com/": ("", "Choose a country", [["United States", "https://www.bestbuy.com/?intl=nosplash"],
                                                             ["Canada", "https://www.bestbuy.ca/en-ca"]]),
          "https://www.bestbuy.com/?intl=nosplash": ("", "Deals", [["Terms", "https://www.bestbuy.com/terms"]]),
          "https://www.bestbuy.com/terms": ("", "Best Buy Co., Inc., EIN: 41-0907483", [])}
collector.visit = lambda url, expect=None, shot=None, light=False: splash.get(url)
assert real_walk("https://bestbuy.com/")[1].endswith("EIN: 41-0907483")  # through the country picker, .ca skipped
rakuten = "楽天グループ株式会社 〒158-0094 東京都世田谷区玉川一丁目14番1号"
assert collector.identified(collector.company(rakuten)) and collector.is_info("会社概要", "https://corp.rakuten.co.jp/")
assert collector.locale("https://x.com/pl/regulamin") == "pl" and collector.locale("https://x.com/plany") is None
saved_visit = collector.visit
flags = [["Austria", "https://at.hm.eu/"], ["Poland", "https://pl.hm.eu/"], ["Germany", "https://de.hm.eu/"]]
collector.visit = lambda url, light=False, **kw: ("", "", flags)
assert collector.country_code("https://pl.hm.eu/", "hm.eu") == "pl" and collector.country_code("https://hm.eu/en-gb/", "hm.eu") == "gb"
assert collector.country_code("https://shop.hm.eu/", "hm.eu") is None and collector.country_code("https://x.com/pl/", "hm.eu") is None
assert collector.country_version("hm.eu", "https://de.hm.eu/x") == "https://pl.hm.eu/"  # homeandmarker.eu
assert collector.country_version("hm.eu", "https://pl.hm.eu/") is None  # the Polish one was read, no UK or US
flags.append(["UK", "https://hm.eu/en-gb/"])
assert collector.country_version("hm.eu", "https://pl.hm.eu/") == "https://hm.eu/en-gb/"
collector.visit = lambda url, light=False, **kw: ("", "", flags[:2])
assert collector.country_version("hm.eu", "") is None  # two languages are a switch, not a picker
collector.visit = saved_visit
policies = [[f"Polityka {i}", f"https://many.com/policies/{i}"] for i in range(12)]
collector.visit = lambda url, expect=None, shot=None, light=False: ("", "Nic", policies)
assert real_walk("https://many.com/")[2] == [f'legal page over the limit, not opened "Polityka {i}" -> '
                                             f'https://many.com/policies/{i}' for i in range(8, 12)]
policies.append(["Impressum", "https://many.com/impressum"])  # last in the footer, opened first: the number's page
assert "https://many.com/impressum" not in str(real_walk("https://many.com/")[2])


def broken(url, expect=None, shot=None, light=False):  # a dead landing, and a shop whose terms link is dead
    if url == "https://dead.com/" or url.endswith("/regulamin"):
        raise collector.Dead("dead page: HTTP 404")
    return "", "Krem", [["Regulamin", "https://shop2.com/regulamin"]]


collector.visit = broken
try:
    real_walk("https://dead.com/")
    raise AssertionError("a dead landing is the verdict, not an empty walk")
except collector.Dead:
    pass
assert real_walk("https://shop2.com/")[2] == ['legal page did not load "Regulamin" -> https://shop2.com/regulamin']
real_getaddrinfo = collector.socket.getaddrinfo


def resolver(errno, *known):
    def resolve(host, port):
        if host not in known:
            raise socket.gaierror(errno, "no")
    return resolve


collector.socket.getaddrinfo = resolver(socket.EAI_NONAME, collector.CANARY)
assert collector.unreachable("https://xbngzdfm.com/", "net::ERR_NAME_NOT_RESOLVED at x") == "decoy: no website"
assert collector.unreachable("https://erwinpl.com/", "net::ERR_EMPTY_RESPONSE at x") == "dead page: the server sent nothing"
collector.socket.getaddrinfo = resolver(socket.EAI_NONAME)  # no internet: Docker's resolver knows no name
for error in ("net::ERR_NAME_NOT_RESOLVED at x", "net::ERR_CONNECTION_REFUSED at x"):
    try:
        collector.unreachable("https://levina.pl/", error)
        raise AssertionError("offline, a missing site proves nothing")
    except collector.Offline:
        pass
collector.socket.getaddrinfo = lambda host, port: (_ for _ in ()).throw(socket.gaierror(socket.EAI_AGAIN, "dns"))
assert collector.unreachable("https://a.com/", "net::ERR_NAME_NOT_RESOLVED at x") is None  # our resolver hiccup
collector.socket.getaddrinfo = real_getaddrinfo
assert collector.unreachable("https://a.com/", "Timeout 30000ms exceeded") is None  # slow is no proof

library = (r'"ad_archive_id":"41","snapshot":{"link_url":"https:\/\/www.nope.com\/"}},'  # the page's other ads
           r'{"ad_archive_id":"42","snapshot":{"link_url":"https:\/\/pl.luropprt.com\/detail\/emp7?from=facebook",'
           r'"cards":[{"link_url":"https:\/\/www.other.com\/x"}]}},'
           r'{"ad_archive_id":"43","snapshot":{"link_url":"https:\/\/www.nope.com\/2"}}')
collector.visit = lambda url, expect=None, shot=None, light=False: (library, "", []) if url.endswith("id=42") else None
assert real_ad_link({"id": "42"}, "luropprt.com") == "https://pl.luropprt.com/detail/emp7?from=facebook"
assert real_ad_link({"id": "42"}, "other.com") == "https://www.other.com/x"
assert real_ad_link({"id": "7"}, "luropprt.com") is None and real_ad_link({}, "x.com") is None
library_ad = {"id": "42"}
real_ad_link(library_ad, "x.com")
assert library_ad["destinations"] == ["https://pl.luropprt.com/detail/emp7?from=facebook", "https://www.other.com/x"]
assert "fb_page" not in library_ad  # a page without the advertiser's data: nothing made up
page = (r'"ad_archive_id":"41","snapshot":{"page_profile_uri":"https:\/\/www.facebook.com\/other\/",'
        r'"page_categories":["Books"],"page_like_count":900}},'
        r'{"ad_archive_id":"42","snapshot":{"page_profile_uri":"https:\/\/www.facebook.com\/61594037744659\/",'
        r'"page_categories":["Obutev"],"page_like_count":16}}')
assert collector.fb_page(page, "42") == {"likes": 16, "categories": ["Obutev"],
                                         "profile": "https://www.facebook.com/61594037744659/"}
assert collector.fb_page(page, "7")["likes"] == 900  # the ad gone from the page: its FB page's other ads tell
assert collector.fb_page("<html></html>", "42") is None
details = {"data": {"ad_library_main": {"ad_details": {"advertiser": {"ad_library_page_info": {"page_info":
          {"ig_followers": 9355, "ig_username": "friscopl", "likes": 48484}}}}}}}  # frisco.pl
assert collector.instagram(details) == {"username": "friscopl", "followers": 9355}
details["data"]["ad_library_main"]["ad_details"]["advertiser"]["ad_library_page_info"]["page_info"]["ig_username"] = None
assert collector.instagram(details) is None and collector.instagram(None) is None and collector.instagram({}) is None
details["data"]["ad_library_main"]["ad_details"]["advertiser"]["ad_library_page_info"]["page_info"] = None
assert collector.instagram(details) is None
assert collector.fb_words({"fb_page": {"likes": 16, "categories": ["Health/beauty"], "profile": "https://www.facebook.com/61594037744659/"}}) \
    == "fb_likes_10 fb_numeric fb_cat_healthbeauty"  # what the word model reads of the FB page
assert collector.fb_words({}) == ""

queue = collector.open_db(":memory:")  # queued entries whose page died since: blocked, unless a human decided
for domain, by in (("gone.com", None), ("err.com", None), ("ok.com", None), ("mine.com", "human"), ("old.com", None),
                   ("shut.com", None)):
    queue.execute("INSERT INTO verdicts (domain, verdict, ad, decided_by) VALUES (?, 'review', ?, ?)",
                  (domain, json.dumps({"id": "5", "links": {domain: f"https://{domain}/?a={{{{ad.id}}}}"},
                                       "age_days": {domain: 4000 if domain == "old.com" else 9}}), by))
pages = {"https://err.com/?a=5": ("", "Not Found", []), "https://ok.com/?a=5": ("", "Sklep " * 100, []),
         "https://shut.com/?a=5": ("<h1>The website is under maintenance</h1>", "s***l The website is under maintenance", [])}


def requeue(url, expect=None, shot=None, light=False):
    if url.startswith(("https://gone.com/", "https://mine.com/")):
        raise collector.Dead("decoy: no website")
    if url.startswith("https://old.com/"):  # an old firm's campaign page gone with the ad: a human decides
        raise collector.Dead("dead page: HTTP 404")
    return pages.get(url)


collector.visit = requeue
assert collector.recheck(queue) == 3
assert dict(queue.execute("SELECT domain, verdict FROM verdicts")) == {
    "gone.com": "block", "err.com": "block", "ok.com": "review", "mine.com": "review", "old.com": "review", "shut.com": "block"}
opened = len(collector._rechecked)
assert collector.recheck(queue) == 0 and len(collector._rechecked) == opened  # each once a day, none opened again
assert collector.emptiness("<p>The website is under maintenance</p>", "Buty " * 100) == "decoy: under maintenance"
picker = [["Polska", "https://pl.kubolo.eu/"], ["Czechy", "https://cz.kubolo.eu/"], ["Węgry", "https://hu.kubolo.eu/"]]
assert collector.emptiness("", "Bulgaria Open Czech Rep. Open", picker) is None  # a country picker is no empty page
assert collector.emptiness("", "404 Not Found", picker) == "dead page: 404 Not Found"
assert collector.emptiness("", "PL3-MINUTOWY QUIZObudź swoją Kundalini") is None  # a quiz goes to a human instead
assert collector.emptiness("", "Magdalena pisze", url="https://astrolog.live/prawda") is None  # nor fortune telling
assert collector.emptiness("", "", url="https://quizgo.site/") is None
assert collector.emptiness("", "Select Your Country Country CZ — Česko ES — España") is None  # promo-storytel.com
long_text = "Lorem ipsum dolor sit amet. " * 20  # over 300 characters: the length alone says nothing
for html, mark in (("<title>Apache2 Ubuntu Default Page: It works</title>", "Apache2 Ubuntu Default Page"),
                   ("<html><title>Index of /</title><a href='css/'>css/</a>", "<title>Index of /"),
                   ("<b>Fatal error</b>:  Uncaught PDOException: SQLSTATE[HY000]", "Fatal error</b>:  Uncaught"),
                   ("Parse error: syntax error, unexpected '}' in /var/www/index.php", "Parse error: syntax error"),
                   ("<h3 class='card__heading'>Example product title</h3>", "Example product title")):
    assert collector.emptiness(html, long_text) == f"decoy: {mark}", html
assert collector.emptiness('<h2><a href="/?p=1">Witaj, świecie!</a></h2>', long_text) == "decoy: Witaj, świecie!"
assert collector.emptiness('<h2 class="title">Witaj, świecie! To ja.</h2>', long_text) is None  # kidsandus.pl's own
assert collector.emptiness("<p>Warning: Undefined variable $x</p>", long_text) is None  # a warning, the shop still works
webinar = {"ad_creative_link_captions": ["event.webinarjam.com"], "links": {"webinarjam.com": "https://event.webinarjam.com/r/1"}}
assert collector.shown_links(webinar, "webinarjam.com") == ["https://event.webinarjam.com/r/1", "https://webinarjam.com/"]
assert collector.shown_links({"ad_creative_link_captions": ["go.x.com"]}, "x.com") == ["https://go.x.com/", "https://x.com/"]
assert collector.shown_links({"ad_creative_link_captions": ["reha.s.com/s/Jan"]}, "s.com") == ["https://reha.s.com/s/Jan", "https://s.com/"]
before = collector.visit
collector.visit = lambda url, expect=None, shot=None, light=False: ("", "", []) if url.endswith(".com/") else (
    "", "Webinar " * 100, [])
assert collector.dead_link(webinar, "webinarjam.com") is None  # getresponsewebsite.com: a platform's home is not the ad's
assert collector.dead_link({"links": {"x.com": "https://x.com/p"}}, "x.com") == (
    "the page shows almost nothing:  on https://x.com/")  # the advertiser's own home still counts
collector.visit = before
assert collector.caption_url({"ad_creative_link_captions": ["https://x.com/produkt/kurs-fotog..."]}, "x.com") == "https://x.com/"  # cut by Meta

long_ad = {"ad_creative_bodies": ["Czekasz miesiącami na ortopedę? " * 4]}
assert collector.fingerprint(long_ad) and collector.fingerprint(shop) is None

def rdap(code):
    def fail(url):
        raise OSError(f"{code} {url}")
    return fail


real_http_json = collector.http_json
collector.http_json = lambda url: {"services": [[["pl", "xn--p1ai"], ["http://x/", "https://rdap.dns.pl/"]]]}
assert collector.rdap_base("pl") == "https://rdap.dns.pl" and collector.rdap_base("eu") is None  # https first
collector._rdap.clear()
collector._rdap.update({"pl": "https://rdap.dns.pl", "com": "https://rdap.verisign.com/com/v1"})  # IANA's list
collector.http_json = rdap(404)
assert real_age("shop.eu") is None  # no RDAP for this TLD: age unknown
collector.http_json = rdap(429)
real_whois, collector.whois_pl_age = collector.whois_pl_age, lambda domain: None
try:
    real_age("x.pl")
    raise AssertionError("a rate limit must defer the domain, not hide its age")
except OSError:
    pass
collector.whois_pl_age = lambda domain: 4000
assert real_age("x.pl") == 4000  # NASK's RDAP is limited, its WHOIS answers instead
collector._young["nowa.eu"] = 7
assert real_age("nowa.eu") == 7  # newly registered: no registry asked (.eu gives no date at all)
collector._gave_up.add("czeka.pl")
assert real_age("czeka.pl") is None  # waited out NASK's limit: judged with its age unknown, NASK not asked again
# on a server: NASK from the server's own address, never through home's relay too
saved_http, asked = collector.http_json, []
collector.HOME, collector.HOME_TOKEN = "http://home:8765", "t" * 32
collector.http_json = lambda url, body=None, timeout=30: asked.append(url) or {}
assert real_age("dom.pl") is None and asked == ["https://rdap.dns.pl/domain/dom.pl"]  # the registry itself, not rdap.org
web, sent = collector.urllib.request, []
urlopen, web.urlopen = web.urlopen, lambda request, timeout: sent.append(request.get_header("Authorization")) or io.BytesIO(b"{}")
real_http_json("http://home:8765/api/tags")
real_http_json("https://rdap.org/domain/a.com")
assert sent == ["Bearer " + "t" * 32, None]  # the token goes to home only
web.urlopen, collector.http_json, collector.HOME, collector.HOME_TOKEN = urlopen, saved_http, None, None
history = collector.open_db(":memory:")
assert collector.registered_history(history, {"a.pl": 7}) == {"a.pl": 7}
history.execute("UPDATE registered SET born = ?", ((date.today() - timedelta(days=40)).isoformat(),))
# a.pl on the lists again: the date from its first sighting stays
assert collector.registered_history(history, {"a.pl": 14, "b.pl": 14}) == {"a.pl": 40, "b.pl": 14}
history.execute("UPDATE registered SET born = '2020-01-01' WHERE domain = 'a.pl'")
assert collector.registered_history(history, {}) == {"b.pl": 14}  # over a year: established, the registry is asked


class Whois(io.BytesIO):  # socket stand-in: recv() reads the canned reply
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def sendall(self, data):
        pass

    def recv(self, size):
        return self.read(size)


real_connect = collector.socket.create_connection
collector.socket.create_connection = lambda address, timeout: Whois(
    b"option created:        2026.09.08 19:26:53\ncreated:               2000.04.04 13:00:00\n")
assert real_whois("smyk.pl") > 9000  # the domain's own date, not its option's
collector.socket.create_connection = lambda address, timeout: Whois(b"No information available about domain name\n")
assert real_whois("brak.pl") is None
collector.socket.create_connection = real_connect


class Page(io.BytesIO):  # urlopen() stand-in
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass


decoy = '<a href="/">首页</a><img src="//pic.compgoo.com/x.png">'.encode()
collector.urllib.request.urlopen = lambda request, timeout: Page(gzip.compress(decoy))
assert real_decoy("rrieceffa.com") == "首页"  # gzipped though nobody asked
collector.urllib.request.urlopen = lambda request, timeout: Page(b"<title>OSIWEI</title> uchwyty i galki")
assert real_decoy("osiwei.com") is None
collector.urllib.request.urlopen = lambda request, timeout: Page('page_name:"官网书城首页"'.encode())
assert real_decoy("moboreader.com") is None  # a page name in the scripts of a real reading app
collector.urllib.request.urlopen = lambda request, timeout: Page(gzip.compress(decoy)[:20])
assert real_decoy("cut.com") is None  # truncated gzip: no proof, no crash
collector.urllib.request.urlopen = lambda request, timeout: Page(b"<title>My WordPress</title>")
assert real_decoy("scontistock.com") == "<title>My WordPress</title>"


def unreachable(errno):
    def fail(request, timeout):
        raise urllib.error.URLError(socket.gaierror(errno, "dns"))
    return fail


collector.urllib.request.urlopen = unreachable(socket.EAI_NONAME)
collector.socket.getaddrinfo = resolver(socket.EAI_NONAME, collector.CANARY)
assert real_decoy("nbnpigcy.com") == "no website"
collector.socket.getaddrinfo = resolver(socket.EAI_NONAME)
try:
    real_decoy("levina.pl")
    raise AssertionError("offline, no address proves nothing")
except collector.Offline:
    pass
collector.socket.getaddrinfo = real_getaddrinfo
collector.urllib.request.urlopen = unreachable(socket.EAI_AGAIN)
assert real_decoy("buty.pl") is None  # resolver hiccup is no proof
bands = {"7": b"# Title: NRD\nnowa.pl\nnowa.com\nvinted-kyc.com\nipko-pl.com\ninpost.fun\nolxshop.com\nlinpost.com\n"
             b"allegro.pl\nuncle.lidl\nint-ikea.com\noe-blik.dk\nzus-ott.online\nblik-pay.com\nkasyna-blik.pl\n", "14-8": b"nowa.pl\nstarsza.eu\ndpd-doplata.top\n"}
collector.urllib.request.urlopen = lambda url, timeout: Page(bands.get(url.split("nrd")[-1][:-4], b""))
assert collector.newly_registered() == {"nowa.pl": 7, "allegro.pl": 7, "kasyna-blik.pl": 7, "starsza.eu": 14}  # gTLDs left to RDAP
# olxshop: "shop" is no lure; linpost: no brand; uncle.lidl: the brand is the TLD; dpd-doplata.top: seen last week;
# oe-blik.dk, zus-ott.online: plain words abroad, alone; blik-pay.com has a lure, kasyna-blik.pl is Polish
assert collector._branded == {"vinted-kyc.com": "vinted", "ipko-pl.com": "ipko", "inpost.fun": "inpost", "allegro.pl": "allegro",
                              "int-ikea.com": "ikea", "blik-pay.com": "blik", "kasyna-blik.pl": "blik"}
brands = collector.open_db(":memory:")
brands.execute("INSERT INTO verdicts (domain, verdict) VALUES ('vinted-kyc.com', 'block')")  # judged already
real_addresses, collector.addresses = collector.addresses, lambda d: [] if d == "inpost.fun" else ["5.5.5.5"]
real_lands, collector.lands_on = collector.lands_on, lambda d: "ikea.com" if d == "int-ikea.com" else d
assert collector.impersonators(brands, {"allegro.pl", "ikea.com"}) == 3  # ipko-pl, both blik; inpost.fun has no address yet: tried again tomorrow
assert not brands.execute("SELECT 1 FROM verdicts WHERE domain = 'int-ikea.com'").fetchone()  # IKEA's own: sends home
assert brands.execute("SELECT domain, verdict, reason FROM verdicts WHERE domain = 'ipko-pl.com'").fetchone() == (
    "ipko-pl.com", "block", "new domain named like ipko: on the list of new domains, no ad seen")
assert collector.impersonators(brands, {"allegro.pl", "ikea.com"}) == 0  # blocked once
collector.addresses, collector.lands_on = real_addresses, real_lands

pages = {"smyk.brand-eu.com": None, "brand-eu.com": "首页",
         "rejestracja.medica.com": None, "medica.com": "no website"}
collector.decoy = pages.get
assert collector.decoy_mark(smyk, "brand-eu.com") == "首页"  # the bare domain gives the platform away
medica = {"ad_creative_link_captions": ["rejestracja.medica.com"]}
assert collector.decoy_mark(medica, "medica.com") is None  # the advertised page works
collector.decoy = lambda host: None


def fake_judge(ad, domain, twin=None):  # NASK (.pl) is rate limited, the .com registry is fine
    if domain.endswith(".pl"):
        raise OSError("429 https://rdap.org/domain/" + domain)
    return ("pass", 0, f"twin {twin}") if twin else ("block", 0, "heuristics")


collector.judge = fake_judge
mining = collector.open_db(":memory:")
for i in range(6):  # "cudowny" in 6 blocked ads and 1 passed, "dostawa" everywhere
    for verdict, text in (("block", f"Cudowny krem nr {i} darmowa dostawa już"), ("pass", f"Sklep{i} darmowa dostawa już")):
        mining.execute("INSERT INTO verdicts (domain, verdict, ad) VALUES (?, ?, ?)",
                       (f"{verdict}{i}.pl", verdict, json.dumps({"ad_creative_bodies": [text]})))
    # a foreign version beside a Polish one: its words are no search term
    mining.execute("INSERT INTO verdicts (domain, verdict, ad) VALUES (?, 'block', ?)",
                   (f"en{i}.com", json.dumps({"ad_creative_bodies": ["Watch someone catch it", "Kup już"]})))
mining.execute("INSERT INTO verdicts (domain, verdict, ad) VALUES ('p.pl', 'pass', ?)",
               (json.dumps({"ad_creative_bodies": ["cudowny dzień u lekarza"]}),))
assert collector.mined_terms(mining) == ["cudowny"]  # 6/(1+1) = 3; "darmowa", "dostawa" are in passes too
for i in range(5):  # one story campaign: "czekałam" adds no ad "zniknęła" does not reach; "bitcoina" is another scam
    mining.execute("INSERT INTO verdicts (domain, verdict, ad) VALUES (?, 'block', ?)",
                   (f"story{i}.pl", json.dumps({"ad_creative_bodies": ["zniknęła, czekałam na nią"]})))
    mining.execute("INSERT INTO verdicts (domain, verdict, ad) VALUES (?, 'block', ?)",
                   (f"btc{i}.pl", json.dumps({"ad_creative_bodies": ["kup bitcoina już"]})))
mined = collector.mined_terms(mining)
assert "bitcoina" in mined and len({"zniknęła", "czekałam"} & set(mined)) == 1, mined

fetched = []


def fake_ads(token, query=None, pages=3, page_ids=None):
    fetched.append(page_ids or query)
    if page_ids:  # the blocked domain's FB page runs one more domain
        return [{"id": "4", "page_id": "p1", "ad_creative_link_captions": ["b.com"]},
                {"id": "5", "page_id": "p1", "ad_creative_link_captions": ["f.com"]}]
    return [{"id": "1", "page_id": "p1", "page_name": "Okazje", "ad_creative_link_captions": ["a.pl", "b.com", "c.pl"]},
            {"id": "2", "ad_creative_link_captions": ["d.com"], **long_ad},
            {"id": "3", "ad_creative_link_captions": ["e.com"], **long_ad}]


collector.fetch_ads = fake_ads
collector.addresses = lambda domain: []
published = []
collector.publish = lambda db: published.append(db.execute("SELECT count(*) FROM verdicts WHERE verdict = 'block'").fetchone()[0])
db = collector.open_db(":memory:")
real_llm_up, collector.llm_up = collector.llm_up, lambda db: True
collector.collect(db, "token", set(), ["inwestycja"])
assert published == [1, 2, 3]  # each block on the list at once, committed first
assert [d for (d,) in db.execute("SELECT domain FROM verdicts")] == ["b.com", "d.com", "e.com", "f.com"]  # .pl waits
assert fetched == ["inwestycja", ["p1"]]  # the page is chased once, also after f.com's block on it
assert db.execute("SELECT domain, verdict, by FROM history ORDER BY domain").fetchall()[:2] == [
    ("b.com", "block", "collector"), ("d.com", "block", "collector")]
assert collector.STATS['scamdns_judged_total{verdict="block"}'] == 3 and collector.STATS["scamdns_ads_total"] == 5
assert collector.STATS['scamdns_rdap_limited_total{tld="pl"}'] == 1  # c.pl then waits, no second try this cycle
assert db.execute("SELECT domain FROM waiting ORDER BY domain").fetchall() == [("a.pl",), ("c.pl",)]  # kept with the ad
young_db, collector._young["c.pl"] = collector.open_db(":memory:"), 3  # newly registered: age known without NASK
collector.judge = lambda ad, domain, twin=None: (("block", 0, "young") if domain in collector._young
                                                else fake_judge(ad, domain, twin))
collector.fetch_ads = lambda token, query=None, pages=3, page_ids=None: [] if page_ids else [
    {"id": "12", "ad_creative_link_captions": ["a.pl", "c.pl"]}]
collector.collect(young_db, "token", set(), ["nowe"])
assert young_db.execute("SELECT domain FROM verdicts").fetchall() == [("c.pl",)]  # judged although .pl hit 429
collector._young.pop("c.pl")
collector.judge, collector.fetch_ads = fake_judge, fake_ads
collector.fetch_ads = lambda token, query=None, pages=3, page_ids=None: [] if page_ids else [
    {"id": "6", "ad_creative_link_captions": ["brand.com"], "destinations": ["https://x.shop/p", "https://y.shop/"]}]
collector.collect(db, "token", {"y.shop"}, ["moda"])
judged = {d for (d,) in db.execute("SELECT domain FROM verdicts")}
assert {"brand.com", "x.shop"} <= judged and "y.shop" not in judged  # the hidden target too, unless allowed
assert json.loads(db.execute("SELECT ad FROM verdicts").fetchone()[0])["ad_creative_link_captions"][1] == "b.com"
assert db.execute("SELECT reason FROM verdicts WHERE domain = 'e.com'").fetchone() == ("twin d.com",)
collector.fetch_ads = lambda token, query=None, pages=3, page_ids=None: [] if page_ids else [
    {"id": "10", "ad_creative_link_captions": ["ua.com", "ua2.com"],
     "ad_creative_bodies": ["Buty do biegania, nowa kolekcja. " * 4]}]
collector.collect(db, "token", set(), ["sport"])  # ua.com blocked first: ua2.com of the same ad is judged on its own
pair = db.execute("SELECT reason FROM verdicts WHERE domain IN ('ua.com', 'ua2.com')").fetchall()
assert pair == [("heuristics",)] * 2
assert db.execute("SELECT count(*) FROM waiting").fetchone() == (2,)  # still limited: they keep waiting
db.execute("UPDATE waiting SET since = '2026-01-01T00:00:00+00:00' WHERE domain = 'a.pl'")
collector.judge = lambda ad, domain, twin=None: (("pass", 0, "age unknown") if domain in collector._gave_up
                                                else fake_judge(ad, domain, twin))
collector.collect(db, "token", {"brand.com", "x.shop"}, ["moda"])
assert db.execute("SELECT domain FROM waiting").fetchall() == [("c.pl",)]  # a.pl waited long enough, c.pl not yet
assert db.execute("SELECT reason FROM verdicts WHERE domain = 'a.pl'").fetchone() == ("age unknown",)
collector.judge = lambda ad, domain, twin=None: ("pass", 0, "heuristics")  # the limit is gone
collector.fetch_ads = lambda token, query=None, pages=3, page_ids=None: []
collector.collect(db, "token", set(), ["moda"])  # no new ads: the waiting ones are judged anyway
assert db.execute("SELECT count(*) FROM verdicts WHERE domain IN ('a.pl', 'c.pl')").fetchone() == (2,)
assert db.execute("SELECT count(*) FROM waiting").fetchone() == (0,)
collector.judge = lambda ad, domain, twin=None: None  # the LLM is down (home's computer off)
collector.fetch_ads = lambda token, query=None, pages=3, page_ids=None: [] if page_ids else [
    {"id": "8", "ad_creative_link_captions": ["llm.com"]}]
collector.collect(db, "token", set(), ["moda"])
assert db.execute("SELECT domain FROM waiting").fetchall() == [("llm.com",)]  # kept with its ad, not lost
opened = []
collector.judge = lambda ad, domain, twin=None: opened.append(domain)
collector.llm_up = lambda db: False
collector.fetch_ads = lambda token, query=None, pages=3, page_ids=None: []
collector.collect(db, "token", set(), ["moda"])
assert opened == []  # not opened again while the LLM is down
collector.fetch_ads = lambda token, query=None, pages=3, page_ids=None: [] if page_ids else [
    {"id": "9", "ad_creative_link_captions": ["llm.com"]}, {"id": "11", "ad_creative_link_captions": ["llm.com"]}]
collector.collect(db, "token", set(), ["moda"])
assert opened == []  # nor by its other ads (DokiShop: one cycle ran 4 h reopening waiting domains)


def refused(url, body=None, timeout=30):
    raise OSError("refused")


saved_http, collector.http_json = collector.http_json, refused
db.execute("UPDATE waiting SET since = '2026-01-01T00:00:00+00:00'")
assert not real_llm_up(db)
collector.http_json = lambda url, body=None, timeout=30: {"models": []}
assert real_llm_up(db) and db.execute("SELECT since FROM waiting").fetchone()[0] > "2026-11"  # its wait starts afresh
db.execute("UPDATE waiting SET since = '2026-01-01T00:00:00+00:00'")
assert real_llm_up(db) and db.execute("SELECT since FROM waiting").fetchone()[0] < "2026-11"  # only after a break
collector.http_json, collector.llm_up = saved_http, lambda db: True
db.execute("DELETE FROM waiting")

reports = collector.open_db(":memory:")  # sites sent on /zglos: judged like an ad's domain, the address as caption
assert collector.reported(reports, set()) == []  # no table before the panel's first start
reports.execute("CREATE TABLE suspects (domain TEXT, url TEXT, note TEXT, who TEXT, at TEXT)")
reports.executemany("INSERT INTO suspects VALUES (?, ?, 'zablokuj', NULL, ?)", [
    ("www.zly.shop", "http://www.zly.shop/promo?x=1", "2026-11-13T10:00:00+00:00"),
    ("lan.shop", "http://lan.shop", "2026-11-13T09:00:00+00:00"),  # resolves into the server's own network
    ("facebook.com", "http://facebook.com", "2026-11-13T09:00:00+00:00"),  # allowed
    ("znany.com", "http://znany.com", "2026-11-13T09:00:00+00:00"),  # judged already
    *[("drugi.shop", "http://drugi.shop", "2026-11-13T11:00:00+00:00")] * 2])  # sent twice: judged first
reports.execute("INSERT INTO verdicts (domain, verdict) VALUES ('znany.com', 'pass')")
collector.socket.getaddrinfo = lambda host, port: [(2, 1, 6, "", ("10.0.0.5" if host == "lan.shop" else "8.8.8.8", port))]
assert [d for d, _ in collector.reported(reports, {"facebook.com"})] == ["drugi.shop", "zly.shop"]
opened = []
collector.judge = lambda ad, domain, twin=None: opened.append((domain, collector.caption_url(ad, domain))) or ("block", 0, "x")
collector.fetch_ads = lambda token, query=None, pages=3, page_ids=None: []
collector.collect(reports, "token", {"facebook.com"}, ["moda"])
assert opened == [("drugi.shop", "https://drugi.shop/"), ("zly.shop", "http://www.zly.shop/promo?x=1")]  # the page sent
assert reports.execute("SELECT by FROM history WHERE domain = 'zly.shop'").fetchone() == ("collector",)
assert collector.reported(reports, {"facebook.com"}) == []  # each judged once; lan.shop never opened
collector.socket.getaddrinfo = real_getaddrinfo
assert not collector.public("localhost") and not collector.public("nie-ma-takiej.invalid")
collector.judge = lambda ad, domain, twin=None: ("pass", 0, "heuristics")

servers = collector.open_db(":memory:")  # a scam network's server: two blocked domains, no passed one
for d in ("s1.com", "s2.com"):
    servers.execute("INSERT INTO verdicts (domain, verdict, ad) VALUES (?, 'block', ?)",
                    (d, json.dumps({"ips": {d: ["18.139.214.139"]}})))
ips = {"s3.com": ["18.139.214.139"], "cf.com": ["104.16.1.1"]}
collector.addresses = lambda domain: ips.get(domain, [])
collector.fetch_ads = lambda token, query=None, pages=3, page_ids=None: [] if page_ids else [
    {"id": "7", "ad_creative_link_captions": ["s3.com", "cf.com"]}]
collector.collect(servers, "token", set(), ["x"])
assert servers.execute("SELECT verdict, reason FROM verdicts WHERE domain = 's3.com'").fetchone() == (
    "review", "same server as blocked s1.com, s2.com")
assert servers.execute("SELECT verdict FROM verdicts WHERE domain = 'cf.com'").fetchone() == ("pass",)
saved = json.loads(servers.execute("SELECT ad FROM verdicts WHERE domain = 's3.com'").fetchone()[0])
assert saved["ips"]["s3.com"] == ["18.139.214.139"]  # kept with the ad, for the next cycle's map
collector._servers["104.16.1.1"] = {"block": ["a.com", "b.com"], "pass": 0}
assert collector.same_server(["104.16.1.1"], "x.com") == []  # Cloudflare: thousands of sites on one address
collector._servers["5.5.5.5"] = {"block": ["a.com", "b.com"], "pass": 1}
assert collector.same_server(["5.5.5.5"], "x.com") == []  # a passed domain there: a shared host
collector._servers["9.9.9.9"] = {"block": ["a.com", "b.com", "c.com"], "pass": 0}
assert collector.traced(("pass", 0, "llm: ok"), "x.com", ["9.9.9.9"], [], 10)[::2] == ("block", "same server as blocked a.com, b.com, c.com")
assert collector.traced(("pass", 0, "llm: ok"), "x.com", ["9.9.9.9"], [], 4000)[0] == "review"  # an old firm: a human looks
collector._numbers.update({"9721377277": {"block": ["medyknacito.pl"], "pass": 0}, "7010357724": {"block": ["t.pl"], "pass": 2}})
assert collector.traced(("pass", 0, "llm: ok"), "x.pl", [], [], 4000, "9721377277")[::2] == ("review", "same company number as blocked medyknacito.pl")
assert collector.traced(("pass", 0, "llm: ok"), "x.pl", [], [], 4000, "7010357724")[0] == "pass"  # one firm, honest shops too
assert collector.traced(("pass", 0, "llm: ok"), "medyknacito.pl", [], [], 4000, "9721377277")[0] == "pass"  # itself

page = """<script>fbq('init', '1234567890123456');</script><noscript><img src="https://www.facebook.com/tr?ev=PageView&amp;id=987654321098765"></noscript>
<script src="https://www.googletagmanager.com/gtag/js?id=G-AB12CD34EF"></script><script>gtm('GTM-K9X2LMP'); ttq.load('C9ABCDEFGHIJ0KLMNOPQ');</script>
{\\"pixel_id\\":\\"555555555555555\\"} G-SHOCKWATCH UA-12345678-1 AW-123456789"""
assert collector.trackers(page) == ["AW-123456789", "G-AB12CD34EF", "GTM-K9X2LMP", "UA-12345678-1", "fb:1234567890123456",
                                    "fb:555555555555555", "fb:987654321098765", "tt:C9ABCDEFGHIJ0KLMNOPQ"]  # no digit: a brand
assert collector.trackers("https://relivital.com/?flow=59225&pxl=990573317278835&traff=facebook") == ["fb:990573317278835"]
owners = collector.open_db(":memory:")  # one pixel on a blocked shop: the next shop with it goes to a human
owners.execute("INSERT INTO verdicts (domain, verdict, ad) VALUES ('t1.com', 'block', ?)",
               (json.dumps({"trackers": {"t1.com": ["fb:111111111111"]}}),))
owners.execute("INSERT INTO verdicts (domain, verdict, ad) VALUES ('t2.com', 'pass', ?)",
               (json.dumps({"trackers": {"t2.com": ["G-SHARED0001"]}}),))
owners.execute("INSERT INTO verdicts (domain, verdict, ad) VALUES ('t0.com', 'block', ?)",
               (json.dumps({"trackers": {"t0.com": ["G-SHARED0001"]}}),))
tracked = {"t3.com": ["fb:111111111111"], "t4.com": ["G-SHARED0001"]}


def tracked_judge(ad, domain, twin=None):
    ad.setdefault("trackers", {})[domain] = tracked[domain]
    return "pass", 0, "heuristics"


collector.judge = tracked_judge
collector.fetch_ads = lambda token, query=None, pages=3, page_ids=None: [] if page_ids else [
    {"id": "9", "ad_creative_link_captions": ["t3.com", "t4.com"]}]
collector.collect(owners, "token", set(), ["x"])
assert dict(owners.execute("SELECT domain, reason FROM verdicts WHERE domain IN ('t3.com', 't4.com')")) == {
    "t3.com": "same tracking id as blocked t1.com", "t4.com": "heuristics"}  # t4: a passed shop shares that id
collector.judge = lambda ad, domain, twin=None: ("pass", 0, "heuristics")
abroad = collector.open_db(":memory:")
collector.fetch_ads = lambda token, query=None, pages=3, page_ids=None: [] if page_ids else [
    {"id": "8", "ad_creative_link_captions": ["essanova-pl.co", "sklep-pl.pl", "hover-polska.com"]}]
collector.collect(abroad, "token", set(), ["x"])
assert dict(abroad.execute("SELECT domain, verdict FROM verdicts")) == {
    "essanova-pl.co": "review", "sklep-pl.pl": "pass", "hover-polska.com": "review"}
with tempfile.TemporaryDirectory() as tmp:  # the base left in lists/: no empty one beside it on the volume
    real_lists, real_verdicts = collector.LISTS, collector.VERDICTS
    collector.LISTS, collector.VERDICTS = Path(tmp), Path(tmp) / "volume" / "verdicts.db"
    (collector.LISTS / "verdicts.db").write_bytes(b"")
    try:
        collector.open_db(collector.VERDICTS)
        raise AssertionError("opened an empty base")
    except SystemExit:
        pass
    collector.LISTS, collector.VERDICTS = real_lists, real_verdicts
aged = collector.open_db(":memory:")  # verdicts that age, judged again with a new walk
for domain, verdict, reason, by, days in (
        ("back.com", "block", "dead page: HTTP 404", None, 2), ("wall.com", "review", "page hidden behind a bot check", None, 2),
        ("old.com", "pass", "llm: fine", None, 8), ("new.com", "pass", "llm: fine", None, 3),
        ("mine.com", "block", "dead page: HTTP 404", "human", 2), ("fake.com", "block", "decoy: no website", None, 2),
        ("dead.com", "block", "dead page: HTTP 404", None, 2),
        ("forbid.com", "review", "page refuses the server (403 Forbidden), a human looks", None, 2)):
    at = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    aged.execute("INSERT INTO verdicts (domain, verdict, reason, seen_at, ad, decided_by) VALUES (?, ?, ?, ?, '{}', ?)",
                 (domain, verdict, reason, at, by))
    aged.execute("INSERT INTO history (domain, verdict, reason, by, at) VALUES (?, ?, ?, 'collector', ?)", (domain, verdict, reason, at))
again = {"back.com": ("pass", 0, "llm: a real shop"), "wall.com": ("review", 0, "page hidden behind a bot check"),
         "old.com": ("block", 9, "NIP 1 belongs to X, struck off in CEIDG"),
         "dead.com": ("review", 0, "dead page: HTTP 404 on https://dead.com/"),  # an old domain's dead page
         "forbid.com": ("review", 0, "page refuses the server (403 Forbidden), a human looks")}  # a day later: blocked
aged.execute("UPDATE verdicts SET ad = '{\"age_days\": {\"old.com\": 400}}' WHERE domain = 'old.com'")
ages = {}
collector.judge = lambda ad, domain, twin=None: (ages.update({domain: collector._known.get(domain)}), again[domain])[1]
real_no_age, collector.NO_AGE = collector.NO_AGE, ("", "")  # no window: the dates above are relative to today
real_no_browser, collector.NO_BROWSER = collector.NO_BROWSER, ("", "")
assert collector.look_again(aged, batch=6) == 3
assert dict(aged.execute("SELECT domain, verdict FROM verdicts")) == {
    "back.com": "pass", "wall.com": "review", "old.com": "block", "new.com": "pass", "mine.com": "block", "fake.com": "block",
    "dead.com": "block", "forbid.com": "block"}
assert ages["old.com"] == 408 and ages["back.com"] is None and not collector._known  # 400 days 8 days ago, no registry
assert aged.execute("SELECT count(*) FROM history WHERE domain = 'wall.com'").fetchone() == (2,)  # its day starts again
assert collector.look_again(aged) == 0  # each once a day (a pass once a week)
real_aging, collector.AGING = collector.AGING, (("review", "no company%", 7, datetime.now(timezone.utc).isoformat()),)
aged.execute("UPDATE verdicts SET verdict = 'review', reason = 'no company named' WHERE domain = 'new.com'")
again["new.com"] = ("pass", 0, "company named on the page")
assert collector.look_again(aged) == 1  # 3 days old, but judged before the walk it waited for
collector.AGING = real_aging
# a pass judged with its age unknown (rdap.org refused the server): judged again first, once
aged.execute("UPDATE verdicts SET verdict = 'pass', ad = '{\"age_days\": {\"fake.com\": null}}', decided_by = NULL "
             "WHERE domain IN ('fake.com', 'mine.com')")
aged.execute("UPDATE verdicts SET ad = 'nie json' WHERE domain = 'mine.com'")
aged.execute("INSERT INTO verdicts (domain, verdict, ad) VALUES ('stary.pl', 'pass', '{}')")
aged.execute("INSERT INTO history (domain, verdict, reason, by, at) VALUES ('stary.pl', 'pass', '', 'collector', '2026-11-06T12:00:00+00:00')")
for domain in ("sklep.eu", "strona.netlify.app"):  # no registry gives their age: judging them again changes nothing
    aged.execute("INSERT INTO verdicts (domain, verdict, ad) VALUES (?, 'pass', '{}')", (domain,))
    aged.execute("INSERT INTO history (domain, verdict, reason, by, at) VALUES (?, 'pass', '', 'collector', '2026-11-06T11:00:00+00:00')", (domain,))
collector._rdap["app"] = "https://pubapi.registry.google/rdap"
aged.execute("UPDATE history SET at = '2026-11-06T12:00:00+00:00' WHERE domain IN ('fake.com', 'mine.com', 'old.com')")
collector.NO_AGE = real_no_age
again["fake.com"] = ("block", 9, "llm: 5 days old")  # mine.com, its ad broken, is skipped
real_aging, collector.AGING = collector.AGING, ()  # the window alone: weekly passes caught a week later
assert collector.look_again(aged, batch=1) == 1  # old.com had its age, stary.pl is a .pl (NASK answered home then)
assert dict(aged.execute("SELECT domain, verdict FROM verdicts WHERE domain IN ('fake.com', 'mine.com')")) == {
    "fake.com": "block", "mine.com": "pass"}
assert collector.look_again(aged) == 0  # once: judged now, after the window
collector.AGING = real_aging
# reviews judged while the browser could not start: judged again at once, on top of AGING, each once
broken = collector.open_db(":memory:")
hour = lambda hours: (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
collector.NO_BROWSER, collector.NO_BROWSER_BATCH = (hour(3), hour(1)), 2
for domain, verdict, at in (("nofb.com", "review", 2), ("nofb2.com", "review", 2.5), ("nofb3.com", "review", 1.5),
                            ("blocked.com", "block", 2), ("later.com", "review", 0.5), ("nasku.pl", "review", 2.9)):
    broken.execute("INSERT INTO verdicts (domain, verdict, reason, ad) VALUES (?, ?, 'page did not load, the model', '{}')",
                   (domain, verdict))
    broken.execute("INSERT INTO history (domain, verdict, reason, by, at) VALUES (?, ?, '', 'collector', ?)", (domain, verdict, hour(at)))
judged = []
collector.judge = lambda ad, domain, twin=None: judged.append(domain) or ("pass", 0, "llm: a real shop")
assert collector.look_again(broken) == 2 and judged == ["nofb2.com", "nofb.com"]  # the oldest first, 2 a cycle
assert collector.look_again(broken) == 2 and judged[2:] == ["nofb3.com", "nasku.pl"]  # a .pl with no age: last
assert collector.look_again(broken) == 0 and len(judged) == 4  # each once; a block and a later review stay
# NASK 429 all day: a .pl judged before with its age unknown goes so again, one never aged waits and is logged
for domain, ad in (("ukryty.pl", '{"age_days": {"ukryty.pl": null}}'), ("bezwieku.pl", "{}")):
    broken.execute("INSERT INTO verdicts (domain, verdict, reason, ad) VALUES (?, 'review', 'page did not load', ?)",
                   (domain, ad))
    broken.execute("INSERT INTO history (domain, verdict, reason, by, at) VALUES (?, 'review', '', 'collector', ?)", (domain, hour(2)))
def limited(ad, domain, twin=None):
    if domain not in collector._gave_up:
        raise OSError("429 https://rdap.dns.pl")
    return judged.append(domain) or ("pass", 0, "llm: a real shop")
collector.judge = limited
out = io.StringIO()
with contextlib.redirect_stdout(out):
    assert collector.look_again(broken) == 1 and judged[4:] == ["ukryty.pl"] and not collector._gave_up
assert "waiting (registry limit or LLM down): bezwieku.pl" in out.getvalue()
# the cycle's spare time: rounds until `until`, one waiting is not walked again and takes no other's place
spare, judged = collector.open_db(":memory:"), []
for i in range(5):
    spare.execute("INSERT INTO verdicts (domain, verdict, reason, ad) VALUES (?, 'review', 'page did not load', '{}')",
                  (f"r{i}.com",))
    spare.execute("INSERT INTO history (domain, verdict, reason, by, at) VALUES (?, 'review', '', 'collector', ?)", (f"r{i}.com", hour(2.5 - i / 10)))
collector.judge = lambda ad, domain, twin=None: judged.append(domain) or (None if domain == "r0.com" else
                                                                          ("pass", 0, "llm: a real shop"))
with contextlib.redirect_stdout(io.StringIO()):
    assert collector.look_again(spare) == 1 and judged == ["r0.com", "r1.com"]  # no spare time: one round
    assert collector.look_again(spare, until=time.monotonic() + 60) == 3 and judged[2:] == ["r0.com", "r2.com", "r3.com",
                                                                                            "r4.com"]
# the process judging again: rounds for a cycle while the LLM answers, nothing walked while it is down
real_llm_up, real_look_again, calls = collector.llm_up, collector.look_again, []
collector.look_again = lambda db, until=0.0: calls.append(until - time.monotonic()) or 1
for up in (False, True):
    collector.llm_up = lambda db: up
    with contextlib.redirect_stdout(io.StringIO()):
        collector.again_cycle(spare, idle=0)
assert len(calls) == 1 and collector.CYCLE_SECONDS - 5 < calls[0] <= collector.CYCLE_SECONDS
collector.llm_up, collector.look_again = real_llm_up, real_look_again
assert not collector.APART and not collector.AGAIN  # unset: one process does both, as at home before
collector.NO_BROWSER = real_no_browser
late = collector.open_db(":memory:")  # judged again over 2 days after its turn: the alarm's count
for domain, verdict, reason, days, by in (("a.com", "pass", "llm: ok", 10, None), ("b.com", "pass", "llm: ok", 8, None),
                                          ("c.com", "review", "page did not load", 4, None), ("d.com", "pass", "x", 30, "human")):
    late.execute("INSERT INTO verdicts (domain, verdict, reason, ad, decided_by) VALUES (?, ?, ?, '{}', ?)",
                 (domain, verdict, reason, by))
    late.execute("INSERT INTO history (domain, verdict, reason, by, at) VALUES (?, ?, '', 'collector', ?)", (domain, verdict, hour(24 * days)))
assert collector.overdue(late) == (2, late.execute("SELECT at FROM history WHERE domain = 'a.com'").fetchone()[0])
# a.com 3 days late, c.com 3; b.com 1 day late, d.com a human's
sale = collector.open_db(":memory:")  # a domain for sale: forgotten, a block stays blocked
for domain, verdict, reason in (("mibu.pl", "review", "page hidden behind a bot check"), ("sold.com", "block", "dead page")):
    sale.execute("INSERT INTO verdicts (domain, verdict, reason, ad) VALUES (?, ?, ?, '{}')", (domain, verdict, reason))
    sale.execute("INSERT INTO history (domain, verdict, reason, by, at) VALUES (?, ?, ?, 'collector', ?)", (domain, verdict, reason, hour(30)))
collector.judge = lambda ad, domain, twin=None: judged.append(domain) or ("forget", 0, "domain for sale: x")
assert collector.look_again(sale) == 1
assert dict(sale.execute("SELECT domain, verdict FROM verdicts")) == {"sold.com": "block"}
assert sale.execute("SELECT verdict, \"by\" FROM history WHERE domain = 'mibu.pl' ORDER BY at DESC").fetchone() == (
    "forgotten", "collector")
judged[:] = []
collector.fetch_ads = lambda token, query=None, pages=3, page_ids=None: [] if page_ids else [
    {"id": "7", "ad_creative_link_captions": ["mibu.pl", "kupdomene.pl"]}]
collector.collect(sale, "token", set(), ["x"])  # mibu.pl forgotten an hour ago: not walked again for a week
assert judged == ["kupdomene.pl"] and sale.execute("SELECT count(*) FROM verdicts").fetchone() == (1,)
assert sale.execute("SELECT count(*) FROM history WHERE domain = 'kupdomene.pl' AND verdict = 'forgotten'").fetchone() == (1,)
collector.judge = lambda ad, domain, twin=None: None  # the model did not answer: nothing to save
collector.fetch_ads = lambda token, query=None, pages=3, page_ids=None: [] if page_ids else [
    {"id": "9", "ad_creative_link_captions": ["cisza.com"]}]
collector.collect(abroad, "token", set(), ["x"])
assert not abroad.in_transaction  # no write left open: the panel could not save a decision for 15 minutes
collector.addresses = lambda domain: []

with tempfile.TemporaryDirectory() as tmp:  # a base from before the `ad` column gets it added
    path = f"{tmp}/verdicts.db"
    with sqlite3.connect(path) as old:
        old.execute("CREATE TABLE verdicts (domain TEXT PRIMARY KEY, verdict, score, reason, ad_id, page, seen_at)")
        old.execute("INSERT INTO verdicts VALUES ('a.pl', 'block', 5, 'llm: x', '1', 'P', '2026-10-01T00:00:00+00:00')")
    old.close()
    migrated = collector.open_db(path)
    columns = {column for _, column, *_ in migrated.execute("PRAGMA table_info(verdicts)")}
    assert {"ad", "decided_by", "decided_at"} <= columns
    migrated.close()
    migrated = collector.open_db(path)  # the second start adds no history twice
    assert migrated.execute("SELECT * FROM history").fetchall() == [
        ("a.pl", "block", "llm: x", "collector", "2026-10-01T00:00:00+00:00", None)]  # the history starts with today's state
    migrated.close()

graph = "400 https://graph.facebook.com/v26.0/ads_archive: b'{{\"error\":{{\"message\":\"{}\",\"code\":{}}}}}'"
message, wait = collector.explain(OSError(graph.format("Error validating access token: Session has expired", 190)))
assert message.startswith("META TOKEN EXPIRED") and wait == collector.CYCLE_SECONDS
message, wait = collector.explain(OSError(graph.format("(#4) Application request limit reached", 4)))
assert message.startswith("META RATE LIMIT (code 4)") and wait == 3600
assert collector.explain(OSError("timed out")) == ("cycle failed: timed out", collector.CYCLE_SECONDS)
# Meta down (500) or limiting: old verdicts are judged again anyway; no network: nothing is
assert collector.meta_refused(OSError(graph.format("An unexpected error has occurred", 2)))
assert not collector.meta_refused(OSError("timed out")) and not collector.meta_refused(collector.Offline("no internet"))
assert not collector.meta_refused(OSError("500 https://sklep.com/: b''"))

collector.visit = lambda url, expect=None, shot=None, light=False: None
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Buty. " * 60 + contact, [])
collector.domain_age_days = lambda domain: 10
hidden = {"ad_creative_link_captions": ["x.pro"], "ad_creative_bodies": ["zr\u200b\u200bob to " * 30]}
assert judge(hidden, "x.pro")[::2] == ("block", "60 invisible characters hidden in the ad's words")  # smallesttell.pro
assert judge({"ad_creative_bodies": ["Krem\u200b na stopy"]}, "x.pro")[2] != "1 invisible characters hidden in the ad's words"
real_nip_problem, collector.nip_problem = collector.nip_problem, lambda text, domain="": None
collector.ask_llm = lambda ad, domain, age, site=None: {"scam": True, "reason": "fake shop"}
collector.domain_age_days = lambda domain: None
assert judge(dict(shop), "buty.eu")[::2] == ("review", "llm: fake shop")  # twistcar.eu: date hidden, company registered
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Buty. " * 60 + "sklep@buty.eu", [])
assert judge(dict(shop), "buty.eu")[0] == "review"  # nobody named, the date hidden: a human looks
collector.nip_problem = real_nip_problem
assert collector.contradicts("Falszowe informacje o wypłacie") and collector.contradicts("Gwarantowany zysk")
collector.domain_age_days = lambda domain: 4000  # an aged domain, bought
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Opaska. " * 60 + "kontakt@vigoroa.com", [])
knees = {"ad_creative_link_captions": ["vigoroa.com"], "ad_creative_bodies": ["Ból kolana przy każdym kroku? Ulga w 7 dni"]}
assert judge(knees, "vigoroa.com")[::2] == ("block", "health promise and no company named on the site or its legal pages (only: email)")
assert judge(dict(shop), "buty.pl")[0] == "review"  # an old shoe shop naming nobody goes to a human
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Krem. " * 60 + "Ondyna SAS, TVA FR79108703331", [])
real_vat_problem, collector.vat_problem = collector.vat_problem, lambda text, domain="": (
    False, "VAT FR79108703331E is not valid in VIES")
assert judge(knees, "ondyna-pl.com")[::2] == ("block", "health promise and VAT FR79108703331E is not valid in VIES")
collector.vat_problem = real_vat_problem
assert all(collector.HEALTH.search(t) for t in ("Problemy z prostatą", "żylaki znikną", "cukrzyca typu 2", "sztuczne zęby"))
assert not any(collector.HEALTH.search(t) for t in ("Stawki ekip rosną", "Słuchawki bluetooth", "Zastaw samochód",
                                                    "Kolekcja jesienna", "Wzrost sprzedaży", "spojrzała błędnym wzrokiem",
                                                    "kapcie, żadnego bólu stóp", "myła zęby i odchudzała się",
                                                    "jej stawy wyglądały na zniekształcone", "uderzyła kolanem w krocze"))
assert all(collector.HEALTH.search(t) for t in ("zapomnij o uporczywym bólu stawów", "leczenie bólu kolan w domu",
                                                "ból kolana lub niestabilność stawu", "zmniejsz ból stawów i pleców",
                                                "krem na stawy", "sztywność stawów rano", "problemy ze stawami"))
collector.domain_age_days = lambda domain: 30
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Krem. " * 60, ['legal page did not load "Regulamin" -> https://x.com/r'])
assert judge(dict(shop), "buty.pl")[::2] == (
    "block", '30-day-old domain, no company named; not read: legal page did not load "Regulamin" -> https://x.com/r')
collector.domain_age_days = lambda domain: 400
assert judge(dict(shop), "buty.pl")[0] == "review"  # an older shop with an unread page: a human looks
collector.domain_age_days = lambda domain: 645
watch = {"ad_creative_bodies": ["Smartwatch: monitoruj poziom cukru we krwi bez nakłucia"]}
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Zegarek. " * 60 + "help@hadahe.monster", [])
assert judge(dict(watch), "hadahe.monster")[0] == "block"  # no needle-free glucose watch exists
libre = {"ad_creative_bodies": ["FreeStyle Libre 2: sprawdzaj poziom cukru we krwi telefonem"]}
collector.walk = lambda url, shot=None: ("<p>Abbott</p>", "Libre. " * 60 + "Abbott Laboratories Poland sp. z o.o., KRS 0000123456", [])
collector.ask_llm = lambda ad, domain, age, site=None: {"scam": False, "reason": "medical device by a known maker"}
real_nip_problem, collector.nip_problem = collector.nip_problem, lambda text, domain="": None
assert judge(dict(libre), "freestylelibre.pl")[0] == "pass"  # a named maker of a real device is never the health rule
real_libre_walk = collector.walk  # a domain for sale is forgotten, a parked one too, not blocked as a decoy
collector.walk = lambda url, shot=None: ('<div class="parking-lander">', "Oferta sprzedaży domeny: mibu.pl Jak kupić tę "
                                         "domenę? Aftermarket.pl Limited CY10245422H", [])
assert judge({}, "mibu.pl")[::2] == ("forget", "domain for sale: Oferta sprzedaży domeny")
for text in ("Ta domena jest na sprzedaż", "Play dot Game is a premium domain name for sale", "www.hugedomains.com"):
    assert collector.FOR_SALE.search(text), text
for text in ("This domain is not currently for sale", "Zapytaj o cenę", "170.000 domen na sprzedaż", "Złóż ofertę"):
    assert not collector.FOR_SALE.search(text), text
assert not collector.THIRD_PARTY_IDS.search("NIP 1234563218") and collector.THIRD_PARTY_IDS.search("VAT CY10245422H")
collector.walk = real_libre_walk
learned = collector.open_db(":memory:")  # the word model: a pass that reads like what humans blocked goes to a human
for i in range(60):
    learned.execute("INSERT INTO verdicts (domain, verdict, ad, decided_by) VALUES (?, ?, ?, 'human')",
                    (f"z{i}.pl", "block" if i % 2 else "doubtful", json.dumps({"ad_creative_bodies": [f"Libre 2 płatność przy odbiorze {i}"]})))
    learned.execute("INSERT INTO verdicts (domain, verdict, ad, decided_by) VALUES (?, 'pass', ?, 'human')",
                    (f"d{i}.pl", json.dumps({"ad_creative_bodies": [f"Meble na wymiar, ceny netto, umów pomiar {i}"]})))
assert collector.train_words(learned) == 120 and collector.words_score(dict(libre), "freestylelibre.pl") > .7
assert judge(dict(libre), "freestylelibre.pl")[2].startswith("words like blocked ads (")
real_words, collector.words_score = collector.words_score, lambda ad, domain: 0.95
card = dict(libre)
assert judge(card, "freestylelibre.pl")[::2] == (  # a template seen in blocks: the words decide, the model passed it
    "block", "words like blocked ads (95%), llm passed it: medical device by a known maker")
assert card["model"] == collector.MODEL  # the verdict carries the model that read it
assert judge(card, "freestylelibre.pl", twin="z1.pl")[0] == "block" and "model" not in card  # a clone, no model read it
assert judge({}, "freestylelibre.pl")[0] == "pass"  # no ad to read the words of (named like a brand)
collector.words_score = real_words
import numpy as np  # ModernBERT's vectors: bad cards point one way, good ones the other
vector = lambda x: base64.b64encode(np.full(768, x, dtype=np.float16).tobytes()).decode()
for domain, ad in learned.execute("SELECT domain, ad FROM verdicts").fetchall():
    learned.execute("UPDATE verdicts SET ad = ? WHERE domain = ?",
                    (json.dumps(json.loads(ad) | {"bert": {domain: vector(-1 if domain[0] == "d" else 1)}}), domain))
assert collector.train_bert(learned) == 120
measured = collector.measure(learned)  # judged by models that never saw them: these two kinds part cleanly
assert [(name, cards, right, caught, wrong) for _, name, cards, right, caught, wrong in measured] == [
    ("words", 120, 1.0, 1.0, 0.0), ("bert", 120, 1.0, 1.0, 0.0), ("both", 120, 1.0, 1.0, 0.0)]
assert learned.execute("SELECT count(*) FROM trainings").fetchone()[0] == 3
blind_bert = collector._bert_words
collector.words_score = lambda ad, domain: 0.75  # words alone would send it to a human
assert judge(dict(libre, bert={"freestylelibre.pl": vector(-1)}), "freestylelibre.pl")[0] == "pass"  # BERT: good
assert judge(dict(libre, bert={"freestylelibre.pl": vector(1)}), "freestylelibre.pl")[::2] == (
    "review", "words like blocked ads (87%), llm passed it: medical device by a known maker")
assert judge(dict(libre), "freestylelibre.pl")[0] == "review"  # no vector on the card: words alone at 0.7
collector.words_score, collector._bert_words = real_words, None
real_no_browser, collector.NO_BROWSER = collector.NO_BROWSER, (hour(3), hour(1))  # ruled from the ad alone: not learned
for domain in ("z0.pl", "d0.pl", "d1.pl"):
    learned.execute("INSERT INTO history (domain, verdict, reason, by, at) VALUES (?, 'review', 'page did not load', 'collector qwen', ?)", (domain, hour(2)))
learned.execute("UPDATE verdicts SET ad = json_set(ad, '$.landing', json_object('d1.pl', 'Meble')) WHERE domain = 'd1.pl'")
assert collector.train_words(learned) == 118 and collector.train_bert(learned) == 118  # d1.pl had its page
collector.NO_BROWSER, collector._bert_words = real_no_browser, blind_bert
queue = collector.open_db(":memory:")  # off the queue: nothing to learn from, or queued before the ad was kept
for domain, ad, seen in (("old.pl", {"ad_creative_bodies": ["Meble"]}, "2026-10-25T10:00:00+00:00"),
                         ("bare.pl", {"age_days": {"bare.pl": 3}}, hour(1)),
                         ("page.pl", {"landing": {"page.pl": "Sklep"}}, hour(1)),
                         ("text.pl", {"ad_creative_link_titles": ["Buty"]}, hour(1))):
    queue.execute("INSERT INTO verdicts (domain, verdict, ad, seen_at) VALUES (?, 'review', ?, ?)", (domain, json.dumps(ad), seen))
queue.execute("INSERT INTO verdicts (domain, verdict, ad, seen_at, decided_by) VALUES ('kept.pl', 'review', '{}', ?, 'human')", (hour(1),))
assert collector.skip_unlearnable(queue) == 2 and collector.skip_unlearnable(queue) == 0
assert [d for (d,) in queue.execute("SELECT domain FROM verdicts WHERE verdict = 'skipped' ORDER BY domain")] == ["bare.pl", "old.pl"]
assert queue.execute("SELECT count(*) FROM history WHERE verdict = 'skipped'").fetchone()[0] == 2
assert queue.execute("SELECT count(*) FROM verdicts").fetchone()[0] == 5  # the stats still count them
real_bert, collector.bert_vector = collector.bert_vector, lambda ad, domain: None
assert collector.fill_vectors(queue) == 0  # no torch: nothing made, nothing written
collector.bert_vector = lambda ad, domain: "v-" + domain
queue.execute("UPDATE verdicts SET decided_by = 'human' WHERE domain = 'text.pl'")
assert collector.fill_vectors(queue, batch=1) == 1  # human decisions first
assert json.loads(queue.execute("SELECT ad FROM verdicts WHERE domain = 'text.pl'").fetchone()[0])["bert"] == {"text.pl": "v-text.pl"}
assert collector.fill_vectors(queue) == 2 and collector.fill_vectors(queue) == 0  # old.pl, page.pl; bare.pl, kept.pl: nothing
collector.bert_vector = real_bert
learned.execute("DELETE FROM verdicts WHERE verdict = 'pass'")
assert collector.train_words(learned) == 0  # nothing good to tell the bad from: the model it had stays
collector._words = None
collector.walk = lambda url, shot=None: ("<p>Quiz</p>", "Quiz prostata. " * 30, [])
assert judge({"ad_creative_bodies": ["Ból prostaty minie"]}, "pp.lol")[::2] == (
    "block", "health promise in a quiz (Quiz) and no company named")
collector.domain_age_days = lambda domain: 2000
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Szampon. " * 60 + "Vita sp. z o.o., NIP 5263131989", [])
collector.nip_problem = lambda text, domain="": (True, "NIP 5263131989 is in no Polish business register (GUS REGON)")
collector._fake_numbers.clear()
assert judge(dict(shop), "harmonyvita.pl")[0] == "review"  # an old shop with a fake NIP: a human looks
assert judge(dict(shop), "vitapolska.pl")[::2] == ("block", "NIP 5263131989 is in no Polish business register (GUS REGON), "
                                                   "the same number as on harmonyvita.pl")
collector.nip_problem = real_nip_problem
hosted = "Sklep sp. z o.o., NIP 1234563218. Hosting: cyber_folks S.A., ul. Franklina Roosevelta 22, 60-829 Poznań"
assert collector.company(hosted) == ["legal form", "NIP"]  # the host's address is not the shop's
assert {"inpost.pl", "przelewy24.pl", "payu.pl", "poczta-polska.pl", "cyberfolks.pl", "dpd.com.pl", "dhl.com"} <= collector.TRUSTED
shortened = {"ad_creative_link_captions": ["poradnia.iwrd.pl"], "destinations": ["https://tiny.pl/twjfzsc3"]}
assert collector.hidden_domains(shortened) == [] and collector.lying_caption(shortened) == []  # iwrd.pl
assert judge({}, "tiny.pl")[0] == "pass" and collector.unshortened("https://buty.pl/x") == "https://buty.pl/x"
assert "NIP 1234563218" in collector.THIRD_PARTY.sub("", "Sklep hestiahome.pl, NIP 1234563218")  # a shop named *home.pl
assert judge(dict(shop), "calendesk.net")[0] == "review"  # a platform is never blocked whole
real_gus = collector.gus_subject
collector.gus_subject = lambda nip: {"name": "CYBER_FOLKS SPÓŁKA AKCYJNA", "ended": "2023-09-11"}
assert collector.nip_problem("Hostingodawca ... " + "x" * 300 + " NIP 7822622168") is None  # the host, not the shop
collector.gus_subject = real_gus
payu_far = "Płatności obsługuje PayU S.A." + " regulamin" * 40 + " KRS 0000274399, NIP 779-23-08-495"
assert not collector.identified(collector.company(payu_far))  # PayU's numbers are not the shop's company
collector.domain_age_days = lambda domain: None  # .eu, .de: the registry hides the date
collector.walk = lambda url, shot=None: ("<p>Sklep</p>", "Buty. " * 60 + "help@stepease.eu", [])
assert judge(dict(shop), "stepease.eu")[0] == "review"
collector.domain_age_days = lambda domain: 3594
collector.walk = lambda url, shot=None: ("<h1>Under Maintenance</h1>", "Under Maintenance. " * 30, [])
assert judge(dict(shop), "travala.com")[::2] == ("review", "decoy: Under Maintenance")  # an old site's break
collector.domain_age_days = lambda domain: 30
assert judge(dict(shop), "travala2.com")[0] == "block"  # a new shop "under maintenance" sells nothing
collector.walk = lambda url, shot=None: ('<h2><a href="/witaj-swiecie/">Witaj, świecie!</a></h2>', "Witaj, świecie! " * 30, [])
assert judge(dict(shop), "wp.com")[0] == "block"  # a new site's WordPress sample post
collector.domain_age_days = lambda domain: 1725
assert judge(dict(shop), "wybormenu.pl")[0] == "review"  # an old firm's fresh WordPress on its subdomain
collector.domain_age_days = lambda domain: 30
collector._gave_up.add("przerwa.pl")
assert judge(dict(shop), "przerwa.pl")[0] == "review"  # waited out NASK: maybe years old, a human looks
collector._gave_up.clear()
collector.domain_age_days = lambda domain: None
collector.walk = lambda url, shot=None: ("<p>Kurs</p>", "Kurs. " * 60 + "kurs@gmail.com", [])
assert judge(dict(shop), "kurs-jogi.vercel.app")[0] == "block"  # free hosting: no age, judged as young
collector.walk = lambda url, shot=None: ("<p>Kurs</p>", "Kurs. " * 60, ['legal page did not load "Regulamin" -> https://x/r'])
assert judge(dict(shop), "kurs-jogi.vercel.app")[2].startswith("a free-hosted site, no company named")
assert judge(dict(shop), "kurs-jogi.eu")[0] == "review"  # a registry hiding the date is another matter
named_queue = collector.open_db(":memory:")
named_queue.execute("INSERT INTO verdicts (domain, verdict, ad) VALUES ('sklep.pl', 'review', ?)",
                    (json.dumps({"links": {"sklep.pl": "https://sklep.pl/p/1"}, "landing": {"sklep.pl": contact}}),))
collector.visit = lambda url, expect=None, shot=None, light=False: gone(url)
assert collector.recheck(named_queue) == 0  # meskie-spodnie.pl: the product sold out, the shop is there
newborn = {"landing": {"sklep.pl": contact}, "age_days": {"sklep.pl": 3},
           "fb_page": {"likes": 0, "profile": "https://www.facebook.com/x", "categories": ["Shopping"]}}
named_queue.execute("UPDATE verdicts SET ad = ?", (json.dumps(newborn),))
collector._rechecked.clear()
assert collector.recheck(named_queue) == 1 and named_queue.execute("SELECT verdict FROM verdicts").fetchone()[0] == "block"
shop_queue = collector.open_db(":memory:")
shop_queue.execute("INSERT INTO verdicts (domain, verdict, ad) VALUES ('garnki.pl', 'review', ?)",
                   (json.dumps({"links": {"garnki.pl": "https://garnki.pl/p/1"}}),))
collector.visit = lambda url, expect=None, shot=None, light=False: ("", "Garnki " * 100, []) if url.endswith("pl/") else (
    "", "404 Not Found", [])
assert collector.recheck(shop_queue) == 0  # elmich.pl: one product gone, the shop's home lives
opened = []
collector.visit = lambda url, expect=None, shot=None, light=False: opened.append(url) or ("", "", [])
caption_only = {"ad_creative_link_captions": ["ccc.eu"], "links": {"ccc.eu": "https://superceny.club/r?u=1"},
                "destinations": ["https://superceny.club/r?u=1"]}
assert collector.dead_link(caption_only, "ccc.eu") == "the page shows almost nothing:  on https://ccc.eu/"
assert opened == ["https://ccc.eu/"]  # superceny.club's dead page is not ccc.eu's
before_lands, collector.lands_on = collector.lands_on, lambda d: "smyk.com" if d == "smyk.pl" else None
assert collector.caption_typo({"ad_creative_link_captions": ["pełnadoba.pl"], "page_name": "Pełna Doba - Najem"}, "pelnadoba.pl")
assert collector.caption_typo({"ad_creative_link_captions": ["skihero.pl"], "page_name": "SkiHero"}, "skihero.com.pl")
assert not collector.caption_typo({"ad_creative_link_captions": ["smyk.pl"], "page_name": "Smyk"}, "smyk.shop")  # a site
assert not collector.caption_typo({"ad_creative_link_captions": ["skihero.pl"], "page_name": "Sklep"}, "skihero.com.pl")
collector.lands_on = before_lands


class Answer:  # what urlopen gives inside a with block
    def __init__(self, status, body=b""):
        self.status, self.body = status, body
    def __enter__(self):
        return self
    def __exit__(self, *_):
        return False
    def read(self, *_):
        return self.body


def over_limit(request, timeout):
    raise urllib.error.HTTPError(request.full_url, 429, "Too Many Requests", {}, None)


web = collector.urllib.request
firm = {"firma": [{"nazwa": "Borys Książczyk", "status": "AKTYWNY", "dataRozpoczecia": "2023-10-11",
                   "dataWznowienia": "2026-08-01", "pkdGlowny": {"nazwa": "Wykonywanie konstrukcji"},
                   "pkd": [{"nazwa": "Wykonywanie konstrukcji"}, {"nazwa": "Sprzątanie budynków"}]}]}
collector.CEIDG_TOKENS, urlopen, sleep, slept = ["t"], web.urlopen, collector.time.sleep, []
collector.time.sleep = slept.append
web.urlopen = lambda request, timeout: Answer(200, json.dumps(firm).encode())
assert real_ceidg("5993279575") == {"name": "Borys Książczyk", "status": "AKTYWNY", "since": "2023-10-11", "suspended": None,
                                    "resumed": "2026-08-01", "pkd": ["Wykonywanie konstrukcji", "Sprzątanie budynków"],
                                    "partnerships": []}
owner = {"firma": [{"nazwa": "FIRMA HANDLOWO-USŁUGOWA Grzegorz Urbanek", "status": "WYKRESLONY", "dataRozpoczecia": "2006-11-02"},
                   {"nazwa": "szklanka.pl Grzegorz Urbanek", "status": "AKTYWNY", "dataRozpoczecia": "2017-05-18"}]}
web.urlopen = lambda request, timeout: Answer(200, json.dumps(owner).encode())
assert real_ceidg("6842277774")["status"] == "AKTYWNY"  # the live business, not the one struck off before it
partner = {"firma": [{"nazwa": "Meet My Boss Anna Stankiewicz", "status": "WYKRESLONY", "dataRozpoczecia": "2016-12-07"},
                     {"nazwa": "Anna Stankiewicz LULLALOVE", "status": "WYLACZNIE_W_FORMIE_SPOLKI",
                      "dataRozpoczecia": "2019-09-01", "spolki": [{"nip": "5492436176", "regon": "122940480"}]}]}
web.urlopen = lambda request, timeout: Answer(200, json.dumps(partner).encode())
assert real_ceidg("5492250253")["partnerships"] == ["5492436176"]  # trades only as a partner: live, not struck off
web.urlopen = lambda request, timeout: Answer(204)  # a company: not in CEIDG
assert real_ceidg("5993279575")["name"] == "Borys Książczyk"  # remembered, not asked again
assert real_ceidg("8571941295") == {} and slept[-1] > 3  # 3.6 s after the call before
web.urlopen = over_limit
assert real_ceidg("1234563218") is None and collector._ceidg_next["t"] - collector.time.monotonic() > 170  # CEIDG's pause
collector.CEIDG_TOKENS, collector._ceidg_next, used = ["a", "b"], {}, []  # two accounts take turns
web.urlopen = lambda request, timeout: used.append(request.get_header("Authorization")) or Answer(204)
real_ceidg("1111111111"), real_ceidg("2222222222")
assert used == ["Bearer a", "Bearer b"], used
web.urlopen = over_limit
real_ceidg("3333333333")  # "a" is stopped for 180 s, "b" goes on alone
web.urlopen, used[:] = lambda request, timeout: used.append(request.get_header("Authorization")) or Answer(204), []
real_ceidg("4444444444"), real_ceidg("5555555555")
assert used == ["Bearer b", "Bearer b"], used
web.urlopen, collector.time.sleep, collector.CEIDG_TOKENS, collector._ceidg_next = urlopen, sleep, [], {}

import threading  # home's relay: token, only the model's chat and tags
import home
home.TOKEN, collector.OLLAMA = "t" * 32, "http://127.0.0.1:9"  # nothing listens there
patched, web.urlopen = web.urlopen, lambda request, timeout=None: urllib.request.build_opener().open(request, timeout=timeout)
relay = home.ThreadingHTTPServer(("127.0.0.1", 0), home.Relay)
threading.Thread(target=relay.serve_forever, daemon=True).start()


def ask(path, token="t" * 32, body=None):
    request = urllib.request.Request(f"http://127.0.0.1:{relay.server_port}{path}", body, {"Authorization": f"Bearer {token}"})
    try:
        with web.urlopen(request, timeout=10) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as e:
        return e.code, None


assert ask("/api/tags", token="zly")[0] == 401
assert [ask(p)[0] for p in ("/age/sklep.pl", "/api/pull", "/")] == [404] * 3  # NASK is the server's own now
assert ask("/api/delete", body=b"{}")[0] == 404 and ask("/api/chat", body=b"{}")[0] == 502  # Ollama not started
web.urlopen = patched
relay.shutdown()

with tempfile.TemporaryDirectory() as tmp:  # home's DNS copies the server's lists
    collector.LISTS, served = Path(tmp), {"fb.txt": "*.zly.shop\n", "allow.txt": "", "watpliwe.txt": "*.w.shop\n",
                                          "deny.txt": "x"}
    (collector.LISTS / "allow.txt").write_text("*.dobry.pl\n", encoding="utf-8")
    patched, urllib.request.urlopen = urllib.request.urlopen, lambda url, timeout=None: io.BytesIO(json.dumps(served).encode())
    assert home.sync() and not home.sync()  # the second time nothing changed: no Blocky reload
    assert (collector.LISTS / "fb.txt").read_text(encoding="utf-8") == "*.zly.shop\n"
    assert (collector.LISTS / "allow.txt").read_text(encoding="utf-8") == "*.dobry.pl\n"  # never emptied
    assert not (collector.LISTS / "deny.txt").exists()  # only what the server decides
    urllib.request.urlopen = patched

# a real Chromium after kill_browser() (the end of each cycle): an unstopped driver failed every start
page = Path("/tmp/strona.html")
page.write_text("<p>Sklep Krem</p>", encoding="utf-8")
assert "Sklep Krem" in collector.browse(page.as_uri(), None, None, True)[1]
collector.kill_browser()
assert "Sklep Krem" in collector.browse(page.as_uri(), None, None, True)[1]
collector._browser.browser.close()  # Chromium gone while the collector still holds it (again)
assert "Sklep Krem" in collector.browse(page.as_uri(), None, None, True)[1]
collector.kill_browser()
print("ok")

# a dropped connection is tried again (GET only), an API error is not
tries, real_open, real_sleep = [], collector.urllib.request.urlopen, collector.time.sleep
def flaky(request, timeout):
    tries.append(request.get_method())
    raise collector.urllib.error.URLError(OSError(101, "Network is unreachable"))
collector.urllib.request.urlopen, collector.time.sleep = flaky, lambda s: None
# Graph API's edges: the DNS default drops every connection, the www.facebook.com one takes them
dns = {"graph.facebook.com": "10.0.0.13", "www.facebook.com": "10.0.0.35", "star-mini.c10r.facebook.com": "10.0.0.35"}
real_dns, real_connect = collector._getaddrinfo, collector.socket.create_connection
def fake_dns(host, *args, **kwargs):
    return [(2, 1, 6, "", (dns.get(host, host), 443))]
def fake_connect(address, timeout):
    if address[0] == dead:
        raise TimeoutError("timed out")
    return io.BytesIO()
collector._getaddrinfo, collector.socket.create_connection, dead = fake_dns, fake_connect, "10.0.0.13"
for body, count in ((None, 3), ({"a": 1}, 1)):
    tries.clear()
    try:
        real_http_json("https://graph.facebook.com/x", body)
    except OSError:
        pass
    assert len(tries) == count, (body, tries)
assert collector._graph["ip"] == "10.0.0.35"  # moved off the dead edge after the first drop
assert collector.socket.getaddrinfo("graph.facebook.com", 443)[0][4][0] == "10.0.0.35"
assert collector.socket.getaddrinfo("example.com", 443)[0][4][0] == "example.com"  # other hosts untouched
collector._graph["since"] -= collector.GRAPH_RETRY  # an hour later: DNS again
assert collector.socket.getaddrinfo("graph.facebook.com", 443)[0][4][0] == "10.0.0.13" and collector._graph["ip"] is None
dead = None  # the default healed: it wins the tie, DNS stays
assert collector.graph_edge() is None
collector._getaddrinfo, collector.socket.create_connection = real_dns, real_connect
collector.urllib.request.urlopen, collector.time.sleep = real_open, real_sleep
print("ok")
