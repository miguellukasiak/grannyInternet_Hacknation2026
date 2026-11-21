"""Kampanie: from single suspicious ads to campaigns.

Each material (an incident folder, an uploaded file set, a URL or an ad text) becomes a set of features: text,
keywords, topics, people, impersonated brands, page domains, redirects, tracking IDs, URL parameter schemes, server
IPs, image hashes, page assets and HTML template. Two materials are compared signal by signal; every signal that
matches is one piece of evidence with its own strength and a sentence saying why, and the pieces add up like
independent clues (1 - prod(1 - s)). Missing data is no evidence, never evidence against: a page that is gone still
links by its ad text and its screenshot. Campaigns are single-linkage clusters of 1 - score (each member has one
link of at least LINK), families of campaigns average-linkage clusters at a lower threshold.
"""
import base64
import email
import email.policy
import hashlib
import html
import itertools
import ipaddress
import json
import math
import os
import re
import socket
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zlib
from collections import Counter
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlsplit

import numpy as np
import tldextract
from PIL import Image
from scipy.sparse import csr_matrix
from sklearn.cluster import AgglomerativeClustering
from sklearn.feature_extraction.text import TfidfVectorizer

LINK = 0.5  # score of one campaign: single linkage, every member has at least one link this strong, shown as evidence
SOFT = {"narracja", "temat", "osoba", "marka", "serwer", "parametry"}  # one story, celebrity, host or UTM scheme is shared by unrelated scams
STRONG_TEXT = 0.4  # share of 5-word runs that is a copied text; a shop platform's checkout footer alone gives 15–20%
FAMILY = 0.2  # score of a family of campaigns: average linkage, so weak clues (a topic, a person) do not chain everything
DUPLICATE = 0.9  # share of 5-word runs: the same text, a copy of one page
IMAGE_DIST = 4  # bits of 64 in which two dHashes may differ and still be one picture (recompressed, resized);
# at 5 two different faces in one round testimonial frame matched (organiser's set, 21.11)
CROPS = (0, 0.05, 0.1)  # a re-upload is often trimmed at the edges: the centre gets hashes of its own
# the bundled suffix list (no download at start) with its private part: x.netlify.app, y.myshopify.com, z.lovable.app
# are separate sites of separate owners, not one domain
_ext = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
IMAGES = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}
VIDEOS = {".mp4", ".mov", ".webm", ".m3u8", ".ts", ".avi", ".mkv"}
# anycast addresses of a CDN or a shop platform: thousands of unrelated sites answer from one IP (Cloudflare's published
# ranges, Shopify's storefronts). shortcut: the two biggest in our data; add a range when it chains a campaign
SHARED_IP = 20  # domains on one IP: from here on a hosting platform, not one owner
SHARED_CODE = 10  # materials with one own API or CSS/JS file: below it never taken for a platform

CDN = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32", "23.227.38.0/23")]
# hosts every page loads: sharing them says nothing about a common source
COMMON = {"facebook.com", "facebook.net", "fbcdn.net", "google.com", "googleapis.com", "gstatic.com", "google.pl",
          "googletagmanager.com", "google-analytics.com", "doubleclick.net", "youtube.com", "ytimg.com",
          "jsdelivr.net", "cloudflare.com", "cdnjs.com", "jquery.com", "bootstrapcdn.com", "unpkg.com", "w3.org",
          "schema.org", "gravatar.com", "wp.com", "wordpress.org", "apple.com", "instagram.com", "twitter.com",
          "x.com", "tiktok.com", "cloudflareinsights.com", "fontawesome.com", "typekit.net", "jsdelivr.com",
          # marketplaces and link hosts that unrelated ads point to (amazon.com: 121 of our blocked domains)
          "amazon.com", "amazon.de", "amazon.it", "amazon.pl", "amazon.fr", "amazon.es", "amazon.co.uk", "a.co",
          "amzn.to", "booking.com", "temu.com", "allegro.pl", "aliexpress.com", "ebay.com", "etsy.com", "olx.pl",
          "fruugo.nl", "fruugo.pl", "meta.com", "fb.me", "fb.com", "m.me", "wa.me", "whatsapp.com", "linktr.ee",
          "bit.ly", "t.me"}
STOP = ("a aby ale albo bo by być był była było były co czy dla do gdy go i ich im in is jak jako je jego jej jest "
        "już ma mi mnie na nad nie nich nim niż o od on ona one oni po pod przez przy się są ta tak tam te tego tej "
        "ten to tu tym u w we wiele z za że ze żeby oraz także który która które którzy tylko też bardzo jeszcze "
        "the and of to in for on with you your this that are was www http https com pl").split()

TRACKERS = [  # (name, regex): an account ID of an ad or analytics service, the same owner on two pages
    ("piksel Meta", r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{8,20})"),
    ("piksel Meta", r"facebook\.com/tr/?\?(?:[^\"'\s<>]*?&)?id=(\d{8,20})"),
    ("piksel Meta", r"[?&](?:pxl|fbpx|fb_pixel|pixel_id|pixel|fbpixel)=(\d{8,20})"),
    ("Google Tag Manager", r"\b(GTM-[A-Z0-9]{5,9})\b"),
    ("Google Analytics", r"\b(G-[A-Z0-9]{8,12})\b"),
    ("Google Analytics", r"\b(UA-\d{4,10}-\d{1,3})\b"),
    ("piksel TikTok", r"ttq\.load\(\s*['\"]([A-Z0-9]{12,25})"),
    ("Yandex Metrica", r"mc\.yandex\.ru/watch/(\d{5,12})"),
    ("reklama Meta", r"[?&]ad_id=(\d{12,20})\b"),  # one ad: the link it sent people with
    ("kampania Meta", r"[?&](?:fb_)?campaign_id=(\d{12,20})\b"),
    ("Google Ads", r"\bAW-(\d{9,11})\b"),
    ("Google Ads", r"/(?:1p-conversion|viewthroughconversion)/(\d{9,11})/"),
]
# hosting whose every subdomain is one customer's account, but missing from the Public Suffix List
ACCOUNT_HOSTS = {"b-cdn.net", "surge.sh", "weebly.com", "tilda.ws", "godaddysites.com", "wordpress.com",
                 "000webhostapp.com", "mystrikingly.com", "site123.me", "jimdosite.com", "webnode.page", "ucoz.net"}
# self-hosted copies of public libraries: the same bytes on unrelated sites
# shortcut: names only (a saved page's _files keep no origin); Base.common drops the rest once the base is large
LIBRARY = re.compile(r"jquery|bootstrap|fbevents|gtag|gtm|analytics|swiper|slick|owl\.carousel|lazysizes|sweetalert|"
                     r"intl-?tel|inputmask|imask|polyfill|recaptcha|font-?awesome|animate|aos\b|wow\b|lottie|embla|"
                     r"vue|react|axios|lodash|moment|popper|fancybox|lightbox|select2|toastr|normalize|reset|"
                     r"framework|webpack|runtime|vendor|sdk|shaka|email-decode|^all\.min\.css$|"
                     # Google Maps and Translate scripts a saved page keeps next to its own
                     r"^(?:common|util|controls|geometry|log|init_embed|onion|map|marker|stats|element|api|embed|"
                     r"places|places_impl)\.js$",
                     re.I)
THEMES = re.compile(r"/wp-(?:content|includes)/|/cdn/shop/")  # one WordPress or Shopify theme serves thousands of shops
OWN_CODE = re.compile(r"\.(css|js)$")
KIT_ID = re.compile(r"^(?:[0-9a-f-]{8,}|\d+)$", re.I)  # per-page part of an API path (UUID, hash, number)
# people whose faces and names scams borrow most often; a stem catches Polish inflection (Brzoska, Brzoskę)
PERSONS = {
    "Rafał Brzoska": r"brzosk", "Monika Olejnik": r"olejnik", "Mateusz Morawiecki": r"morawieck",
    "Donald Tusk": r"\btusk", "Karol Nawrocki": r"nawrock", "Rafał Trzaskowski": r"trzaskowsk",
    "Szymon Hołownia": r"hołowni", "Jarosław Kaczyński": r"kaczyńsk", "Andrzej Duda": r"andrzej\w* dud",
    "Robert Lewandowski": r"robert\w* lewandowsk", "Anna Lewandowska": r"ann\w* lewandowsk",
    "Kuba Wojewódzki": r"wojewódzk", "Marcin Prokop": r"marcin\w* prokop", "Dorota Wellman": r"wellman",
    "Krzysztof Ibisz": r"ibisz", "Magda Gessler": r"gessler", "Ewa Chodakowska": r"chodakowsk",
    "Jerzy Owsiak": r"owsiak", "Michał Sołowow": r"sołow", "Dominika Kulczyk": r"kulczyk",
    "Zbigniew Jakubas": r"jakubas", "Leszek Czarnecki": r"leszk\w* czarneck", "Adam Glapiński": r"glapińsk",
    "Krzysztof Stanowski": r"krzysztof\w* stanowsk", "Piotr Kraśko": r"kraśk", "Elon Musk": r"\bmusk",
    "Bill Gates": r"\bbill\w* gates", "Andrzej Domański": r"andrzej\w* domańsk", "Tomasz Lis": r"tomasz\w* lis\b",
}
# brands a page may pose as -> their real domains
BRANDS = {
    "Gazeta.pl": ("gazeta.pl",), "TVN24": ("tvn24.pl",), "Onet": ("onet.pl",), "Interia": ("interia.pl",),
    "Wirtualna Polska": ("wp.pl",), "Business Insider": ("businessinsider.com.pl",), "Forbes": ("forbes.pl",),
    "money.pl": ("money.pl",), "Rzeczpospolita": ("rp.pl",), "Polsat News": ("polsatnews.pl",),
    "Fakt": ("fakt.pl",), "Super Express": ("se.pl",), "Bankier": ("bankier.pl",), "Pudelek": ("pudelek.pl",),
    "PKO BP": ("pkobp.pl", "ipko.pl"), "Pekao": ("pekao.com.pl",), "mBank": ("mbank.pl",),
    "Santander": ("santander.pl",), "InPost": ("inpost.pl",), "Allegro": ("allegro.pl",), "OLX": ("olx.pl",),
    "ZUS": ("zus.pl",), "NBP": ("nbp.pl",), "KNF": ("knf.gov.pl",), "Orlen": ("orlen.pl",),
    "App Store": ("apple.com",), "Google Play": ("google.com",), "BLIK": ("blik.com",),
}
TOPICS = {  # stems; two different ones make the topic
    "inwestycje": ["inwest", "zarob", "zysk", "dochód", "dochod", "kryptowalut", "bitcoin", "giełd", "pasywn",
                   "kapitał", "trading", "platform", "portfel", "wypłat"],
    "zdrowie / suplement": ["cukrzyc", "nadciśnien", "stawy", "staw", "prostat", "odchudz", "lekarz", "kuracj",
                            "suplement", "tabletk", "kapsułk", "schud", "ciśnieni", "potencj", "pęcherz"],
    "sensacja / fałszywy news": ["zamach", "aresztow", "kajdank", "usunięt", "skandal", "szok", "nagrani",
                                 "ujawni", "wywiad", "afera", "emisj", "strzela"],
    "hazard": ["kasyn", "bonanza", "slot", "spin", "jackpot", "zakład", "wygran", "bonus"],
    "paczka / dopłata": ["paczk", "przesyłk", "dopłat", "kurier", "dostaw", "nadani"],
    "loteria / nagroda": ["nagrod", "loteri", "gratulacj", "konkurs", "wylosowa"],
}
URGENCY = re.compile(r"tylko dziś|tylko dzisiaj|ostatni\w* (?:miejsc|szt|dzień|szans)|zostało (?:tylko )?\d+|"
                     r"limitowan|pośpiesz|do północy|ograniczon\w* (?:liczb|czas|ofert)|oferta wygasa|nie czekaj",
                     re.I)
MIRACLE = re.compile(r"\bcud|100\s?%|gwarant|lekarze (?:nie|ukrywa)|bez recepty|raz na zawsze|w \d+ dni", re.I)
CHEAP_TLDS = {"live", "xyz", "icu", "pro", "life", "top", "shop", "online", "site", "click", "store", "buzz",
              "cfd", "sbs", "lol", "fun", "space", "website", "info", "bond", "today", "world"}
DOMAIN_TEXT = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
WORDS = re.compile(r"[^\W\d_]+")
SAVED_FROM = re.compile(r"<!-- saved from url=\(\d+\)(\S+?) -->")
_persons = {name: re.compile(stem) for name, stem in PERSONS.items()}
_brands = {name: re.compile(r"(?<![\w.])" + re.escape(name.lower()) + r"(?![\w])") for name in BRANDS}


@dataclass
class Material:
    id: str
    name: str
    origin: str = "zbiór"  # zbiór = the analysed folder, dodane = added in the GUI
    text: str = ""
    title: str = ""
    landing: list = field(default_factory=list)  # domains the material's pages ran on
    redirects: list = field(default_factory=list)  # [[host, host, ...], ...]
    domains: list = field(default_factory=list)  # every other domain in links, assets, requests, screenshots
    claimed: list = field(default_factory=list)  # brands in a title, site name or logo
    persons: list = field(default_factory=list)
    topics: list = field(default_factory=list)
    trackers: list = field(default_factory=list)  # "piksel Meta 1071875908635809"
    params: list = field(default_factory=list)  # URL parameter schemes: "utm_campaign,utm_content,utm_id,..."
    ips: list = field(default_factory=list)
    images: list = field(default_factory=list)  # [[dhash, name], ...]
    assets: list = field(default_factory=list)  # file names a page loads
    template: list = field(default_factory=list)  # crc32 of 6-tag runs of the page structure
    shingles: list = field(default_factory=list)  # crc32 of 5-word runs of the text
    forms: list = field(default_factory=list)  # input fields
    kit: list = field(default_factory=list)  # "POST /api/v1/trigger/field/*/": the page's own API, the backend kit
    files: list = field(default_factory=list)  # "sha1 name" of the page's own CSS/JS: the same file, the same author
    ages: dict = field(default_factory=dict)  # domain -> days since registration (RDAP)
    sources: list = field(default_factory=list)  # what was read
    missing: list = field(default_factory=list)  # what could not be read: no evidence, not counter-evidence


def domain_of(host: str | None) -> str | None:
    if not host:
        return None
    host = host.lower().strip(".").split(":")[0]
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        dom = _ext(host).top_domain_under_public_suffix or None
    if dom in ACCOUNT_HOSTS and host.removeprefix("www.") != dom:
        return ".".join(host.split(".")[-(dom.count(".") + 2):])  # vz-6110f311-389.b-cdn.net, not b-cdn.net
    return dom


def on_cdn(ip: str) -> bool:
    try:
        return any(ipaddress.ip_address(ip) in net for net in CDN)
    except ValueError:
        return False


def host_of(url: str) -> str | None:
    try:
        parts = urlsplit(url.strip())
        return parts.hostname if parts.scheme in ("http", "https") else None
    except ValueError:
        return None


def crc_runs(items: list[str], n: int) -> set[int]:
    return {zlib.crc32(" ".join(items[i:i + n]).encode()) for i in range(len(items) - n + 1)}


class Page(HTMLParser):
    SKIP = {"script", "style", "noscript", "template", "svg", "head"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text, self.links, self.assets, self.tags, self.inputs = [], set(), set(), [], set()
        self.meta, self.title, self._skip, self._title = {}, "", 0, False

    def handle_starttag(self, tag, attrs):
        a = {k: v or "" for k, v in attrs}
        if tag in self.SKIP:
            self._skip += 1
        self._title = tag == "title"
        cls = ".".join(sorted(a.get("class", "").split())[:2])
        self.tags.append(tag + ("." + cls if cls else ""))
        if tag in ("a", "form", "area") and (href := a.get("href") or a.get("action")):
            self.links.add(href)
        for key in ("src", "href", "data-src"):
            if tag in ("img", "script", "link", "source", "iframe", "video") and a.get(key):
                self.assets.add(a[key])
        if tag in ("input", "select", "textarea") and a.get("type", "").lower() not in ("hidden", "submit"):
            self.inputs.add((a.get("type") or tag).lower() + ":" + (a.get("name") or a.get("id") or "").lower())
        if tag == "meta" and a.get("content"):
            self.meta[(a.get("property") or a.get("name") or "").lower()] = a["content"]
        if tag == "link" and "canonical" in a.get("rel", "") and a.get("href"):
            self.meta["canonical"] = a["href"]

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip:
            self._skip -= 1
        if tag == "title":
            self._title = False

    def handle_data(self, data):
        if self._title:
            self.title += data
        elif not self._skip and (data := data.strip()):
            self.text.append(data)


def asset_name(url: str) -> str:
    name = urlsplit(url).path.rsplit("/", 1)[-1].lower()
    return re.sub(r"\(\d+\)(?=\.\w+$)", "", re.sub(r"\.(pobrane|download)$", "", name))  # main(1).js: a second copy


def add_text(m: Material, text: str):
    m.text = (m.text + "\n" + text).strip()


def add_trackers(m: Material, raw: str):
    for name, pattern in TRACKERS:
        for found in re.findall(pattern, raw):
            if f"{name} {found}" not in m.trackers:
                m.trackers.append(f"{name} {found}")


def add_file(m: Material, name: str, data: bytes):
    """The page's own stylesheet or script, by content: a renamed copy is still the same file."""
    if THEMES.search(name):
        return
    name = asset_name(name)
    if len(data) > 500 and OWN_CODE.search(name) and not LIBRARY.search(name):
        if (item := f"{hashlib.sha1(data).hexdigest()[:12]} {name}") not in m.files:
            m.files.append(item)


def add_kit(m: Material, method: str, url: str):
    """A request the page sends to its own server: the path of the kit's API, page IDs blanked out."""
    path = "/".join("*" if KIT_ID.match(s) else s for s in urlsplit(url).path.split("/"))
    if method != "GET" and path.count("/") >= 3 and not re.match(r"/(cdn-cgi|wp-)", path):
        if (item := f"{method} {path}") not in m.kit:
            m.kit.append(item)


def add_url(m: Material, url: str, landing: bool = False):
    """A URL the material showed: its domain, its parameter scheme, IDs in its query."""
    if not (host := host_of(url)) or not (dom := domain_of(host)):
        return
    target = m.landing if landing else m.domains
    if dom not in target:
        target.append(dom)
    names = sorted({k.lower() for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)})
    if landing and len(names) >= 3 and (scheme := ",".join(names)) not in m.params:
        m.params.append(scheme)
    add_trackers(m, url)


def add_html(m: Material, raw: str, url: str | None = None, source: str = "strona"):
    page = Page()
    try:
        page.feed(raw)
    except Exception:  # a broken page still gives what was read before the break
        pass
    if saved := SAVED_FROM.search(raw[:2000]):
        url = url or saved[1]
    if url:
        add_url(m, url, landing=True)
    for key in ("canonical", "og:url"):
        if page.meta.get(key, "").startswith("http"):
            add_url(m, page.meta[key])
    for link in page.links | page.assets:
        if link.startswith("http"):
            add_url(m, link)
    m.assets += [n for n in sorted({asset_name(a) for a in page.assets}) if len(n) >= 5 and n not in m.assets]
    for key in ("facebook-domain-verification", "google-site-verification"):
        if code := page.meta.get(key):
            m.trackers.append(f"weryfikacja domeny ({key.split('-')[0]}) {code[:40]}")
    add_trackers(m, raw)
    m.title = m.title or html.unescape(page.title.strip())
    shown = " ".join([page.title, page.meta.get("og:site_name", ""), page.meta.get("og:title", "")] +
                     [a for a in page.assets if "logo" in a.lower()]).lower()
    m.claimed += [b for b, rx in _brands.items() if rx.search(shown) and b not in m.claimed]
    m.forms += [i for i in sorted(page.inputs) if i not in m.forms]
    m.template = sorted(set(m.template) | crc_runs(page.tags[:4000], 6))
    add_text(m, " ".join(page.text))
    m.sources.append(source)


def add_har(m: Material, path: Path):
    entries = json.loads(path.read_text(encoding="utf-8", errors="replace"))["log"]["entries"]
    if not entries:
        m.missing.append(f"{path.name}: pusty HAR")
        return
    chain, url, by_url = [], entries[0]["request"]["url"], {e["request"]["url"]: e for e in entries}
    while (e := by_url.get(url)) and 300 <= e["response"]["status"] < 400 and len(chain) < 10:
        chain.append(host_of(url) or "?")
        url = urljoin(url, e["response"].get("redirectURL") or "")
    chain.append(host_of(url) or "?")
    if len(chain) > 1:
        m.redirects.append(chain)
    for host in chain:
        add_url(m, "https://" + host + "/", landing=True)
    add_url(m, entries[0]["request"]["url"], landing=True)
    main = by_url.get(url)
    for e in entries:
        req, res = e["request"], e["response"]
        add_url(m, req["url"])
        if (ip := e.get("serverIPAddress", "").strip("[]")) and host_of(req["url"]) in chain and ip not in m.ips:
            m.ips.append(ip)
        raw = res.get("content", {}).get("text") or ""
        data = base64.b64decode(raw) if res.get("content", {}).get("encoding") == "base64" else raw.encode()
        if domain_of(host_of(req["url"])) in m.landing:  # the page's own server, not an ad network or a CDN library
            add_kit(m, req["method"].upper(), req["url"])
            add_file(m, req["url"], data)
        if e is main or (main is None and "html" in res.get("content", {}).get("mimeType", "")):
            body = data.decode("utf-8", "replace")
            if body:
                add_html(m, body, url=req["url"], source=f"{path.name} (strona z HAR)")
                main = e
    if main is None:
        m.missing.append(f"{path.name}: brak treści strony w HAR (strona nie odpowiedziała)")
    m.sources.append(path.name)


def ocr(path: Path) -> str:
    """Text of a screenshot (tesseract pol+eng), shrunk first: phone screenshots are 4-6 MB."""
    with Image.open(path) as img, tempfile.TemporaryDirectory() as tmp:
        img = img.convert("RGB")
        if img.width > 1600:
            img = img.resize((1600, round(img.height * 1600 / img.width)))
        img.save(small := Path(tmp) / "x.png")
        out = subprocess.run(["tesseract", str(small), "stdout", "-l", "pol+eng", "--psm", "3"],
                             capture_output=True, text=True, timeout=120)
    return out.stdout


def dhash(img: Image.Image) -> int | None:
    px = img.convert("L").resize((9, 8), Image.Resampling.LANCZOS).tobytes()
    bits = 0
    for r in range(8):
        for c in range(8):
            bits = bits << 1 | (px[r * 9 + c] > px[r * 9 + c + 1])
    return bits if 8 <= bits.bit_count() <= 56 else None  # a flat image (blank, one colour) matches anything


def add_image(m: Material, path: Path, screenshot: bool):
    with Image.open(path) as img:
        if min(img.size) < 48:  # icons and spacers
            return
        w, h = img.size
        for f in CROPS:  # one entry per crop, all under one name: a saved base keeps its [hash, name] rows
            if (dh := dhash(img.crop((int(w * f), int(h * f), int(w * (1 - f)), int(h * (1 - f)))))) is not None:
                m.images.append([dh, path.name])
    if screenshot:
        try:
            text = ocr(path)
        except (OSError, subprocess.SubprocessError) as e:
            m.missing.append(f"{path.name}: OCR niedostępny ({e.__class__.__name__})")
            return
        add_text(m, text)
        for dom in {domain_of(d) for d in DOMAIN_TEXT.findall(text.lower())} - {None}:
            if dom.rsplit(".", 1)[-1] not in ("png", "jpg", "html", "js", "css", "webp") and dom not in m.domains:
                m.domains.append(dom)  # an address bar or a link in a caption
        m.sources.append(f"{path.name} (zrzut, OCR)")


def add_info(m: Material, path: Path):
    """Metadata of a downloaded ad video (yt-dlp .info.json): its text and the ad's IDs."""
    info = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    add_text(m, " ".join(str(info.get(k) or "") for k in ("title", "description", "uploader", "alt_title")))
    m.title = m.title or str(info.get("title") or "")
    for key in ("webpage_url", "original_url"):
        if str(info.get(key, "")).startswith("http"):
            add_url(m, info[key])
    for key in ("playlist_uploader_id", "uploader_id", "channel_id"):  # the advertiser's page, as baza.py names it
        if re.fullmatch(r"\d{6,20}", str(info.get(key) or "")) and (t := f"strona FB {info[key]}") not in m.trackers:
            m.trackers.append(t)
    m.sources.append(path.name)


def add_mhtml(m: Material, path: Path):
    msg = email.message_from_bytes(path.read_bytes(), policy=email.policy.default)
    url = msg.get("Snapshot-Content-Location")
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            add_html(m, part.get_content(), url=url or part.get("Content-Location"), source=path.name)
            return


def from_files(m: Material, files: list[Path], root: Path) -> Material:
    for f in sorted(files):
        ext = f.suffix.lower()
        in_assets = any(p.name.endswith("_files") for p in f.relative_to(root).parents)  # "Webpage, complete"
        try:
            if ext in (".html", ".htm") and not in_assets:
                add_html(m, f.read_text(encoding="utf-8", errors="replace"), source=f.name)
            elif ext == ".mhtml":
                add_mhtml(m, f)
            elif ext == ".har":
                add_har(m, f)
            elif in_assets and OWN_CODE.search(asset_name(f.name)):  # main.css.pobrane: a saved page's own file
                add_file(m, f.name, f.read_bytes())
            elif f.name.endswith(".info.json"):
                add_info(m, f)
            elif ext in IMAGES:
                add_image(m, f, screenshot=not in_assets)
            elif ext in VIDEOS and not in_assets:
                m.missing.append(f"{f.name}: wideo nie jest analizowane (tylko jego metadane i zrzuty)")
            elif ext == ".txt" and not in_assets:
                add_text(m, f.read_text(encoding="utf-8", errors="replace"))
                m.sources.append(f.name)
        except Exception as e:  # one broken file never stops the material
            m.missing.append(f"{f.name}: nie udało się odczytać ({e.__class__.__name__})")
    return finish(m)


def from_folder(path: Path, origin: str = "zbiór") -> Material:
    return from_files(Material(id=path.name, name=path.name, origin=origin),
                      [f for f in path.rglob("*") if f.is_file()], path)


def public_ip(host: str) -> str:
    ips = {i[4][0] for i in socket.getaddrinfo(host, None)}
    if not ips or not all(ipaddress.ip_address(ip).is_global for ip in ips):
        raise ValueError(f"{host}: adres prywatny lub nieznany")
    return sorted(ips)[0]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def fetch(m: Material, url: str):
    """The page's HTML only (never files), every redirect checked to lead to a public address.
    shortcut: DNS is checked before urllib resolves it again (rebinding possible), fine for a local demo."""
    opener, chain = urllib.request.build_opener(_NoRedirect), []
    for _ in range(8):
        host = host_of(url)
        if not host:
            raise ValueError("tylko adresy http(s)")
        ip = public_ip(host)
        chain.append(host)
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Linux; Android 14) Chrome/130 Mobile",
                                                   "Accept-Language": "pl-PL,pl;q=0.9"})
        try:
            with opener.open(req, timeout=20) as res:
                if "html" not in res.headers.get("Content-Type", ""):
                    raise ValueError(f"to nie strona HTML ({res.headers.get('Content-Type')})")
                raw = res.read(3_000_000).decode(res.headers.get_content_charset() or "utf-8", "replace")
            break
        except urllib.error.HTTPError as e:
            if 300 <= e.code < 400 and e.headers.get("Location"):
                url = urljoin(url, e.headers["Location"])
                continue
            raise
    else:
        raise ValueError("za dużo przekierowań")
    if len(chain) > 1:
        m.redirects.append(chain)
    for host in chain:
        add_url(m, "https://" + host + "/", landing=True)
    m.ips.append(ip)
    add_html(m, raw, url=url, source=f"pobrana strona {chain[-1]}")


def rdap_age(domain: str) -> int | None:
    """Days since the domain was registered, from its registry's RDAP; None when it does not say."""
    from datetime import datetime, timezone
    req = urllib.request.Request(f"https://rdap.org/domain/{domain}", headers={"Accept": "application/rdap+json"})
    with urllib.request.urlopen(req, timeout=15) as res:
        events = json.load(res).get("events", [])
    for e in events:
        if e.get("eventAction") == "registration":
            born = datetime.fromisoformat(e["eventDate"].replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - born).days
    return None


def finish(m: Material) -> Material:
    low = m.text.lower()
    m.text = m.text[:30000]
    m.persons = [p for p, rx in _persons.items() if rx.search(low)]
    m.topics = [t for t, stems in TOPICS.items() if len({s for s in stems if s in low}) >= 2]
    m.shingles = sorted(crc_runs(WORDS.findall(DOMAIN_TEXT.sub(" ", low[:20000])), 5))
    m.domains = [d for d in m.domains if d not in m.landing]
    if not m.text.strip():
        m.missing.append("brak tekstu (strona niedostępna albo sam obraz bez OCR)")
    return m


def look_up_ages(m: Material):
    for dom in m.landing[:4]:
        if dom not in m.ages:
            try:
                m.ages[dom] = rdap_age(dom)
            except Exception as e:
                m.missing.append(f"RDAP {dom}: brak odpowiedzi ({e.__class__.__name__})")


# ---------- verdict: what in one material draws attention ----------

def flags(m: Material) -> list[tuple[int, str]]:
    low, out = m.text.lower(), []
    who = ", ".join(m.persons)
    if m.persons and "inwestycje" in m.topics:
        out.append((3, f"Wizerunek znanej osoby ({who}) przy obietnicy zarobku"))
    elif m.persons and "sensacja / fałszywy news" in m.topics:
        out.append((2, f"Sensacyjna „wiadomość” o znanej osobie ({who})"))
    elif m.persons and "zdrowie / suplement" in m.topics:
        out.append((2, f"Znana osoba ({who}) poleca środek na zdrowie"))
    for brand in m.claimed:
        if m.landing and not any(d in BRANDS[brand] for d in m.landing):
            out.append((3, f"Strona podaje się za {brand}, a działa na {', '.join(m.landing[:3])}"))
    if (bad := [d for d in m.landing if d.rsplit(".", 1)[-1] in CHEAP_TLDS]):
        out.append((1, f"Tania domena jednorazowa: {', '.join(bad)}"))
    for dom in m.landing:
        lure = [b for b, real in BRANDS.items() if b.lower().replace(" ", "").replace(".", "") in dom.replace("-", "")
                and dom not in real]
        if lure:
            out.append((2, f"Nazwa domeny {dom} udaje markę {lure[0]}"))
    if (young := {d: a for d, a in m.ages.items() if a is not None and a < 180}):
        out.append((2, "Młoda domena: " + ", ".join(f"{d} ({a} dni)" for d, a in young.items())))
    for chain in m.redirects:
        if len({domain_of(h) for h in chain}) > 1:
            out.append((1, "Przekierowania przez kilka domen: " + " → ".join(chain)))
    if any(f.startswith("tel:") or re.search(r"phone|telefon|tel\b", f) for f in m.forms):
        out.append((1, "Formularz zbiera numer telefonu (oddzwoni „doradca”)"))
    if URGENCY.search(low):
        out.append((1, f"Presja czasu: „{URGENCY.search(low)[0]}”"))
    if "lubię to" in low and "odpowiedz" in low:
        out.append((1, "Wklejone „komentarze z Facebooka” (Lubię to · Odpowiedz)"))
    if "zdrowie / suplement" in m.topics and MIRACLE.search(low):
        out.append((2, f"Obietnica cudownego leczenia: „{MIRACLE.search(low)[0]}”"))
    if "hazard" in m.topics:
        out.append((2, "Gra hazardowa w reklamie"))
    if any(t.startswith("piksel") for t in m.trackers) and m.claimed:
        out.append((1, "Strona udająca medium mierzy ruch z reklam pikselem"))
    return out


def verdict(m: Material) -> tuple[str, int]:
    points = sum(p for p, _ in flags(m))
    return ("wysokie ryzyko: wygląda na oszustwo" if points >= 4 else "podejrzane" if points >= 2
            else "brak wyraźnych sygnałów"), points


# ---------- comparing and grouping ----------

def jaccard(a, b) -> float:
    a, b = set(a), set(b)
    return len(a & b) / len(a | b) if a and b else 0.0


class Base:
    """All materials with what comparing them needs: TF-IDF of texts and what is too common to link anything."""

    def __init__(self, materials: list[Material]):
        self.materials = materials
        self.by_id = {m.id: m for m in materials}
        n = len(materials)
        freq = Counter()
        for m in materials:
            freq.update({("d", d) for d in m.landing + m.domains} | {("a", a) for a in m.assets} |
                        {("i", i) for i in m.ips} | {("k", x) for x in m.kit} | {("f", x) for x in m.files})
        many = max(3, math.ceil(0.4 * n))  # in 40% of all materials: a platform, not a campaign
        # the same API or file of a page's own is a platform only on many pages: in a small set it is the campaign itself
        self.common = ({k for k, c in freq.items() if c >= (max(SHARED_CODE, many) if k[0] in "kf" else many)}
                       | {("d", d) for d in COMMON})
        # an IP that serves many of our domains is shared hosting (Lovable, Netlify, Vercel…), learned from the data itself
        self.common |= {k for k, c in freq.items() if k[0] == "i" and (c >= SHARED_IP or on_cdn(k[1]))}
        texts = [m.text or "" for m in materials]
        self.vec = TfidfVectorizer(token_pattern=r"(?u)\b[^\W\d_]{3,}\b", stop_words=STOP, sublinear_tf=True,
                                   max_df=1.0 if n < 5 else 0.8, max_features=20000)
        try:
            self.tfidf = self.vec.fit_transform(texts)
            self.terms = self.vec.get_feature_names_out()
        except ValueError:  # no words at all
            self.tfidf, self.terms = None, []
        self.row = {m.id: i for i, m in enumerate(materials)}
        self._pairs: dict = {}
        self._cos = self._similar_texts()
        self._jac = {"shingles": self._overlaps("shingles", 0.15, 20), "template": self._overlaps("template", 0.3, 30)}
        self._matrix = None

    def _similar_texts(self) -> dict:
        """(row, row) -> cosine of the texts, for pairs at 0.25 or more: below it narration is no evidence."""
        out = {}
        if self.tfidf is None:
            return out
        for start in range(0, self.tfidf.shape[0], 1000):  # in blocks: all pairs of thousands of texts at once is GBs
            block = (self.tfidf[start:start + 1000] @ self.tfidf.T).tocoo()
            keep = (block.data >= 0.25) & (block.row + start < block.col)
            out.update(zip(zip((block.row[keep] + start).tolist(), block.col[keep].tolist()), block.data[keep].tolist()))
        return out

    def _overlaps(self, attr: str, least: float, size: int) -> dict:
        """(row, row) -> Jaccard of `attr` sets (each of at least `size`), where >= least: sparse products, not loops."""
        rows = [i for i, m in enumerate(self.materials) if len(getattr(m, attr)) >= size]
        if len(rows) < 2:
            return {}
        vocab, ind, ptr = {}, [], [0]
        for i in rows:
            ind += [vocab.setdefault(x, len(vocab)) for x in set(getattr(self.materials[i], attr))]
            ptr.append(len(ind))
        s = csr_matrix((np.ones(len(ind), np.float32), ind, ptr), shape=(len(rows), len(vocab)))
        sizes, rows, out = np.diff(ptr), np.array(rows), {}
        for start in range(0, len(rows), 1000):
            both = (s[start:start + 1000] @ s.T).tocoo()
            a, b = both.row + start, both.col
            jac = both.data.astype(np.float64) / (sizes[a] + sizes[b] - both.data)  # counts: exact, as in jaccard()
            keep = (a < b) & (jac >= least - 1e-6)
            out.update(zip(zip(rows[a[keep]].tolist(), rows[b[keep]].tolist()), jac[keep].tolist()))
        return out

    def candidates(self) -> set:
        """Every pair that shares something compare() looks at; any other pair scores 0, so it is never compared."""
        pairs, index = set(self._cos), {}
        for i, m in enumerate(self.materials):
            keys = ({("d", x) for x in m.landing + m.domains} | {("a", x) for x in m.assets} |
                    {("i", x) for x in m.ips} | {("k", x) for x in m.kit} | {("f", x) for x in m.files}) - self.common
            keys |= ({("t", x) for x in m.trackers} | {("p", x) for x in m.params} |
                     {("o", x) for x in m.persons + m.claimed + m.topics})
            for key in keys:
                index.setdefault(key, []).append(i)
        for rows in index.values():
            pairs.update(itertools.combinations(rows, 2))
        pairs.update(self._jac["shingles"], self._jac["template"])
        pairs.update(itertools.combinations([i for i, m in enumerate(self.materials) if m.images], 2))
        return pairs

    def _key(self, a: Material, b: Material) -> tuple:
        return tuple(sorted((self.row[a.id], self.row[b.id])))

    def _jaccard(self, attr: str, a: Material, b: Material) -> float:
        if a.id in self.row and b.id in self.row:  # worked out for the whole base at once; absent = below the bar
            return self._jac[attr].get(self._key(a, b), 0.0)
        return jaccard(getattr(a, attr), getattr(b, attr))

    def narration(self, a: Material, b: Material) -> tuple[float, list[str]]:
        if a.id not in self.row or b.id not in self.row or not (cos := self._cos.get(self._key(a, b))):
            return 0.0, []
        both = self.tfidf[self.row[a.id]].multiply(self.tfidf[self.row[b.id]])
        top = [self.terms[i] for i in np.argsort(-both.toarray()[0])[:6] if both[0, i] > 0]
        return cos, top

    def compare(self, a: Material, b: Material) -> tuple[float, list[tuple[float, str, str]]]:
        """Evidence that a and b are one campaign: [(strength, kind, why)] and its sum as independent clues."""
        key = (a.id, b.id) if a.id < b.id else (b.id, a.id)
        if key in self._pairs:
            return self._pairs[key]
        ev = []

        def rare(kind, items):
            return sorted(set(items) - {x for k, x in self.common if k == kind})

        if tr := sorted(set(a.trackers) & set(b.trackers)):
            ev.append((0.95, "identyfikator", "ten sam identyfikator reklam/analityki: " + ", ".join(tr)))
        if land := rare("d", set(a.landing) & set(b.landing)):
            ev.append((0.9, "domena", "ta sama domena strony: " + ", ".join(land)))
        if same_files := rare("f", set(a.files) & set(b.files)):
            ev.append((min(0.9, 0.7 + 0.1 * len(same_files)), "pliki",
                       "identyczne własne pliki CSS/JS (sha1): " + ", ".join(same_files[:4])))
        # one path may be a common shop plugin, two of one API are the same backend
        if kit := rare("k", set(a.kit) & set(b.kit)):
            ev.append((min(0.8, 0.4 * len(kit)), "zestaw", "to samo API strony (zestaw): " + "; ".join(kit[:4])))
        if len(a.shingles) >= 20 and len(b.shingles) >= 20 and (cp := self._jaccard("shingles", a, b)) >= 0.15:
            ev.append((min(0.95, 0.3 + cp), "tekst", f"{cp:.0%} wspólnych 5-wyrazowych fragmentów tekstu"))
        cos, words = self.narration(a, b)
        if cos >= 0.25:
            ev.append((min(0.7, cos * 0.8), "narracja", f"podobna narracja ({cos:.0%}): " + ", ".join(words)))
        same = sorted({f"{na}≈{nb}" if na != nb else na for ha, na in a.images for hb, nb in b.images
                       if (ha ^ hb).bit_count() <= IMAGE_DIST})
        if same:
            ev.append((min(0.9, 0.6 + 0.1 * (len(same) - 1)), "obraz", "te same obrazy: " + ", ".join(same[:5])))
        if sch := sorted(set(a.params) & set(b.params)):
            ev.append((0.6, "parametry", "ten sam schemat parametrów linku z reklamy: " + "; ".join(sch)))
        # below LINK: shared hosting serves many unrelated sites, so a server alone never makes a campaign
        if ips := rare("i", set(a.ips) & set(b.ips)):
            ev.append((0.4, "serwer", "ten sam adres IP serwera: " + ", ".join(ips)))
        if doms := rare("d", (set(a.domains) | set(a.landing)) & (set(b.domains) | set(b.landing)) - set(land)):
            ev.append((min(0.6, 0.3 * len(doms)), "domeny", "wspólne domeny w linkach i zasobach: " + ", ".join(doms[:6])))
        if assets := rare("a", set(a.assets) & set(b.assets)):
            ev.append((min(0.6, 0.15 * len(assets)), "zasoby", "te same pliki strony: " + ", ".join(assets[:6])))
        if len(a.template) >= 30 and len(b.template) >= 30 and (tp := self._jaccard("template", a, b)) >= 0.3:
            ev.append((0.6 * tp, "szablon", f"zbliżony szablon HTML ({tp:.0%} wspólnej struktury)"))
        if who := sorted(set(a.persons) & set(b.persons)):
            ev.append((0.35, "osoba", "te same osoby: " + ", ".join(who)))
        if brand := sorted(set(a.claimed) & set(b.claimed)):
            ev.append((0.3, "marka", "podszywa się pod tę samą markę: " + ", ".join(brand)))
        if topic := sorted(set(a.topics) & set(b.topics)):
            ev.append((0.15, "temat", "ten sam temat: " + ", ".join(topic)))
        ev.sort(reverse=True)
        score = 1 - math.prod(1 - s for s, _, _ in ev)
        self._pairs[key] = (score, ev)
        return score, ev

    @staticmethod
    def duplicate(a: Material, b: Material) -> bool:
        """The same text (a copy under another domain), or the same landing domain with mostly the same text."""
        cp = jaccard(a.shingles, b.shingles) if min(len(a.shingles), len(b.shingles)) >= 20 else 0
        return cp >= DUPLICATE or (cp >= 0.7 and bool(set(a.landing) & set(b.landing)))

    def link(self, a: Material, b: Material) -> float:
        """compare()'s score if some evidence is hard; soft clues alone chained 1054 of our 5404 domains into one,
        and generic UTM schemes with a shared checkout footer still 431."""
        score, ev = self.compare(a, b)
        hard = [s for s, kind, _ in ev if kind not in SOFT and (kind != "tekst" or s >= 0.3 + STRONG_TEXT)]
        return score if hard else 0.0

    def matrix(self, hard: bool = False) -> np.ndarray:
        """Pair scores; hard=True keeps only pairs a campaign may be built on (see link())."""
        if self._matrix is None:
            s, h = np.eye(len(self.materials)), np.eye(len(self.materials))
            for i, j in self.candidates():
                a, b = self.materials[i], self.materials[j]
                s[i, j] = s[j, i] = self.compare(a, b)[0]
                h[i, j] = h[j, i] = self.link(a, b)
            self._matrix = (s, h)
        return self._matrix[hard]

    def groups(self, level: float, linkage: str = "average", hard: bool = False) -> list[list[str]]:
        n = len(self.materials)
        if n < 2:
            return [[m.id for m in self.materials]] if n else []
        # sklearn merges only below the threshold; the rule is "at least `level`", as in place()
        labels = AgglomerativeClustering(n_clusters=None, metric="precomputed", linkage=linkage,
                                         distance_threshold=1 - level + 1e-9).fit_predict(1 - self.matrix(hard))
        out: dict[int, list[str]] = {}
        for m, label in zip(self.materials, labels):
            out.setdefault(int(label), []).append(m.id)
        return sorted(out.values(), key=lambda g: (-len(g), g))

    def campaigns(self) -> list[dict]:
        fams = {mid: i for i, fam in enumerate(self.groups(FAMILY)) for mid in fam}
        out = []
        for i, ids in enumerate(self.groups(LINK, "single", hard=True), 1):
            kinds, pairs = Counter(), []
            for x in range(len(ids)):
                for y in range(x + 1, len(ids)):
                    score, ev = self.compare(self.by_id[ids[x]], self.by_id[ids[y]])
                    kinds.update(k for _, k, _ in ev)
                    pairs.append((score, ids[x], ids[y], ev))
            ms = [self.by_id[x] for x in ids]
            label = Counter(p for m in ms for p in m.persons + m.claimed + m.topics).most_common(3)
            dup = [(a, b) for _, a, b, _ in pairs if self.duplicate(self.by_id[a], self.by_id[b])]
            out.append({"id": f"K{i}", "members": ids, "family": f"R{fams[ids[0]] + 1}",
                        "label": ", ".join(x for x, _ in label) or "bez wspólnego motywu",
                        "linked_by": [k for k, _ in kinds.most_common(4)], "pairs": sorted(pairs, reverse=True),
                        "duplicates": dup, "domains": sorted({d for m in ms for d in m.landing})})
        return out

    def place(self, new: Material, campaigns: list[dict]) -> dict:
        """Where a new material belongs: the campaign of its strongest link (as in campaigns()), or a new pattern."""
        scored = sorted(((self.compare(new, m)[0], m.id) for m in self.materials if m.id != new.id), reverse=True)
        best, where = None, {}
        for c in campaigns:
            members = [x for x in c["members"] if x != new.id]
            if not members:
                continue
            avg = sum(self.compare(new, self.by_id[x])[0] for x in members) / len(members)
            top = max(self.link(new, self.by_id[x]) for x in members)
            where[c["id"]] = (avg, top)
            if top >= LINK and (best is None or top > where[best][1]):
                best = c["id"]
        return {"campaign": best, "fit": where, "similar": scored[:8]}


def load_folder(root: Path, log=print) -> list[Material]:
    """Every subfolder is one material; loose files in the root are one each."""
    out = []
    for p in sorted(root.iterdir(), key=lambda p: (len(p.name), p.name)):
        if p.name.startswith("."):
            continue
        log(f"analiza: {p.name}")
        out.append(from_folder(p) if p.is_dir() else
                   from_files(Material(id=p.stem, name=p.name), [p], root))
    return out


if __name__ == "__main__":  # python kampanie.py <folder>: campaigns as text, no GUI
    base = Base(load_folder(Path(sys.argv[1] if len(sys.argv) > 1 else "/dane")))
    for c in base.campaigns():
        print(f"\n{c['id']} ({c['family']}) {c['label']}: {', '.join(c['members'])}")
        for score, a, b, ev in c["pairs"][:5]:
            print(f"  {a} ~ {b} {score:.2f}: " + "; ".join(why for _, _, why in ev[:3]))
    for m in base.materials:
        print(f"\n{m.id}: {verdict(m)[0]}")
        for p, why in flags(m):
            print(f"  +{p} {why}")
