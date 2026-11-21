"""Meta Ad Library -> scam-domain denylist for Blocky.

Every advertised domain goes through: allowlist -> clone and decoy-page checks -> heuristic score
-> optional local LLM -> denylist.
"""

import base64
import colorsys
import csv
import functools
import html as html_lib
import http.client
import io
import ipaddress
import itertools
import json
import os
import re
import signal
import socket
import sqlite3
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from html import unescape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import tldextract
from playwright.sync_api import Error as PlaywrightError, sync_playwright

ADS_API = "https://graph.facebook.com/v26.0/ads_archive"
FIELDS = "id,page_id,page_name,ad_creative_bodies,ad_creative_link_captions,ad_creative_link_titles"
SEARCH_TERMS = [  # the Ad Library needs a search term; each cycle takes the next TERMS_PER_CYCLE of them
    "inwestycja", "zarabiaj", "pasywny dochód", "kryptowaluty", "bitcoin", "giełda",  # investment
    "wyprzedaż", "likwidacja sklepu", "likwidacja magazynu", "ostatnie sztuki", "darmowa dostawa", "rabat",  # shops
    "stawy", "ból kolan", "cukrzyca", "odchudzanie", "żylaki", "ciśnienie", "słuch",  # health miracles
    "ćwiczenia", "trening w domu", "ćwiczenia na krześle", "joga dla seniorów", "plan treningowy",  # fitness
    "dopłata paczka", "odbierz nagrodę", "weryfikacja konta", "zwrot podatku", "blik",  # phishing
    "praca zdalna", "praca w domu",  # job scams
]
TERMS_PER_CYCLE = 18  # x3 pages = 54 Graph calls per 15 min; 30 got Meta's 613 every hour in the day, 15 never did
TRANCO = "https://tranco-list.eu/download/daily/top-1m.csv.zip"
LISTS = Path("/lists")
# on a Docker volume: SQLite's locks fail on the Windows bind mount, a second writing process broke four commits
VERDICTS = Path("/verdicts/verdicts.db")
SHOTS = LISTS / "shots"  # first screen of each landing page, {domain}.jpg: evidence, scam pages vanish fast
LANDING_CHARS = 20_000  # landing and legal page text kept with the ad, for appeals and training
BLOCKY = os.getenv("BLOCKY", "http://blocky:4000")  # empty on the server: DNS is at home, it copies fb.txt (home.py)
SERVED = ("fb.txt", "allow.txt", "watpliwe.txt")  # the server's decisions that home's DNS copies (home.py)
# On a server: home's relay (home.py, through an SSH tunnel from home) for the LLM on home's card
HOME = os.getenv("HOME_URL")
HOME_TOKEN = os.getenv("HOME_TOKEN")  # the relay answers only with it
OLLAMA = HOME or os.getenv("OLLAMA_URL")  # unset = heuristics only
# `collector.py again`: a second process that only judges again, with its own browser, while the first collects:
# pages are mostly waiting, so two walk at once on 2 cores. The first leaves it to it with JUDGE_AGAIN=apart.
AGAIN = sys.argv[1:] == ["again"]
APART = os.getenv("JUDGE_AGAIN") == "apart"
MODEL = os.getenv("OLLAMA_MODEL", "qwen3.5:4b")  # of 8 small models on 2 008 human decisions the one with the fewest false alarms (README)
NUM_GPU = os.getenv("OLLAMA_NUM_GPU")  # "0" = CPU only; unset = Ollama decides
CYCLE_SECONDS = 15 * 60

SIGNALS = [  # (regex, weight): phrasing typical of Polish scam ads
    (r"inwest|zarabia|zarobi|dochód|zysk|krypto|bitcoin|giełd", 2),
    (r"brzosk|kulczyk|solorz|lewandowsk|orlen|pgnig|baltic|tvn24", 2),  # impersonated people and brands
    (r"likwidacj|zamykamy|wyprzeda|ostatnie sztuki|tylko dziś|-[5-9]\d ?%", 1),
    (r"dopłat|wygra|weryfikacj|blik", 1),  # not "przesyłka" or "odbierz": every shop says "darmowa przesyłka"
    (r"cukrzyc|\bstaw[yóa]|lekarz|cudown|bez operacji|żylak", 1),
]
DECOY = re.compile(  # home pages that are not a real business behind an ad
    # Chinese shop platform behind most throwaway scam shops (20 of 23 checked): a Chinese "home"
    # link (首页) in a shop selling to Poles, and its asset servers (also blocked in lists/deny.txt);
    # 首页 alone, not inside a longer Chinese name like moboreader.com's "官网书城首页" in its scripts
    r"(?<![一-鿿])首页(?![一-鿿])|compgoo\.com|ocolt\.com|sdhahs\.com|hsrdkt\.com|dpdvx\.com|lndpy\.com"
    # empty WordPress (scontistock.com); its sample post's title, not a shop's "Witaj, świecie! To ja." (kidsandus.pl)
    r"|<title>My WordPress</title>|Just another WordPress site|Witaj, świecie!(?=\s*<)"
    r'|parking-lander|LANDER_SYSTEM|href="/lander'  # parked domain: the ad's caption is not where the link really goes
    # search-ad arbitrage: a text-only article bought with a Meta ad to sell Google's search ads (thefactrelay.com,
    # tiwnr.com; 11 of 4304 domains, 5 blocked, 6 in review, none passed)
    r"|adsense/search/ads\.js|syndicatedsearch\.goog|_googCsa"  # its loader too: (window,'_googCsa') (contradia.com)
    r"|(?i:under maintenance|przerwa techniczna)"  # a shop that advertises but sells nothing (smyk.brand-eu.com)
    # a bare server, a file list, a crashed PHP shop or an unfilled Shopify theme: nothing for sale, however long
    r"|(?i:apache2? (?:\w+ )?default page|test page for the apache)|<title>Index of /"
    r"|(?:Fatal|Parse) error(?:</b>)?:\s*(?:Uncaught|syntax error|Allowed memory size|Call to undefined)"
    r"|Example product title"
)
# A break on a long-lived site (travala.com, 10 years) is no decoy: a human looks. So is a fresh WordPress with its
# sample post on an old firm's subdomain (zamowienie.wybormenu.pl, cms.apartamentymuseo.pl)
MAINTENANCE = re.compile(r"under maintenance|przerwa techniczna|Witaj, świecie", re.I)
# A domain up for sale is no business yet: forgotten, neither blocked nor kept, judged anew once it comes back with a
# shop (the user's rule). CY10245422H is Aftermarket.pl Limited, the seller on its sale pages (mibu.pl)
FOR_SALE = re.compile(r"Oferta sprzedaży domeny|Jak kupić tę domenę|kup tę domenę|\b(?:ta|tę) domen[aęy]? (?:jest |może być )?"
                      r"na sprzeda|\b(?:this|the) domain (?:name )?(?:is |may be )?for sale|domain name for sale"
                      r"|buy this domain|hugedomains\.com|CY\W?10245422H", re.I)
FORGET_DAYS = 7  # a forgotten domain's next ads walk it again only after this
# Hosts giving each customer a subdomain, missing from the public suffix list: each customer's site judged alone, the
# host never blocked (everdance.greatapps.co blocked by a human, greatapps.co not; potyczki.bookero.pl, bookero.pl
# passed). Seen in our ads' captions plus the known ones worldwide; those in the list (webflow.io, carrd.co,
# square.site, framer.website, shoparena.pl) need none, path-based ones (calendly.com/x, linktr.ee/x) neither.
# A free site there is made in minutes: judged as young, like FREE_HOSTS
FREE_TENANT_HOSTS = ("greatapps.co", "coze.site", "bolt.host", "weblium.site", "wix-site-host.com", "onepage.me",
                     "quizgo.site", "wordpress.com", "substack.com", "beehiiv.com", "webnode.page", "webnode.pl",
                     "webnode.com", "jimdosite.com", "jimdofree.com", "site123.me", "ucraft.site", "zyrosite.com",
                     "hostingersite.com", "durablesites.com", "b12sites.com", "super.site", "mailchimpsites.com",
                     "mailerpage.io", "ck.page", "gumroad.com")
# A paying firm's page (booking, events, funnels, courses, shops, jobs, help desks): no age of its own, so judged as
# of unknown age, never by its host's server
TENANT_HOSTS = FREE_TENANT_HOSTS + (
    "bookero.pl", "reservio.com", "simplybook.net", "setmore.com", "youcanbook.me", "acuityscheduling.com", "as.me",
    "appointlet.com", "zohobookings.com", "zohobookings.eu", "medsoft.pl", "cms.efitness.com.pl", "wod.guru",
    "konfeo.com", "guestsage.com", "systembiletowy.pl", "e-skipass.pl", "clickmeeting.com",
    "scoreapp.com", "sendpulse.courses", "vouchercart.com", "ismycheckout.com", "fbads.pl", "responso.com", "user.com",
    "salescrm.pl", "referralrock.com", "member.placewise.com", "myclickfunnels.com", "kartra.com", "pagedemo.co",
    "unbouncepages.com", "landingi.com", "hs-sites.com", "hs-sites-eu1.com", "hubspotpagebuilder.com", "involve.me",
    "outgrow.us", "teachable.com", "thinkific.com", "mykajabi.com", "learnworlds.com", "samcart.com",
    "myshopline.com", "onshopbase.com", "mybigcommerce.com", "company.site", "bigcartel.com", "storenvy.com",
    "iai-shop.com", "squarespace.com", "ghost.io", "traffit.com", "recruitify.ai", "teamtailor.com", "recruitee.com",
    "breezy.hr", "jobs.personio.de", "bamboohr.com", "zendesk.com", "freshdesk.com", "helpscoutdocs.com", "gitbook.io",
    "readme.io", "tebex.io")
# Free hosting that gives each site a subdomain of its own (in the public suffix list, so judged as a domain)
FREE_HOSTS = tuple(f".{host}" for host in ("vercel.app", "lovable.app", "myshopify.com", "netlify.app", "pages.dev",
                                           "github.io", "web.app", "firebaseapp.com", "herokuapp.com", "onrender.com",
                                           "wixsite.com", "heyflow.site", "chatgpt.site", *FREE_TENANT_HOSTS))
HOSTED = FREE_HOSTS + tuple(f".{host}" for host in TENANT_HOSTS)  # no registration, no server of their own
NO_ADDRESS = {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)}  # not EAI_AGAIN: DNS hiccup
CANARY = "www.google.com"  # surely has an address: without one our own network is down
MOBILE_UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36"
LIBRARY = "https://www.facebook.com/ads/library/?id={}"  # public, no login; the API gives only the link's caption
LINK = re.compile(r"""l\.php\?u=([^&"']+)|"link_url":"(https?:\\/\\/[^"]+)\"""")  # click redirect or the ad's JSON;
# other URLs on a Library page are Meta's own blocklist (tinyurl, short.gy), never the ad's
META = {"facebook.com", "fb.com", "fb.me", "m.me", "messenger.com", "instagram.com", "whatsapp.com", "wa.me"}
INFO_PAGE = re.compile(r"regulamin|warunki|polityk|prywatno|cookie|o nas|o firmie|kontakt|dane firm|sprzedawc|prawn"
                       r"|impressum|imprint|privacy|policies|terms|about|contact|legal"
                       # shops abroad selling to Poles: DE, FR, ES/PT/IT, NL, Nordics, CZ/SK, HU, RO, Baltics, HR, UA
                       r"|agb|datenschutz|über uns|mentions|cgv|confidentialit|qui sommes|términos|termos|termini"
                       r"|\bcondici|condiz|privacidad|privacidade|aviso legal|note legali|quiénes somos|chi siamo"
                       r"|voorwaarden|over ons|villkor|vilkår|betingelser|personvern|integritet|om oss|om os|ehdot"
                       r"|tietosuoja|podmínky|podmienky|osobních|osobných|o nás|ászf|aszf|adatvédel|impresszum"
                       r"|termeni|despre noi|noteikumi|privātum|tingimused|privaatsus|taisyklės|privatum|uvjeti"
                       r"|privatnost|o nama|умови|конфіденц|про нас"
                       r"|会社概要|会社情報|運営会社|特定商取引|利用規約|個人情報|プライバシー|お問い合わせ",  # JP
                       re.I)  # on link text and address
# The pages that usually hold the company number, opened first: the page limit cuts off what stands late in a footer
NUMBER_PAGE = re.compile(r"impressum|imprint|impresszum|dane firm|o firmie|sprzedawc|regulamin|terms|agb|mentions|aviso legal"
                         r"|note legali|warunki|kontakt|contact", re.I)
# Policy generators hosting a site's own policy on their domain, followed from the site's pages (and no further):
# omron-healthcare.pl's cookie policy on iubenda.com names "VAT: NL813286281B01 OMRON Healthcare Europe B.V"
POLICY_HOSTS = {"iubenda.com", "termly.io"}
FILE = re.compile(r"\.(?:pdf|docx?|odt|rtf|txt|zip|rar|7z|exe|apk|msi)(?:[?#]|$)|/download\b|[?&]download=", re.I)
CHALLENGE = re.compile(  # anti-bot walls: never solved, the domain goes to a human
    r"Verifying your connection|Checking your browser|Just a moment\.\.\.|Enable JavaScript and cookies"
    r"|połączenie zostało zablokowane|Access Denied|Attention Required|Request blocked"  # answear.com blocks bots
    r"|Przeprowadzanie weryfikacji zabezpieczeń|Punkt kontroli bezpieczeństwa|Security Checkpoint"  # CF, Vercel in pl
    r"|Proszę czekać na weryfikację żądania|Please wait while your request is being verified"  # elevatesummit.pl
    r"|nie może być obecnie obsłużone"  # DirectAdmin WAF with our IP on its blacklist (topdrogeria.pl)
    # adm.tools's "Proceed" button, in English (bocian.shop) or Ukrainian (woodmart.pl)
    r"|confirm that you are not a robot|(?:protected by|захищено|защищено) adm\.tools|(?:ви|вы) не робот"
    r"|verify that you.re human|Press and Hold")  # consumerchoicecircle.com, only from a datacenter address
# a 403 often refuses only the server's address: altisport.pl, a real maker, answered "403 Forbidden"
FORBIDDEN = re.compile(r"403 Forbidden|Forbidden.{0,40}permission to access")
FOREIGN_IDS = [  # business and tax registry numbers by country; words that are also common words need a colon
    r"vat(?: ?id| no| number| reg(?:istration)?(?: no| number)?)?", r"tax ?(?:id|no|number)", r"tin", r"taxpayer",
    r"company (?:no|number|reg(?:istration)?(?: no| number)?)", r"registration (?:no|number)", r"reg\.? ?no",
    r"ust-?idnr", r"steuer-?(?:nr|nummer)", r"hr[ab]", r"fn", r"uid", r"che-",  # DE, AT, CH
    r"siret", r"siren", r"rcs(?: [a-zé\-]+){0,2}(?: sous le (?:numéro|n°))?",  # FR
    r"(?:n° )?tva(?: intracommunautaire)?",
    r"p\.? ?iva", r"partita iva", r"codice fiscale", r"c\.f\.", r"rea",  # IT
    r"cif", r"nif", r"nipc",  # ES, PT
    r"kvk(?:-nummer)?", r"btw", r"kbo", r"bce", r"ondernemingsnummer",  # NL, BE
    r"cvr", r"org\.? ?nr", r"organi[sz]ations?nummer", r"y-tunnus", r"momsnr",  # DK, SE, NO, FI
    r"utr", r"crn", r"cro",  # UK, IE
    r"ičo", r"dič", r"ič dph", r"adószám", r"cégjegyzékszám", r"eik", r"еик", r"bulstat",  # CZ, SK, HU, BG
    # RO, often spelled out: "cod unic de înregistrare RO32062435", "Registrul Comerţului J14/158/2013"
    r"cui", r"cod unic de [îi]nregistrare", r"cod (?:de identificare )?fiscal", r"registrul comer[tţț]ului",
    r"nr\.? ?(?:ord\.? ?)?reg\.? ?com\.?",
    r"oib",  # HR
    # a foreign firm's number in Polish words: "UAB „Rinkos tinklas” (numer rejestracyjny firmy 135927776" (rttax.com)
    r"numer rejestracyjny(?: firmy| spółki)?", r"kod (?:firmy|spółki|przedsiębiorstwa)", r"numer identyfikacji podatkowej",
    r"registrikood", r"įmonės kodas", r"pvm", r"pvn", r"afm", r"αφμ", r"gemi", r"γεμη",  # Baltics, GR
    r"edrpou", r"єдрпоу", r"инн", r"огрн", r"ogrn", r"унп",  # UA, RU, BY
    r"ein:", r"fein", r"bn", r"business number", r"abn", r"acn", r"nzbn",  # US, CA, AU, NZ
    r"gst", r"cin", r"uen", r"br no", r"trn", r"trade licen[cs]e(?: no)?", r"cr no",  # Asia, Gulf
    r"cnpj", r"rfc", r"cuit", r"rut", r"nit", r"ruc",  # Latin America
    r"vergi no", r"mersis", r"法人番号", r"统一社会信用代码", r"사업자등록번호",  # TR, JP, CN, KR
]
COMPANY = {  # details a Polish e-shop must publish (UŚUDE art. 5); each kind found lowers the scam score by one
    "email": r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+",
    "phone": r"(?:\+48[\s-]?)?\b\d{3}[\s-]?\d{3}[\s-]?\d{3}\b",
    "address": r"\b\d{2}-\d{3}\s+\w{3,}|〒\s?\d{3}-\d{4}",  # Polish and Japanese postcode
    "legal form": r"sp\. ?z o\. ?o\.|spółka|\bs\.a\.|\bsp\. ?[jkp]\.|\bs\. ?c\.|\bs\.r\.o\."  # s.c.: dixielion.com
                  r"|\b(?:gmbh|ag|ltd|limited|plc|llc|inc)\b"
                  r"|\b(?:a/s|aps|b\.v\.|n\.v\.|s\.p\.a\.|s\.r\.l\.|sarl|s\.a\.s\.|sas|eurl|oy|kft\.|d\.o\.o\.)(?!\w)"
                  r"|société par actions simplifiée|société à responsabilité limitée|株式会社|有限会社|合同会社",
    # 123-456-78-90, 123-45-67-890, 1234567890; the EU VAT number is the NIP after PL (VAT-UE: PL9562367302);
    # "NIP (VAT):", "NIP/VAT ID: PL…" and footers glued together ("KRS: 0000876618NIP: 7792522018ul."),
    # capital NIP after a word too ("00-363 WarszawaNIP: 5253076071" on titanosklep.pl)
    "NIP": r"(?:(?<![a-z])(?:nip|vat(?:[- ]?ue)?\W{0,3}pl)|(?-i:NIP))(?:\W{0,3}(?:\(?vat\)?|/vat(?: id)?))?\W{0,3}(?:pl)?\s?"
           r"(?:\d[- ]?){9}\d(?!\d)",
    "KRS": r"\bkrs\W{0,3}(?:\d ?){9}\d\b",
    "REGON": r"\bregon\W{0,3}(?:\d ?){8}\d\b",
    # keyword, at most a short prefix (DE, ATU, MI-), then the number: "VAT i są brutto 1999" never counts
    # an aside after the keyword: "CUI (odpowiednik polskiego NIP / VAT-EU): RO39167080" (reelken.pl)
    "foreign registry": r"(?<!\w)(?:" + "|".join(FOREIGN_IDS) + r")(?: ?\([^)]{1,40}\))?\W{0,5}[a-z]{0,4}[\s\-]?\d[\d .\-/]{5,}"
                        r"|\bgstin\W{0,5}\d{2}[a-z]{5}\d{4}[a-z\d]{4}",  # India: letters inside the number
}
REGISTRY = {"NIP", "KRS", "REGON", "foreign registry"}  # names the company; an e-mail alone every scam shop has
# Other companies that terms quote with their own address and KRS: the consumer office, payment and parcel firms.
# Their details say nothing about who runs the shop, so the text around them is left out of the search.
_OTHERS = (r"(?:urz[aą]d ochrony konkurencji|uokik|powstańców warszawy 1|rzecznik|inspekcj"
           r"|payu|paypro|przelewy ?24|blue ?media|autopay|tpay|krajowy integrator|imoje|paynow|sofort|adyen"  # pyszne.pl
           r"|inpost|dpd|dhl|gls|poczta polska|shopify|stripe|paypal|klarna|google|meta platforms"
           r"|packeta|z[aá]silkovna|slovensk[aá] po[sš]t"  # "Packeta Slovakia, s.r.o., ... NIP: 2120099014" read as naturu.pl's own
           r"|cyber_?folks|\bhome\.pl\b|\bnazwa\.pl\b|\bovh\b|hostinger|dhosting|zenbox|linuxpl|\bh88\b"
           r"|hostingow|fakturowni|\b(?:infakt|wfirma|ifirma)\b"  # "Dane rejestrowe firmy hostingowej: H88 S.A. ... NIP" (wiazarpolska.pl); invoicing services among data recipients (wilczoglodna.pl)
           # data recipients: "naszym dostawcom rozwiązań internetowych; - ADVERTpro.co (NIP: …)", the chatbot's vendor
           # before the dealer's own NIP (mgplazawarszawa.pl); "Lista procesorów" stands in footers before the
           # shop's own number, so not that word (bench/processor_nip.py)
           r"|naszym (?:dostawc|partner|podwykonawc)\w*|advertpro)")
# not chained (each firm named inside a cut starting its own 250): a footer's row of logos then ate the shop's NIP
THIRD_PARTY = re.compile(_OTHERS + r"[\s\S]{0,250}", re.I)
# Couriers, payment operators and hosts named on every shop's pages: their own ads are never judged, since
# THIRD_PARTY would cut their own company details from their own pages (autopay.pl went to the queue)
TRUSTED = {"inpost.pl", "inpost.eu", "inpostpay.pl", "dpd.com", "dpd.com.pl", "dpd.pl", "dhl.com", "dhl.pl", "dhl.de",
           "gls-group.com", "gls-group.eu", "gls-poland.com", "poczta-polska.pl", "pocztex.pl", "envelo.pl",
           "przelewy24.pl", "payu.pl", "payu.com", "autopay.pl", "bluemedia.pl", "tpay.com", "imoje.pl", "paynow.pl",
           "paypal.com", "klarna.com", "stripe.com", "shopify.com", "cyberfolks.pl", "cyber-folks.pl", "home.pl",
           "nazwa.pl", "ovhcloud.com", "ovh.com", "hostinger.pl", "dhosting.pl", "zenbox.pl",
           "linuxpl.com", "h88.pl", "fakturownia.pl", "infakt.pl", "wfirma.pl", "ifirma.pl", "packeta.pl", "packeta.com",
           "posta.sk", "zgloszenia24.pl",  # a platform too, but never judged: the caption's own site is
           "investboost.pl"}  # an ad agency's landing pages for its client firms at /<firm> (izolmax.pl)
# Hosts of other people's shops and landing pages: a block would hit every site on them, so a human decides
# mssg.me and the rest seen in the base (awesome-union.mssg.me's ad blocked all of mssg.me)
PLATFORMS = {"myshoplaza.com", "getresponsewebsite.com", "grwebsite.pl", "calendesk.net", "subscribepage.io", "mssg.me",
             "storelo.pl", "zanfia.co", "actpages.com", "ac-page.com", "adsquiz.io", "podia.com", "perspectivefunnel.com",
             "elms.pl", "systeme.io", "tilda.ws", "mystrikingly.com", "weebly.com", "godaddysites.com",
             "getresponsepages.com", "getresponsesite.com", "gr8.com",  # GetResponse's other page hosts
             "simplybook.it", "simplybook.me",  # booking pages: onlyher.simplybook.it (OnlyHer.pl's ad)
             "zgloszenia24.pl",  # firms' shops at /shop/<firm>/ (easymotionskin.com.pl's ad)
             "investboost.pl"}  # same at /<firm>: investboost.pl/izolmax (Izolmax's ad)
# Link shorteners: the ad's real target stands behind them. Followed, never judged: a block would hit every link
# made with them (iwrd.pl's ad opened tiny.pl/..., and tiny.pl itself went to the queue)
SHORTENERS = {"tiny.pl", "bit.ly", "bitly.com", "tinyurl.com", "cutt.ly", "t.ly", "is.gd", "ow.ly", "rebrand.ly",
              "short.gy", "tiny.cc", "shorturl.at", "s.id", "rb.gy", "t.co", "goo.gl", "lnkd.in", "urlz.fr",
              "pixelfy.me"}  # Russell Hobbs Polska's ad
# Their numbers stand in shops' terms further from their names than THIRD_PARTY reaches: PayU, cyber_folks
THIRD_PARTY_IDS = re.compile("|".join(r"\D?".join(number) for number in (
    "7792308495", "0000274399", "300523444", "7822622168", "0000612359", "364261632", "5213704420", "0000572426",
    "2021879959", "CY10245422H", "7792369887", "0000347935")))  # + Fakturownia; Slovenská pošta stands right after
# Packeta, inside its cut (naturu.pl); Aftermarket.pl Limited sells domains (mibu.pl): its number means the
# domain is for sale; PayPro (Przelewy24) ~330 characters after its name in a privacy policy (katarzynagolebiewska.pl)
RISKY_TLDS = {"shop", "top", "xyz", "online", "site", "store", "click", "icu", "sbs", "cfd", "buzz", "live", "cyou"}
BLOCK_AT, ASK_AT = 5, 3
YOUNG_DAYS = 90  # half of the blocked scams are younger (median 98 days), 13 of 304 passed shops
NEWBORN_DAYS = 7  # younger with a FB page of 0 likes: blocked (teresa-bizuteria.com, 1 day)
ESTABLISHED_DAYS = 365  # older domains are never blocked automatically, at most queued for a human
# A firm's own domain, not one bought aged for a scam: those were 1-2 years old (lunarpiath.com 569 days)
OLD_DAYS = 5 * 365

LLM_PROMPT = """You review Facebook ads shown in Poland. Most ads are honest businesses, so answer scam=true only
when the ad itself shows a concrete sign of fraud:
- money promised for little effort: guaranteed profit, "zarabiaj bez wysiłku", celebrity or state company endorsement
- medical miracles: a cream that cures varicose veins, a watch that measures blood sugar, dentures without a dentist
- a fake shop: an unknown store with a made-up name (often "-store", "-buy", "-bazaar") selling a famous brand
  or a "warehouse liquidation" at huge discounts
- phishing: parcel surcharge, prize to collect, BLIK, bank or government account verification
Not scams on their own: courses, webinars, job offers, real estate, crypto exchanges, financial products of a named
company, apps with films, short dramas or series (dramatic plot teasers), ordinary sales and discounts,
bold marketing words like "zyskaj" or "inwestycja".
The facts may add the text of the landing page, the company details found on the site and company_excerpt, the
part of the site that names the company (often its footer or terms). Full details of a
registered company (NIP, KRS, REGON, address, legal form) are a strong sign of honesty unless the page sells
a miracle; a shop with no company details at all is suspicious.
company_register, when given, is what the Polish register says of a sole trader: how many days ago the business
started and the kinds of business it is registered for (PKD codes; left out for one registered to sell any goods),
all of equal weight: a trader may sell under any of them.
Only an ad selling what none of them covers (baby creams sold by a roofer) suggests a borrowed company.
fb_page_category and fb_page_likes describe the advertiser's FB page. A category far from what the ad sells (a shoe
shop advertising hair extensions) suggests a bought or borrowed page; few likes alone prove nothing, many honest
small firms have few.
First give the reason in at most 15 words, without quotation marks, then the verdict."""
LLM_SCHEMA = {  # reason before verdict: the model commits to evidence first
    "type": "object",
    "properties": {"reason": {"type": "string"}, "scam": {"type": "boolean"}},
    "required": ["reason", "scam"],
}

DOMAIN = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}")
extract = tldextract.TLDExtract(include_psl_private_domains=True,  # tenant.netlify.app stays its own domain
                                # www.bookero.pl is the host itself, not its customer: never judged either
                                extra_suffixes=TENANT_HOSTS + tuple(f"www.{host}" for host in TENANT_HOSTS))


# Meta serves graph.facebook.com from many edges; the one DNS gave the server once dropped half the
# connections while the www.facebook.com edge answered all. A dropped connection moves the API to the edge that
# answers best; after an hour the DNS default is tried again.
GRAPH = urllib.parse.urlsplit(ADS_API).hostname
GRAPH_TWINS = ("www.facebook.com", "star-mini.c10r.facebook.com")  # Meta edges that also serve the Graph API
GRAPH_RETRY = 3600
_graph = {"ip": None, "since": 0.0}  # None: what DNS says
_getaddrinfo = socket.getaddrinfo


def _graph_getaddrinfo(host, *args, **kwargs):
    if host == GRAPH and _graph["ip"]:
        if time.time() - _graph["since"] < GRAPH_RETRY:
            host = _graph["ip"]
        else:
            print(f"Graph API: back to the default edge after an hour on {_graph['ip']}")
            _graph["ip"] = None
    return _getaddrinfo(host, *args, **kwargs)


socket.getaddrinfo = _graph_getaddrinfo


def graph_edge() -> str | None:
    """The Meta edge that took the most of 3 connections each (the DNS default wins ties); None keeps DNS."""
    def ips(host: str) -> list[str]:
        try:
            return [info[4][0] for info in _getaddrinfo(host, 443, socket.AF_INET)]
        except OSError:
            return []
    def took(ip: str) -> int:
        ok = 0
        for _ in range(3):
            try:
                socket.create_connection((ip, 443), timeout=5).close()
                ok += 1
            except OSError:
                pass
        return ok
    default = ips(GRAPH)
    edges = list(dict.fromkeys(default + [ip for host in GRAPH_TWINS for ip in ips(host)]))
    if not edges:
        return None
    best = max(edges, key=took)  # max keeps the first of equals: the DNS default
    return None if best in default else best


def http_json(url: str, body: dict | None = None, timeout: int = 30) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json", "User-Agent": "scam-dns"}
    if HOME and url.startswith(HOME):
        headers["Authorization"] = f"Bearer {HOME_TOKEN}"
    request = urllib.request.Request(url, data, headers)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.load(response)
        except urllib.error.HTTPError as e:  # keep the API's error message, drop the query string (it holds the token)
            raise OSError(f"{e.code} {url.split('?')[0]}: {e.read()[:500]!r}") from None
        except (urllib.error.URLError, TimeoutError) as e:  # Graph API may drop every other connection from one edge
            host = urllib.parse.urlsplit(url).hostname
            if body is not None or attempt == 2:  # a POST (the LLM) is not sent twice
                raise OSError(f"{host}: {e}") from None  # "Network is unreachable" alone hides which host it was
            if host == GRAPH:
                edge = graph_edge()
                print(f"Graph API: connection dropped on {_graph['ip'] or 'the DNS edge'}, "
                      f"now through {edge or 'the DNS edge'}")
                if edge != _graph["ip"]:
                    _graph.update(ip=edge, since=time.time())
            time.sleep(5)


def fetch_ads(token: str, query: str | None = None, pages: int = 3, page_ids: list[str] | None = None):
    """Active ads shown in Poland: those matching `query`, or all ads of up to 10 FB pages."""
    params = {
        "access_token": token, "ad_reached_countries": '["PL"]',
        "ad_active_status": "ACTIVE", "ad_type": "ALL", "fields": FIELDS, "limit": 100,
    } | ({"search_page_ids": json.dumps(page_ids)} if page_ids else {"search_terms": query})
    url = f"{ADS_API}?{urllib.parse.urlencode(params)}"
    for _ in range(pages):
        page = http_json(url)
        yield from page.get("data", [])
        if not (url := page.get("paging", {}).get("next")):
            return


def ad_text(ad: dict) -> str:
    return " ".join(ad.get("ad_creative_bodies", []) + ad.get("ad_creative_link_titles", [])).lower()


def caption_text(ad: dict) -> str:
    """Captions without a query: a whole link shown as caption holds {{campaign.id}} and {{ad.name}}, which read as
    domains (.id, .name are real TLDs; heca.art)."""
    return " ".join(re.sub(r"[?#]\S*", "", c) for c in ad.get("ad_creative_link_captions", [])).lower()


def ad_host(ad: dict, domain: str) -> str:
    """The advertised host itself (smyk.brand-eu.com): its registrable domain often has no website at all."""
    captions = caption_text(ad)
    return next((host for host in DOMAIN.findall(captions) if host == domain or host.endswith(f".{domain}")), domain)


def caption_url(ad: dict, domain: str) -> str:
    """The caption as an address: with its path when Meta shows one whole (reha-oferta.surveysparrow.com/s/...,
    whose bare host only asks to log in), else the advertised host's home page."""
    for caption in ad.get("ad_creative_link_captions", []):
        url = caption.strip() if "//" in caption else f"https://{caption.strip()}"
        parts = urllib.parse.urlsplit(url)
        host = (parts.hostname or "").lower()
        if (host == domain or host.endswith(f".{domain}")) and parts.path.strip("/") and not url.endswith(("...", "…")):
            return url
    return f"https://{ad_host(ad, domain)}/"


# Polish letters in a wrong encoding: the replacement mark (also read again as cp1250 "ďż˝" or cp1252 "ï¿½") and
# UTF-8 read as cp1250 ("Ä…" ą, "Ăł" ó, "Ĺ›" ś, "Ĺ‚" ł, "ĹĽ" ż) or as cp1252 ("Ã³" ó, "Å›" ś, "Å‚" ł, "Å¼" ż).
MOJIBAKE = re.compile("�|ďż˝|ï¿½|Ä[…™‡]|Ăł|Ĺ[›‚şĽ„]|Ã³|Å[›‚¼º„]")


SOCIAL = re.compile(r"facebook|instagram|tiktok|youtube|twitter|pinterest|linkedin", re.I)
SOCIAL_HOME = re.compile(r"https?://(?:www\.)?(?:facebook|instagram|tiktok|youtube|twitter|x|pinterest|linkedin)\.com/?", re.I)


def dead_socials(html: str) -> list[str]:
    """Social networks whose icon on the page links nowhere ("#", nothing, the network's home page instead of a
    profile): a shop template whose profiles were never filled in. Share and log-in buttons are "#" by design and
    skipped (mediaexpert.pl); a network linked to a profile elsewhere on the page counts as filled in (otozloto.com:
    one "#" Instagram button beside the real one)."""
    found, alive = set(), set()
    html = re.sub(r"<script\b.*?</script>", " ", html, flags=re.S | re.I)  # "i<a.length" in code is no link
    for attrs, inner in re.findall(r"<a\b([^>]*)>(.*?)</a>", html, re.S | re.I):
        text = f"{attrs} {inner[:500]}"
        if not (m := SOCIAL.search(text)) or re.search(r"shar|udost|login|log in|sign in|zaloguj|continue with", text, re.I):
            continue
        href = (h[1].strip() if (h := re.search(r"""href\s*=\s*["']([^"']*)""", attrs, re.I)) else "")
        if href in ("", "#") or href.lower().startswith("javascript") or SOCIAL_HOME.fullmatch(href):
            found.add(m[0].capitalize())
        elif SOCIAL.search(href):
            alive.add(m[0].capitalize())
    return sorted(found - alive)


def shingles(text: str) -> set[str]:
    """Runs of 5 words of a page, without numbers and domains: a clone differs in prices and its own address."""
    words = re.findall(r"[^\W\d_]+", DOMAIN.sub(" ", text[:LANDING_CHARS].lower()))
    return {" ".join(words[i:i + 5]) for i in range(len(words) - 4)}


# domain -> shingles of the page it showed, for blocked domains; filled by collect(), added to on each block
_blocked_pages: dict[str, set[str]] = {}
SAME_PAGE = 0.8  # share of 5-word runs in common; in the data clones 0.95-1.00, then nothing down to 0.62
# (glavoro.pl ~ ritualdebine.shop: only Shopify's cookie banner and policy boilerplate in common)


# Content delivery networks and site builders: one address serves thousands of sites, sharing it proves nothing.
# AWS CloudFront and Global Accelerator join daily from AWS's own list; EC2 stays, it holds scam networks (huainsa.com).
EDGE_NETS = ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",  # Cloudflare
             "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
             "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
             "23.227.38.0/23",  # Shopify
             "151.101.0.0/16", "199.232.0.0/16",  # Fastly
             "76.76.21.0/24", "216.198.79.0/24", "64.29.17.0/24", "216.150.0.0/16",  # Vercel
             "185.199.108.0/22", "199.36.158.0/24",  # GitHub Pages, Firebase
             "185.230.60.0/22", "198.185.159.0/24", "198.49.23.0/24"]  # Wix, Squarespace
AWS_RANGES = "https://ip-ranges.amazonaws.com/ip-ranges.json"
_edges = [ipaddress.ip_network(net) for net in EDGE_NETS]
SAME_SERVER = 2  # blocked domains on one address, none passed, before a new domain there goes to a human
SAME_SERVER_BLOCK = 3  # ... and blocked, unless over a year old: humans held all 10 such bad, none good
_servers: dict[str, dict] = {}  # address -> {"block": [domains], "pass": count}; filled by collect()
# Ad accounts and analytics properties in a page's code: one id on many "shops" is one owner.
# Meta and TikTok pixels get a prefix, Google ids (Analytics, Tag Manager, Ads) carry their own.
TRACKERS = [("fb:", re.compile(r"""fbq\(\s*['"]init['"]\s*,\s*['"]?(\d{12,17})|facebook\.com/tr/?\?(?:[^"'\s>]*?&(?:amp;)?)?id=(\d{12,17})"""
                               r"""|pixel_?id\W{1,8}(\d{12,17})|[?&]pxl=(\d{12,17})""", re.I)),  # Shopify: escaped JSON; ad links: pxl=
            ("tt:", re.compile(r"""ttq\.load\(\s*['"]([A-Z0-9]{20})['"]""")),
            ("", re.compile(r"\b(G-(?=[A-Z]*\d)[A-Z0-9]{10}|GTM-[A-Z0-9]{6,8}|AW-\d{9,11}|UA-\d{5,10}-\d{1,3})\b"))]
_trackers: dict[str, dict] = {}  # tracking id -> {"block": [domains], "pass": count}; filled by collect()
# A company number (NIP, EU VAT) on a domain blocked or doubted: the same firm back under a new name (
# medyknacito.pl and polecanymedyk.pl); a human looks, since one real firm may run several honest shops
_numbers: dict[str, dict] = {}  # number -> {"block": [domains], "pass": count}; filled by collect()


def aws_edges() -> list:
    with urllib.request.urlopen(AWS_RANGES, timeout=60) as response:
        prefixes = json.load(response)["prefixes"]
    return [ipaddress.ip_network(p["ip_prefix"]) for p in prefixes if p["service"] in ("CLOUDFRONT", "GLOBALACCELERATOR")]


def addresses(domain: str) -> list[str]:
    """The domain's IPv4 addresses, [] when it has none."""
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(domain, 443, socket.AF_INET)} - {"0.0.0.0"})
    except (OSError, UnicodeError):
        return []


def public(host: str) -> bool:
    """True when `host` resolves and its every address is on the open internet: a sent site must never make the
    server's browser open its neighbours (the panel, Blocky, the cloud's metadata at 169.254.169.254)."""
    try:
        found = {info[4][0].split("%")[0] for info in socket.getaddrinfo(host, 443)}
    except (OSError, UnicodeError):
        return False
    return bool(found) and all(ipaddress.ip_address(ip).is_global for ip in found)


def trackers(html: str) -> list[str]:
    """Tracking ids found in a page's code (fb:…, tt:…, G-…, GTM-…, AW-…, UA-…)."""
    return sorted({prefix + next(g for g in m.groups() if g) for prefix, pattern in TRACKERS for m in pattern.finditer(html)})


def remember(book: dict, keys: list[str], domain: str, verdict: str) -> None:
    """Notes a judged domain under each of its addresses (_servers) or tracking ids (_trackers)."""
    for key in keys:
        server = book.setdefault(key, {"block": [], "pass": 0})
        if verdict == "block":
            server["block"].append(domain)
        elif verdict == "pass":
            server["pass"] += 1


def same_server(ips: list[str], domain: str) -> list[str]:
    """Blocked domains sharing an address with this one, when the address is no CDN and serves no passed domain."""
    found = set()
    for ip in ips:
        server = _servers.get(ip)
        if (server and not server["pass"] and len(server["block"]) >= SAME_SERVER
                and not any(ipaddress.ip_address(ip) in net for net in _edges)):
            found.update(server["block"])
    return sorted(found - {domain})


def same_owner(ids: list[str], domain: str, book: dict = _trackers) -> list[str]:
    """Blocked domains sharing a tracking id (or a company number, `book` _numbers) with this one, when no passed
    domain uses it (a platform's own tag)."""
    return sorted({d for i in ids if (seen := book.get(i)) and not seen["pass"] for d in seen["block"]} - {domain})


def same_page(text: str, domain: str) -> str | None:
    """The blocked domain whose page this one copies, None when none does. Pages of a few lines (an empty shop
    template, an error) are no fingerprint."""
    if len(mine := shingles(text)) < 50:
        return None
    return next((other for other, theirs in _blocked_pages.items()
                 if other != domain and len(mine & theirs) >= SAME_PAGE * len(mine | theirs)), None)


def fingerprint(ad: dict) -> str | None:
    """Ad body as a campaign key: scammers run one text under many throwaway domains."""
    body = " ".join(ad.get("ad_creative_bodies", []))
    return body if len(body) >= 100 else None  # short texts ("Kup teraz!") are shared by honest shops too


def ad_domains(ad: dict) -> set[str]:
    # Captions only: ad bodies name impersonated brands (banks, InPost), which must never be blocked.
    return {d for host in DOMAIN.findall(caption_text(ad)) if (d := extract(host).top_domain_under_public_suffix)}


# HaGeZi's newly registered domains, one file per week of the last 35 days, refreshed daily (GPL-3.0)
NRD = "https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/domains/nrd{}.txt"
NRD_BANDS = {"7": 7, "14-8": 14, "21-15": 21, "28-22": 28, "35-29": 35}  # file -> at most this many days old
# Only registries without a date in RDAP (.eu, .io) or with a tight limit (NASK): gTLDs answer RDAP fine, and all
# 14 million names would take over a GB here; these three are about 60 000.
NRD_TLDS = (".pl", ".eu", ".io")
_young: dict[str, int] = {}  # domain -> at most this many days old, from registered_history()
_known: dict[str, int] = {}  # domain judged again -> its age then, brought up to date (look_again)
# Polish brands in new domain names (vinted-kyc.com, ipko-pl.com, inpost-km.xyz): ~18 a day in the NRD list, which
# gives what certstream would without a service reading all CT logs. The brand stands alone or next to a lure.
BRANDS = ("inpost|allegro|olx|pkobp|ipko|mbank|santander|pekao|bankmillennium|aliorbank|bnpparibas|creditagricole|blik"
          "|pocztapolska|orlen|pgnig|tauron|enea|zus|mobywatel|epuap|podatki|vinted|otomoto|biedronka|lidl|rossmann"
          "|mediaexpert|xkom|pzu|dpd|przelewy24|payu|revolut|ingbank|velobank|nestbank|citihandlowy|empik|zalando|smyk"
          "|decathlon|castorama|leroymerlin|ikea|kaufland|auchan|zabka|tmobile|polsat")
LURE = (r"(?:pl|polska|poland|pay|payment|platnosci?|doplata|oplata|weryfikacja|verify|login|logowanie|zwrot|paczka"
        r"|przesylka|dostawa|odbior|konto|bank|online|24|info|support|pomoc|secure|id|app|kurier|delivery|tracking|track)")
BRANDED = re.compile(rf"(?:^|[.-])(?:{LURE}-?)*({BRANDS})(?:-?{LURE})*(?=[.-]|$)")
_any_brand = re.compile(BRANDS)  # a cheap first pass over 2.4 million names
# Brands that are plain words abroad count only in a .pl name or next to a lure: Danish blik (oe-blik.dk, an events
# app), Dutch zus (zus-ott.online), Italian Enea, Czech smyk; a visit of 96 brand blocks found these
WORDS = {"blik", "zus", "enea", "smyk"}
_branded: dict[str, str] = {}  # new domain -> the brand in its name, from newly_registered()
# NASK's RDAP lets through about one query per cycle, while ~250 new .pl domains an hour come up: one that
# waited this long is judged with its age unknown (over 35 days: it is on no newly registered list), NASK not asked
PATIENCE = timedelta(hours=2)
_gave_up: set[str] = set()


def newly_registered() -> dict[str, int]:
    young = {}
    _branded.clear()
    for band, days in NRD_BANDS.items():  # youngest first: a name in two files keeps the lower age
        with urllib.request.urlopen(NRD.format(band), timeout=300) as response:
            for line in io.TextIOWrapper(response, encoding="utf-8", errors="replace"):
                if (domain := line.strip()).endswith(NRD_TLDS):
                    young.setdefault(domain, days)
                # only the last week: older ones were seen on earlier days
                if days == 7 and _any_brand.search(domain) and (m := BRANDED.search(domain.rsplit(".", 1)[0])) and (
                        m[1] not in WORDS or domain.endswith(".pl") or m[0].strip(".-") != m[1]):
                    _branded[domain] = m[1]
    return young


def impersonators(db: sqlite3.Connection, allowed: set[str]) -> int:
    """Blocks new domains named like a Polish brand, no ad needed (user: a queue protects nobody until a human
    looks; of the first 98 only a few were real, foreign sites); the number blocked. One without an address waits:
    the list keeps it a week, so it is tried again each day."""
    queued = 0
    for domain, brand in _branded.items():
        if domain in allowed or db.execute("SELECT 1 FROM verdicts WHERE domain = ?", (domain,)).fetchone():
            continue
        if not addresses(domain):
            continue
        if lands_on(domain) in allowed:  # the brand's own, sending people home (int-ikea.com -> ikea.com)
            continue
        reason = f"new domain named like {brand}: on the list of new domains, no ad seen"
        db.execute("INSERT INTO verdicts (domain, verdict, score, reason, seen_at, ad) VALUES (?, 'block', 0, ?, ?, ?)",
                   (domain, reason, datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    json.dumps({"age_days": {domain: 7}})))  # at most 7: the panel shows it young
        log(db, domain, "block", reason, "collector")
        queued += 1
    db.commit()
    return queued


def whois_pl_age(domain: str) -> int | None:
    """Days since registration from NASK's WHOIS (port 43), a service apart from its rate-limited RDAP."""
    try:
        with socket.create_connection(("whois.dns.pl", 43), timeout=15) as conn:
            conn.sendall(f"{domain}\r\n".encode())
            reply = b"".join(iter(lambda: conn.recv(4096), b""))
    except OSError:
        return None
    born = re.search(rb"^created:\s+(\d{4})\.(\d\d)\.(\d\d)", reply, re.M)
    return (datetime.now(timezone.utc).date() - date(*map(int, born.groups()))).days if born else None


def registered_history(db: sqlite3.Connection, fresh: dict[str, int]) -> dict[str, int]:
    """Adds today's newly registered domains to our own history and returns each one's age from it: the lists keep
    35 days, the history grows by a day each day, so NASK is asked less and less."""
    today = date.today()
    db.executemany("INSERT OR IGNORE INTO registered VALUES (?, ?)",
                   ((domain, (today - timedelta(days=days)).isoformat()) for domain, days in fresh.items()))
    db.commit()
    # older ones are established and asked of the registry as before, which keeps memory to a year's names
    since = (today - timedelta(days=ESTABLISHED_DAYS)).isoformat()
    return {domain: (today - date.fromisoformat(born)).days
            for domain, born in db.execute("SELECT domain, born FROM registered WHERE born >= ?", (since,))}


_rdap: dict[str, str] = {}


def rdap_base(tld: str) -> str | None:
    """The TLD's own RDAP server from IANA's list. rdap.org, which only redirects there, answers cloud providers'
    addresses with Cloudflare's 403: on the server every domain's age was unknown."""
    if not _rdap:  # read once per run, IANA's list changes rarely and the collector restarts on each upload
        for tlds, urls in http_json("https://data.iana.org/rdap/dns.json")["services"]:
            url = next((u for u in urls if u.startswith("https://")), urls[0]).rstrip("/")
            _rdap.update(dict.fromkeys(tlds, url))
    return _rdap.get(tld)


def has_registry(domain: str) -> bool:
    """A registry gives this domain's age: none for .eu or .de, nor for a page on a free host (netlify.app)."""
    try:
        return not domain.endswith(HOSTED) and bool(rdap_base(domain.rsplit(".", 1)[-1]))
    except (OSError, ValueError, KeyError, TypeError):  # IANA's list unreachable
        return False


def meta_refused(error: Exception) -> bool:
    """Meta's ads API answered with an error (500, a limit, the token), so the network works: judging uses no Meta."""
    return bool(re.match(rf"\d{{3}} {re.escape(ADS_API)}", str(error)))


def domain_age_days(domain: str) -> int | None:
    if domain in _young:  # newly registered: no registry asked
        return _young[domain]
    if domain in _known:  # the registration date stays: NASK refuses .pl for hours at a time
        return _known[domain]
    if domain in _gave_up or domain.endswith(HOSTED):  # waited out the registry's limit; a customer's subdomain
        return None
    # NASK sees one address only, the collector's own (on a server the server's): never WARP, never home's too,
    # two addresses at once would double its per-address limit
    try:
        base = rdap_base(domain.rsplit(".", 1)[-1])
    except (OSError, ValueError, KeyError, TypeError):  # IANA's list unreachable: not a registry's limit
        return None
    if not base:  # no RDAP for this TLD (.eu)
        return None
    try:
        events = http_json(f"{base}/domain/{domain}").get("events", [])
        born = next(e["eventDate"] for e in events if e.get("eventAction") == "registration")
        return (datetime.now(timezone.utc) - datetime.fromisoformat(born)).days
    except OSError as e:
        if str(e).startswith("429"):  # registry rate limit (NASK): a guessed "unknown age" would weaken the verdict
            if domain.endswith(".pl") and (days := whois_pl_age(domain)) is not None:
                return days
            raise
        return None  # no RDAP for this TLD (.eu) or registry down
    except (ValueError, KeyError, TypeError, StopIteration):  # no date or odd format
        return None


class Offline(Exception):
    """Our own network is down: Docker's resolver then says "no such name" of every domain.
    The cycle stops and the domains wait. Not an OSError, so no "no proof" handler on the way swallows it."""


def check_online() -> None:
    """Raises Offline when even CANARY has no address: a missing or refusing site proves nothing then."""
    try:
        socket.getaddrinfo(CANARY, 443)
    except socket.gaierror as e:
        raise Offline(f"no internet: {CANARY} does not resolve ({e})") from None


# Stylesheets are no page: mammotion.com's designers comment its CSS in Chinese ("模块间距：首页专用"), which read
# as the scam platform's 首页; of 18 首页 blocks still online, it was the only one with 首页 in CSS alone
STYLES = re.compile(r"(?is)<style\b.*?</style>")


def decoy(host: str) -> str | None:
    """Why the host's home page is no real business (a DECOY mark or "no website"), None when it looks real."""
    request = urllib.request.Request(f"https://{host}/", headers={"User-Agent": MOBILE_UA})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            page = response.read(3_000_000)
        if page[:2] == b"\x1f\x8b":  # the scam platform gzips even when not asked to
            page = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(page)
    except urllib.error.URLError as e:  # an advertised domain without an address hides where the ad really leads
        if isinstance(e.reason, socket.gaierror) and e.reason.errno in NO_ADDRESS:
            check_online()
            return "no website"
        return None
    except (OSError, http.client.HTTPException, zlib.error):  # down, TLS error, cut off: no proof either way
        return None
    text = STYLES.sub(" ", page.decode("utf-8", "replace"))
    # a break said only in a script is one of a shop platform's messages, not shown (ezakupy24.pl: "service break
    # info": "Przepraszamy, przerwa techniczna"); a page that renders it is caught by its rendered text later
    shown = MAINTENANCE.search(re.sub(r"(?is)<script\b.*?</script>", " ", text))
    return next((m[0] for m in DECOY.finditer(text) if shown or not MAINTENANCE.search(m[0])), None)


def decoy_mark(ad: dict, domain: str) -> str | None:
    """decoy() of the advertised host and of its bare domain; "no website" counts only for the host the ad shows."""
    host = ad_host(ad, domain)
    if (mark := decoy(host)) and host != domain and MAINTENANCE.search(mark):  # cms.apartamentymuseo.pl: a WordPress
        return bare if (bare := decoy(domain)) != "no website" else mark     # backend's sample post, the shop is bare
    if mark or host == domain:
        return mark
    return mark if (mark := decoy(domain)) != "no website" else None  # rejestracja.medica...com works, the bare one not


_browser = None  # one headless Chromium per run, started on first use
_playwright = None  # its driver: stopped before a new start, or every start fails
_warp = None  # the same browser's second context, through WARP: started on the first wall
WARP = os.getenv("WARP_PROXY")  # socks5://warp:1080, the warp service in compose; unset = walls go to a human
# Opens accordion, hamburger and dropdown menus so their links and texts count. Only menu toggles are pressed:
# never a link, never anything inside a form.
EXPAND_MENUS = """async () => {
    for (let i = 0, height = 0; i < 8 && height !== document.body.scrollHeight; i++) {  // lazy footers load on scroll
        height = document.body.scrollHeight;
        window.scrollTo(0, height);
        await new Promise(done => setTimeout(done, 700));
    }
    document.querySelectorAll("details").forEach(d => d.open = true);
    // 3 s at most: cameron-hair.pl has 319 comment toggles at ~0.2 s a click, the visit timed out
    const until = performance.now() + 3000;
    for (const toggle of document.querySelectorAll('button[aria-expanded="false"], [role="button"][aria-expanded="false"]:not(a),'
        + ' [data-toggle="collapse"], [data-bs-toggle="collapse"], .accordion-button, [role="tab"]')) {
        if (performance.now() > until) break;
        toggle.closest("form") || toggle.click();
    }
}"""
# Presses up to 3 legal buttons that are no links ("Polityka prywatności" on sushiicons.pl opens a drawer whose text,
# the KRS and NIP, comes from an API) and gives the text each shows anew. Never in a form, never a consent.
LEGAL_BUTTONS = """async () => {
    const seen = new Set(document.body.innerText.split("\\n")), shown = [];
    const buttons = [...document.querySelectorAll('button, [role="button"]:not(a)')].filter(b => !b.closest("form, a")
        && (b.innerText || "").trim().length < 40 && /regulamin|polityk|prywatno|privacy|terms|impressum|dane firmy/i
        .test(b.innerText || "") && !/akceptuj|zgadzam|zgoda|accept|agree|consent/i.test(b.innerText || ""));
    for (const button of buttons.slice(0, 3)) {
        button.click();
        await new Promise(done => setTimeout(done, 1500));
        for (const line of document.body.innerText.split("\\n"))
            if (!seen.has(line)) { seen.add(line); shown.push(line); }
    }
    return shown.join(" ");
}"""
# Text of the whole page, also what collapsed menus hide; scripts and styles left out. `banners` false leaves out
# what HIDE_BANNERS hid: the text the model reads, a third of whose first 2000 characters were a cookie banner.
PAGE_TEXT = """(banners = true) => {
    const body = document.body.cloneNode(true);
    body.querySelectorAll("script, style, noscript, template, svg").forEach(e => e.remove());
    if (!banners) body.querySelectorAll("[data-banner]").forEach(e => e.remove());
    body.querySelectorAll("*").forEach(e => e.append(" "));  // "Siedlce</p><p>NIP: 824..." stays two words (domtel.com.pl)
    return body.textContent.replace(/\\s+/g, " ").trim();
}"""
# Hides cookie and consent banners before the screenshot, so the shot shows the page: nothing is clicked, no consent
# given. Known consent tools by id, any other fixed or sticky box by its words. The text is read with textContent,
# which hidden elements still give.
HIDE_BANNERS = r"""() => {
    const words = /cookie|ciasteczk|consent|zgod[aęy] na|rodo|gdpr/i;
    const hidden = [...document.querySelectorAll('#onetrust-consent-sdk, #CybotCookiebotDialog, #usercentrics-root,'
        + ' #didomi-host, #qc-cmp2-container, .fc-consent-root, #cmplz-cookiebanner-container, .cky-consent-container,'
        + ' #cookie-law-info-bar, .cc-window, #cookiescript_injected')];
    for (const el of document.body.querySelectorAll("*")) {
        const position = getComputedStyle(el).position;
        const text = el.innerText || "";
        if ((position === "fixed" || position === "sticky") && text.length < 3000 && words.test(text)) hidden.push(el);
    }
    hidden.forEach(el => { el.style.setProperty("display", "none", "important"); el.dataset.banner = ""; });
    return hidden.length;
}"""
# A cookie banner links to the privacy policy of every vendor (Google, PayPal), never the shop's: its links are skipped.
# Shopify marks the whole page (html.supports-cookies), otto.de a wrapper (div.js_cookieBanner): an element holding
# most of the page's links is the page, not a banner.
LINKS = """links => links
    .filter(a => typeof a.href === "string")  // an SVG link's href is an object, which crashed the walk
    .filter(a => {
        const banner = a.closest('[id*="cookie" i], [class*="cookie" i], [id*="consent" i], [class*="consent" i]');
        return !banner || banner.querySelectorAll("a[href]").length > links.length / 2;
    })
    .map(a => [(a.textContent || a.getAttribute("aria-label") || a.title || "").trim(), a.href])"""


class Download(Exception):
    """The page is a file download: never opened, a human checks it."""


class Dead(Exception):
    """The address serves no page: an error status, no such domain, a server that refuses or sends nothing.
    An ad paid to send people there is blocked without asking a model; the message is the verdict's reason."""


# Status of the page itself: gone or broken. Not 401/403/429: bot guards answer with those.
DEAD_STATUS = {404, 410} | set(range(500, 600))
# Error text of a short page served with 200 (SPA error screens, "not found" in plain text)
ERROR_PAGE = re.compile(r"\b(?:404|not found|page not found|nie znaleziono|strona nie istnieje|bad gateway"
                        r"|error code \d{3}|service unavailable|internal server error|this page isn.t working"
                        r"|didn.t send any data|something went wrong)\b", re.I)
# Quizzes and fortune telling: a few words and buttons, ending in a sale; always for a human (awake-kundalini.org)
QUIZ = re.compile(r"\b(?:quiz|kwiz|tarot|astrolog|horoskop|wróż|numerolog|jasnowid)", re.I)
# ...but one that opens by asking your age or sex is a funnel to a subscription, blocked (the user's rule):
# "Âge : 18-24 … 50+" (justfit-pilates.com), "WYBIERZ SWÓJ WIEK" (betterme-workouts.com), "Male Female" (bitepal.app)
_MAN, _WOMAN = r"(?:mężczyzn\w*|male|m[ae]n|homme|mann)", r"(?:kobiet\w*|female|wom[ae]n|femme|frau)"
PERSONAL = re.compile(r"\b(?:1[6-9]|2\d) ?[-–] ?[23]\d\b.{0,80}?\b[3-6]\d ?(?:[-–] ?[4-7]\d\b|\+)"
                      r"|ile masz lat|wybierz (?:swój )?wiek|(?:select|choose|enter) your age|how old are you|\b(?:âge|wiek|age) ?:"
                      r"|jaka jest twoja płeć|wybierz (?:swoją )?płeć|(?:select|choose) your (?:gender|sex)|votre (?:sexe|genre)"
                      rf"|\b{_WOMAN}\W{{1,3}}{_MAN}\b|\b{_MAN}\W{{1,3}}{_WOMAN}\b", re.I | re.S)
# "My little boutique is closing, take it all at -80%": the story of fake shops run by foreign shells (liwiawarsaw.pl
# by a Dutch agency); real shops close too, so a human looks, never an automatic pass
CLOSING = re.compile(r"likwidacj\w* (?:sklepu|magazynu|butiku|firmy)|zamyka\w* (?:sklep|butik|firm|działalno)"
                     r"|zmniejsz\w* się|się zmniejsz|kończymy działalno|(?:mój|moim|mojego|nasz|naszym|naszego) mał\w+ (?:butik|sklep)", re.I)
# A cure for an ailment of the elderly: the core of Polish scam ads (prostate, knees, sugar, veins). Sold by nobody
# named or under a company number that is not real, it is blocked even on an old domain: scammers buy aged ones
HEALTH = re.compile(r"\b(?:prostat|żylak|cukrzyc|niedosłuch|aparat\w* słuchow|na stawy\b|staw\w* kolanow"
                    # joints and knees only as an ailment: a story's "jej stawy" or "kolanem w krocze" is none (fictioapp.com)
                    r"|(?:ból\w*|sztywnoś\w*|chor\w*|zapaleni\w*|problem\w* (?:ze?|ze swoimi)) (?:\w+ )?(?:stawów|stawami|stawy|kolan)"
                    r"|neuropat|nadciśnieni|ciśnieni\w* krwi|grzybic|zwyrodnie|reumat|hemoroid|łuszczyc"
                    r"|brak\w*(?: ci)? zęb|sztuczn\w* zęb|licówk|cukr\w* we krwi|poziom\w* cukru|cpap|bezdech)", re.I)  # the ailment, not a story's "ból" or "wzrok"
# A country picker built of buttons, not links (promo-storytel.com): few words, still a door onwards
PICKER = re.compile(r"\b(?:select|choose) (?:your )?country\b|\bwybierz (?:swój )?kraj\b", re.I)
# "działalność nierejestrowana": a person selling without a company, which the law allows; always for a human
UNREGISTERED = re.compile(r".{0,40}\bnierejestrowan\w*.{0,40}", re.I)
# Zero-width characters inside words dodge Meta's ad review: thousands in one scam ad (smallesttell.pro), a few when
# a normal ad was pasted from elsewhere
HIDDEN_CHARS = re.compile("[\u200b-\u200d\u2060\ufeff]")
# A long ad from a FB page nobody likes: casino ads in 18 languages behind random captions (xumi.net ->
# crystal-peak.icu). Of 31 human decisions on such ads (0 likes read, bodies >= 2000 characters) 25 blocked; the 6
# passed were captions of those same casino ads, blocked by hand elsewhere
FACELESS_CHARS = 2000
# Gambling from a FB page nobody likes, any age: "jackpot", "free spins" behind captions of bought old domains
# (mug.com -> mellowhill.bar). Of 28 human decisions on old such captions 21 blocked
GAMBLING = re.compile(r"kasyn|casino|jackpot|\bslot|free ?spins?|\d ?(?:darmow\w* )?spin(?:y|\u00f3w)\b|darmow\w* (?:spin|obrot)"
                      r"|ruletk|bukmach|automat\w* do gier|zakr\u0119\u0107|bonus\w* (?:powital|na start|\d)|\d ?(?:z\u0142|pln|\u20ac|%) bonus"
                      r"|zarzu\u0107 w\u0119dk\u0119|odbierz\w* (?:swoj\u0105 )?nagrod", re.I)
# Medicine, illness, old age from a FB page nobody likes (vitallnexa.com behind med.com, a nun's mother in a care
# home): of 182 such cards on young domains 174 blocked, humans 13 of 15
ILLNESS = re.compile(r"lekarz|doktor|lecz(?:eni|y\b|\u0105\b|nicz)|chorob|choru|dolegliw|\bb\u00f3l|\bb\u00f3le|cierpi|senior|emeryt"
                     r"|dom\w* opieki|po (?:40|50|60|70)(?:\b|-)|\b[4-8]0\+|starsz\w* (?:os[o\u00f3]b|ludzi|pan)|ci\u015bnieni|zawa\u0142"
                     r"|wzrok|s\u0142uchow|niedos\u0142uch|pami\u0119\u0107|demencj|alzheimer|parkinson|\bstaw(?:y|\u00f3w|ach)\b|kr\u0119gos\u0142up"
                     r"|nowotw|szpital|pacjent|aptek|suplement|tablet(?:k|ek)|\bleki?\b|\blek\u00f3w\b|recept", re.I)
MEDICAL_PAGE = re.compile(r"medic|doctor|hospital|pharma|vitamin|supplement|\bhealth\b(?! ?[/&] ?beauty)", re.I)
POLISH_LETTERS = "\u0105\u0107\u0119\u0142\u0144\u00f3\u015b\u017a\u017c\u0104\u0106\u0118\u0141\u0143\u00d3\u015a\u0179\u017b"


def emptiness(html: str, text: str, links: list = (), url: str = "") -> str | None:
    """Why a rendered page shows nothing an ad could be for: a decoy mark ("The website is under maintenance",
    the scam platform's 首页), an error screen, a few words, nothing at all."""
    if m := DECOY.search(html):
        return f"decoy: {m[0]}"
    if walled(html, text) or len(text) >= 300 or QUIZ.search(f"{url} {text}") or PICKER.search(text):
        return None
    if len(links) >= 3 and not ERROR_PAGE.search(text):  # a country picker (kubolo.eu): few words, doors onwards
        return None
    return f"dead page: {text[:80]}" if ERROR_PAGE.search(text) else f"the page shows almost nothing: {text[:80]}"


def shown_links(ad: dict, domain: str) -> list[str]:
    """What the panel gives a reviewer for this domain: the ad's button link, its other targets on the domain
    (one per page, 4 in all), the caption's host and the home page."""
    own = [(ad.get("links") or {}).get(domain)] + [
        href for href in ad.get("destinations", [])
        if (host := urllib.parse.urlsplit(href).hostname or "") == domain or host.endswith(f".{domain}")]
    pages = {}
    for href in filter(None, own):
        pages.setdefault(href.split("#")[0].split("?")[0], clicked(href, ad))
    # the caption's host only without a link, as on the card: event.webinarjam.com serves its pages, not "/"
    host = [] if pages else [caption_url(ad, domain)]
    return list(dict.fromkeys([*list(pages.values())[:4], *host, f"https://{domain}/"]))


def dead_link(ad: dict, domain: str, skip: str | None = None) -> str | None:
    """The first of shown_links() serving no page, as "why on url"; None when each shows something or did not load.

    Old domains too: the ads are active, mostly days old, and nobody pays to show a product that is gone.
    """
    # the button's link on another domain is that domain's page: ccc.eu only captioned superceny.club's ad
    links = [url for url in shown_links(ad, domain) if extract(url.lower()).top_domain_under_public_suffix == domain]
    # the ad's pages on a subdomain: the bare domain is a platform's home (getresponsewebsite.com), not the advertiser's
    platform = any(urllib.parse.urlsplit(url).hostname not in (domain, f"www.{domain}") for url in links)
    for url in links:
        if url == skip or (platform and url == f"https://{domain}/"):
            continue
        try:
            why = (page := visit(url, light=True)) and emptiness(*page, url=url)
        except Dead as e:
            why = str(e)
        except Download:
            continue
        if why:
            return f"{why} on {url}"
    return None


def lives(url: str) -> bool:
    """Whether the page loads and shows something: not dead, not empty, not a file."""
    try:
        return bool((page := visit(url, light=True)) and not emptiness(*page, url=url))
    except (Dead, Download):
        return False


def walled(html: str, text: str) -> bool:
    """An anti-bot wall: never solved, the domain goes to a human. DataDome (fnac.com) shows its wall in an iframe,
    so only the html tells."""
    return bool(CHALLENGE.search(text[:3000]) or FORBIDDEN.search(text[:3000])) or "captcha-delivery.com" in html[:20_000]


def unreachable(url: str, error: str) -> str | None:
    """The verdict reason when a browser error shows the address serves nothing; None when it may be our network."""
    if "ERR_NAME_NOT_RESOLVED" in error:
        try:
            socket.getaddrinfo(urllib.parse.urlsplit(url).hostname, 443)
        except socket.gaierror as e:  # no such domain; not EAI_AGAIN, a resolver hiccup on our side
            if e.errno in NO_ADDRESS:
                check_online()
                return "decoy: no website"
        return None
    for code, why in (("ERR_CONNECTION_REFUSED", "connection refused"), ("ERR_EMPTY_RESPONSE", "the server sent nothing")):
        if code in error:
            check_online()
            return f"dead page: {why}"
    return None


# Meta fills these on a real click; a cloaker shows an empty page to a visitor whose link still has the braces
MACRO = re.compile(r"\{\{\s*([\w.]+)\s*\}\}")
MACRO_VALUES = {"site_source_name": "fb", "placement": "Facebook_Mobile_Feed"}


def clicked(url: str, ad: dict) -> str:
    """The ad link as a click from the feed sends it: ids are the ad's, names a plain word. A zero-width space pasted
    after the link is no part of it (sephora.pl/singles-day-pl/ answered 404 with it)."""
    url = HIDDEN_CHARS.sub("", url)
    return MACRO.sub(lambda m: MACRO_VALUES.get(m[1], ad.get("id", "1") if m[1].endswith(".id") else "pl"), url)


# Background colours of the first three screens, [r, g, b, px²]: the look of a page, measured before any menu opens
PALETTE = """() => {
    const areas = {};
    for (const e of document.querySelectorAll("body *")) {
        const r = e.getBoundingClientRect();
        if (r.width < 40 || r.height < 20 || r.top > 3 * innerHeight || r.bottom < 0) continue;
        const c = getComputedStyle(e).backgroundColor.match(/[\\d.]+/g);
        if (!c || (c.length > 3 && +c[3] < 0.8)) continue;
        const key = c.slice(0, 3).join(",");
        areas[key] = (areas[key] || 0) + Math.min(r.width, innerWidth) * Math.min(r.height, innerHeight);
    }
    return Object.entries(areas).map(([rgb, area]) => [...rgb.split(",").map(Number), Math.round(area)]);
}"""
# [visible letters, those in the browser's own default font (no font set at all), {web font: Polish letters it shows
# but lacks}]. A fake Pitbull shop (pitbullwestshop.shop): 96% in the default font, its Lato lacking "żęć";
# 0% on the ~50 human-judged shops measured, a lacking font only on plasterios.pl (blocked). A face still loading
# draws fallback glyphs too: document.fonts.check() keeps it out (naturaldermapet.pl's Source Sans Pro, passed)
FONTS = r"""() => {
    const POLISH = "ąćęłńóśźżĄĆĘŁŃÓŚŹŻ", fams = {};
    let total = 0, plain = 0;
    for (const e of document.body.querySelectorAll("*")) {
        const own = [...e.childNodes].filter(n => n.nodeType === 3).map(n => n.textContent).join("").replace(/\s+/g, "");
        if (!own || e.closest("script,style,noscript")) continue;
        const r = e.getBoundingClientRect(), st = getComputedStyle(e);
        if (!r.width || !r.height || st.visibility === "hidden") continue;
        total += own.length;
        if (/^"?Times New Roman"?$/.test(st.fontFamily)) plain += own.length;
        const first = st.fontFamily.split(",")[0].trim().replace(/^["']|["']$/g, "");
        fams[first] = (fams[first] || "") + [...own].filter(c => POLISH.includes(c)).join("");
    }
    const ctx = document.createElement("canvas").getContext("2d");
    const width = (font, c) => { ctx.font = `40px ${font}`; return ctx.measureText(c).width; };
    const lacking = {};
    for (const [fam, letters] of Object.entries(fams)) {
        if (!letters || /^(serif|sans-serif|monospace|system-ui|Times New Roman|Arial|Helvetica)$/i.test(fam)) continue;
        if (![...document.fonts].some(f => f.family.replace(/^["']|["']$/g, "") === fam && f.status === "loaded")) continue;
        const miss = [...new Set(letters)].filter(c => document.fonts.check(`40px "${fam}"`, c)
            && width(`"${fam}", monospace`, c) === width("monospace", c) && width(`"${fam}", serif`, c) === width("serif", c));
        if (miss.length) lacking[fam] = miss.join("");
    }
    return [total, plain, lacking];
}"""
_fonts: dict[str, list] = {}  # landing url -> FONTS, from the visit that took its screenshot
_looks: dict[str, list] = {}  # landing url -> PALETTE, from the visit that took its screenshot
_shown: dict[str, str] = {}  # landing url -> its text without cookie banners, from the same visit
_landed: dict[str, str] = {}  # url -> the address it ended on after redirects, see walk()
_details: dict[str, dict] = {}  # Ad Library url -> what its "Zobacz szczegóły reklamy" box got from Meta, see ad_details()
# One-product cash-on-delivery landings: a loud red offer box, a loud yellow form box, loud green order buttons.
# px² each at least, on a 390 px wide phone (a 370 x 55 px button is 20 000)
LOUD_AREA = {"red": 20_000, "yellow": 20_000, "green": 8_000}


def loud(colors: list) -> set[str]:
    """The loud hues among the colours that cover enough of the page (LOUD_AREA)."""
    areas = Counter()
    for r, g, b, area in colors:
        hue, light, saturation = colorsys.rgb_to_hls(r / 255, g / 255, b / 255)
        if saturation < 0.5 or not 0.3 <= light <= 0.8:  # pastel, grey, near black or white: no shouting
            continue
        hue *= 360
        name = "red" if hue < 15 or hue >= 345 else "yellow" if 45 <= hue < 70 else "green" if 75 <= hue < 160 else ""
        areas[name] += area
    return {name for name, least in LOUD_AREA.items() if areas[name] >= least}


def bad_fonts(fonts: list | None) -> str | None:
    """Why a page's lettering looks thrown together (FONTS): a tenth of its text in the browser's default font, or
    a web font missing Polish letters the page shows in it; None when neither or not measured."""
    total, plain, lacking = fonts or (0, 0, {})
    if total >= 200 and plain >= total / 10:
        return f"{plain} of {total} letters in the browser's default font"
    # 3 letters at least: a WooCommerce star rating draws its "ó" in an icon font (zurelo.pl)
    if lacking := {fam: letters for fam, letters in lacking.items() if len(letters) >= 3}:
        return "a font without Polish letters: " + ", ".join(f"{fam} lacks {letters}" for fam, letters in lacking.items())
    return None


VISIT_SECONDS = 90  # a normal visit takes under 45 s (goto 30 s + scripts); page.evaluate itself has no timeout


def too_slow(signum, frame):
    raise TimeoutError


def kill_browser() -> None:
    """Kills this process's Playwright driver and Chromium: after an interrupted call they never answer again."""
    global _browser, _warp, _playwright
    parent = {}
    for stat in Path("/proc").glob("[0-9]*/stat"):
        try:
            parent[stat.parent.name] = stat.read_text().rsplit(")", 1)[1].split()[1]
        except OSError:  # ended meanwhile
            pass
    me = str(os.getpid())
    for pid in parent:
        up = parent[pid]
        while up in parent and up != me:
            up = parent[up]
        if up == me:
            try:
                os.kill(int(pid), signal.SIGKILL)
            except OSError:
                pass
    if _playwright:  # unstopped, the next sync_playwright() raised "Sync API inside the asyncio loop": 492 pages
        try:         # "did not load", blocks back to review
            _playwright.stop()
        except Exception:  # its driver is dead already: only the loop needed letting go
            pass
    _browser = _warp = _playwright = None  # the next visit starts a fresh one


# Images, video and fonts of a legal page: its text is the point (only URLs that name the type, the rest still loads).
HEAVY = re.compile(r"\.(?:png|jpe?g|gif|webp|avif|svg|ico|bmp|mp4|webm|m3u8|mp3|woff2?|ttf|otf|eot)(?:[?#]|$)", re.I)


def visit(url: str, expect: str | None = None, shot: Path | None = None,
          light: bool = False) -> tuple[str, str, list[list[str]]] | None:
    """(html, text, [link text, href]) of a page rendered like a phone in Poland; never submits anything.
    A bot wall that stays is tried once more through WARP: shops and hostings block our home address.

    `expect`: text to wait for, for pages that load their data late (the Ad Library on a fresh browser).
    `shot`: where to save a JPEG of the first screen, as a phone user sees it (cookie banners hidden); the page's
    colours go to _looks[url].
    `light`: a legal page, read for its text: no images, video or fonts and a shorter wait.
    Raises Download when the URL starts a file download instead of showing a page, Dead when it serves no page.
    """
    page = browse(url, expect, shot, light)
    if page and WARP and walled(page[0], page[1]):
        page = browse(url, expect, shot, light, warp=True) or page
    return page


PHONE = {"user_agent": MOBILE_UA, "locale": "pl-PL", "viewport": {"width": 390, "height": 844},
         "accept_downloads": False}  # a file from a scam site is never saved, let alone opened


def browse(url: str, expect: str | None, shot: Path | None, light: bool,
           warp: bool = False) -> tuple[str, str, list[list[str]]] | None:
    """visit() in the home context or, with `warp`, the one through WARP."""
    global _browser, _warp, _playwright
    # a crashed Chromium stays "started": every later page "did not load" and went to review (15:43 in again)
    if _browser is not None and not _browser.browser.is_connected():
        kill_browser()
    try:
        if _browser is None:
            _playwright = sync_playwright().start()
            chromium = _playwright.chromium  # with a window when there is a screen (Xvfb in Docker):
            _browser = chromium.launch(headless=not os.getenv("DISPLAY"),  # shops let it in more often than headless
                                       args=["--disable-dev-shm-usage"]).new_context(**PHONE)
        if warp and _warp is None:
            _warp = _browser.browser.new_context(proxy={"server": WARP}, **PHONE)
        page = (_warp if warp else _browser).new_page()
        if light:
            page.route(HEAVY, lambda route: route.abort())
    except PlaywrightError:  # no browser installed: the collector still works, only without page contents
        return None
    signal.signal(signal.SIGALRM, too_slow)
    signal.alarm(VISIT_SECONDS)
    try:
        # light: the document only; with images aborted some pages never fire "load" (viopascu.ro's terms)
        response = page.goto(url, timeout=30_000, wait_until="domcontentloaded" if light else "load")
        _landed[url] = page.url
        if expect:
            page.wait_for_function("text => document.documentElement.innerHTML.includes(text)", arg=expect,
                                   timeout=20_000)
            if url.startswith(LIBRARY.format("")) and (details := ad_details(page)):
                _details[url] = details
        else:
            if shot:  # the screenshot waits for the page to settle: images, prices, the order form
                try:
                    page.wait_for_load_state("networkidle", timeout=10_000)
                except PlaywrightError:  # chats and trackers keep some pages busy forever
                    pass
            page.wait_for_timeout(2_000 if light else 3_000)  # shops fill in prices and texts with JS after load
            if shot:  # before the menus open and the page scrolls to its footer
                try:
                    page.evaluate(HIDE_BANNERS)  # their colours do not count either
                    _looks[url] = page.evaluate(PALETTE)
                    _fonts[url] = page.evaluate(FONTS)
                    shot.parent.mkdir(parents=True, exist_ok=True)
                    page.screenshot(path=shot, type="jpeg", quality=60)
                except (PlaywrightError, OSError):  # no screenshot is no reason to lose the page
                    pass
            # a toggle that is really a link took the page elsewhere and reading it failed ("page is navigating"):
            # brykacze.pl, manualni.com went to review as "page did not load". ERR_ABORTED keeps the page
            def stay(route):
                if route.request.is_navigation_request() and route.request.frame == page.main_frame:
                    return route.abort("aborted")
                return route.fallback()
            page.route("**/*", stay)
            page.evaluate(EXPAND_MENUS)
            page.wait_for_timeout(1_000)
            page.unroute("**/*", stay)  # a bot check's own redirect, below, has to go through
        html, text = page.content(), page.evaluate(PAGE_TEXT)
        if waited := walled(html, text):  # "Proszę czekać na weryfikację żądania": a JS check often lets a browser on
            page.wait_for_timeout(10_000)
            try:
                html, text = page.content(), page.evaluate(PAGE_TEXT)
            except PlaywrightError:  # still navigating past the check: the wall is what we have
                pass
        if shot:  # the ad's landing page: the model reads it without the banners hidden for the screenshot
            try:  # banners that came after the screenshot are marked too
                page.evaluate(HIDE_BANNERS)
                _shown[url] = page.evaluate(PAGE_TEXT, False)
            except PlaywrightError:  # the full text stands in
                pass
        # the status is the wall's (403, 503), not the page's it let us on to
        if response and response.status in DEAD_STATUS and not waited:
            raise Dead(f"dead page: HTTP {response.status}")  # nginx 404, Cloudflare 502 (a challenge may say 503)
        links = page.eval_on_selector_all("a[href]", LINKS)
        site = extract(page.url).top_domain_under_public_suffix
        for frame in page.frames[1:]:  # a frameset's menu.htm (wegechatka.pl); not others' maps, videos, chats
            if extract(frame.url).top_domain_under_public_suffix == site:
                try:
                    html, text = f"{html} {frame.content()}", f"{text} {frame.evaluate(PAGE_TEXT)}"
                    links += frame.eval_on_selector_all("a[href]", LINKS)
                except PlaywrightError:  # a frame gone meanwhile
                    pass
        if not light:  # last: a button may navigate away
            try:
                text = f"{text} {page.evaluate(LEGAL_BUTTONS)}"
            except PlaywrightError:
                pass
        return STYLES.sub(" ", html), text, [link for link in links if parses(link[1])]
    except PlaywrightError as e:  # timeout, TLS error, crashed tab: no proof either way
        if "Download is starting" in str(e):
            raise Download(url) from None
        if why := unreachable(url, str(e)):
            raise Dead(why) from None
        return None
    except TimeoutError:  # a page that never answers (canadiantire.ca now and then held the collector for 18 min)
        kill_browser()
        return None
    finally:
        signal.alarm(0)
        for tab in [*(_browser.pages if _browser else []), *(_warp.pages if _warp else [])]:  # also target="_blank" ones
            tab.close()


def parses(href: str) -> bool:
    try:
        return bool(urllib.parse.urlsplit(href))
    except ValueError:  # a theme's placeholder https://[strona]/ reads as a bad IPv6 host and threw on every walk
        return False


def own_links(html: str, ad_id: str) -> list[tuple[str, str]]:
    """LINK matches of this one ad: its Library page also lists dozens of the page's other ads, each entry
    starting with its "ad_archive_id" (twistcar.eu got 119 alibaba links of other ads, none its own)."""
    found = []
    for m in re.finditer(f'"ad_archive_id":"{re.escape(ad_id)}"', html):
        end = html.find('"ad_archive_id":"', m.end())
        found += LINK.findall(html[m.end():end if end > 0 else len(html)])
    return found


FB_PAGE = re.compile(r'"page_categories":(\[[^\]]*\]),"page_like_count":(\d+)')
FB_PROFILE = re.compile(r'"page_profile_uri":"([^"]+)"')


def fb_page(html: str, ad_id: str) -> dict | None:
    """The advertiser's FB page as the ad's Library page shows it: {"likes", "categories", "profile"}, e.g.
    16 likes, ["Obutev"] (shoes) and facebook.com/61594037744659 for elevaro.eu's hair extensions.
    Only what that page already holds: more (creation date, renames) needs facebook.com itself, which Meta's
    terms forbid scraping (POMYSLY.md). This ad's own entry first, else any: the page lists one FB page's ads."""
    m = re.search(f'"ad_archive_id":"{re.escape(ad_id)}"', html)
    own = html[m.end():] if m else ""
    end = own.find('"ad_archive_id":"')
    for text in (own[:end] if end > 0 else own, html):
        if (fields := FB_PAGE.search(text)) and (profile := FB_PROFILE.search(text) or FB_PROFILE.search(html)):
            return {"likes": int(fields[2]), "categories": json.loads(fields[1]),
                    "profile": json.loads(f'"{profile[1]}"')}
    return None


def ad_details(page) -> dict | None:
    """The answer to a click on the Library page's first "Zobacz szczegóły reklamy": the advertiser's Instagram,
    likes, payer. The same call Meta's page makes for any visitor, no login (frisco.pl: friscopl, 9355)."""
    try:
        with page.expect_response(lambda r: "AdLibraryV3AdDetailsQuery" in (r.request.post_data or ""),
                                  timeout=10_000) as answer:
            page.get_by_text("Zobacz szczegóły reklamy").first.evaluate("e => e.click()")  # a banner covers it
        return answer.value.json()
    except (PlaywrightError, ValueError):  # no button (a removed ad) or no answer: the page's own data still counts
        return None


def instagram(details: dict | None) -> dict | None:
    """{"username", "followers"} of the Instagram account tied to the advertiser's FB page, from ad_details()."""
    try:
        info = details["data"]["ad_library_main"]["ad_details"]["advertiser"]["ad_library_page_info"]["page_info"]
    except (KeyError, TypeError):
        return None
    return {"username": info["ig_username"], "followers": info.get("ig_followers") or 0}         if (info or {}).get("ig_username") else None  # page_info null: crashed every cycle


def ad_link(ad: dict, domain: str) -> str | None:
    """The ad's real destination on `domain`, e.g. pl.luropprt.com/detail/emp7UctEG6Ll8tpJGTdG.

    Read from the ad's public Ad Library page, once per ad: all its targets stay in ad["destinations"],
    because a caption can lie (smyk.pl on an ad that opens bestmarketzone.shop).
    """
    if "destinations" not in ad:
        try:
            library = ad.get("id") and visit(LIBRARY.format(ad["id"]), expect=domain)
        except Dead:
            library = None
        if not library:
            return None  # not cached: the next domain of this ad tries again
        found = (urllib.parse.unquote(wrapped) if wrapped else json.loads(f'"{escaped}"')
                 for wrapped, escaped in own_links(library[0], ad["id"]))
        ad["destinations"] = list(dict.fromkeys(map(unshortened, found)))
        if page := fb_page(library[0], ad["id"]):
            ad["fb_page"] = page
            if ig := instagram(_details.pop(LIBRARY.format(ad["id"]), None)):
                page["instagram"] = ig
    for href in ad["destinations"]:
        if (host := urllib.parse.urlsplit(href).hostname or "") == domain or host.endswith(f".{domain}"):
            return href
    return None


def ascii_domain(domain: str) -> str:
    """A domain as it goes on the wire: a Polish IDN as punycode; "" for one with an emoji or other symbol, which no
    request can carry (a 👉 in a link's host crashed the collector in its HTTP header)."""
    try:
        return domain.encode("idna").decode() if all(c.isalnum() or c in ".-" for c in domain) else ""
    except UnicodeError:  # a label over 63 characters
        return ""


def hidden_domains(ad: dict) -> list[str]:
    """Domains the ad opens that its captions never show: a quiz's shop (quizgo.site -> pewnaszklarnia.pl) or a scam."""
    targets = {ascii_domain(extract(href.lower()).top_domain_under_public_suffix) for href in ad.get("destinations", [])}
    return sorted(targets - ad_domains(ad) - META - SHORTENERS - {""})  # ads stored before links were followed


def unshortened(href: str) -> str:
    """Where a shortener's link leads, by its redirects (the body is never read); the link itself when not one or
    when it does not answer."""
    if extract(href.lower()).top_domain_under_public_suffix not in SHORTENERS:
        return href
    try:
        with urllib.request.urlopen(urllib.request.Request(href, headers={"User-Agent": MOBILE_UA}), timeout=15) as response:
            return response.geturl()
    except (OSError, ValueError, http.client.HTTPException):
        return href


def lying_caption(ad: dict) -> list[str]:
    """hidden_domains() when the ad opens none of the domains its captions show (smyk.pl -> bestmarketzone.shop)."""
    targets = {extract(href.lower()).top_domain_under_public_suffix for href in ad.get("destinations", [])}
    return [] if targets & ad_domains(ad) else hidden_domains(ad)


def no_likes(ad: dict) -> bool:
    """The ad's FB page read with 0 likes. Only a FB page's 0: an Instagram account or a FB profile ("Profile",
    Vichy) always shows 0, and a page not found is no 0 at all."""
    page = ad.get("fb_page") or {}
    return (page.get("likes") == 0 and "facebook.com/" in page.get("profile", "")
            and not {"Profile", "Profil"} & set(page.get("categories") or []))


def unliked(ad: dict) -> tuple[bool, str] | None:
    """(even an old domain, why) for an ad from a FB page with 0 likes read and a sign of a scam behind it."""
    if not no_likes(ad):
        return None
    page = ad.get("fb_page") or {}
    categories = page.get("categories") or []
    if (n := len("".join(dict.fromkeys(filter(None, ad.get("ad_creative_bodies") or []))))) >= FACELESS_CHARS:
        return True, f"{n}-character ad from a FB page with 0 likes"
    text = ad_text(ad)
    if m := GAMBLING.search(text):
        return True, f"gambling ({m[0]}) from a FB page with 0 likes"
    if m := HEALTH.search(text) or ILLNESS.search(text) or MEDICAL_PAGE.search(" ".join(categories)):
        return False, f"medicine, illness or old age ({m[0]}) from a FB page with 0 likes"
    name = ad.get("page_name") or ""
    if foreign := "".join(dict.fromkeys(c for c in name if ord(c) > 127 and c.isalnum() and c not in POLISH_LETTERS)):
        return False, f"FB page {name} with foreign letters ({foreign}) and 0 likes"
    return None


# <meta http-equiv="refresh" content="0; url=https://booksy.com/biz/">: a redirect in the page, not the headers
META_REFRESH = re.compile(r"""<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["']?\d+\s*;\s*url=([^"'>\s]+)""", re.I)


def lands_on(source: str) -> str | None:
    """The domain `source`'s home page ends on after its redirects, a meta refresh too (booksy.biz -> booksy.com);
    None when it does not answer."""
    try:
        with urllib.request.urlopen(urllib.request.Request(f"https://{source}/", headers={"User-Agent": MOBILE_UA}),
                                    timeout=15) as response:
            url = response.geturl()
            if m := META_REFRESH.search(response.read(20_000).decode("utf-8", "ignore")):
                url = urllib.parse.urljoin(url, html_lib.unescape(m[1]))
            return extract(url).top_domain_under_public_suffix
    except (OSError, ValueError, http.client.HTTPException):
        return None


def served_text(url: str) -> str:
    """The page's text as the server sends it, before its scripts run; "" when it does not answer.
    kwant.net.pl's script shows the same branch picker on every address, its NIP stands only in this HTML."""
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": MOBILE_UA}),
                                    timeout=15) as response:
            page = response.read(5_000_000).decode("utf-8", "ignore")
    except (OSError, ValueError, http.client.HTTPException):
        return ""
    page = re.sub(r"(?is)<(script|style|noscript|template|svg)\b.*?</\1>", " ", page)
    return re.sub(r"\s+", " ", html_lib.unescape(re.sub(r"<[^>]+>", " ", page))).strip()


def forwards(source: str, target: str) -> bool:
    """Whether `source`'s home page sends visitors on to `target`: one firm's two domains (e-foc.pl -> fiveoclock.eu). A scam cannot make the brand it shows do that (wedel.pl stays on wedel.pl)."""
    return lands_on(source) == target


def caption_typo(ad: dict, domain: str) -> bool:
    """Whether each caption is the landing domain's own name mistyped, with Polish letters (pełnadoba.pl for
    pelnadoba.pl) or another suffix (skihero.pl for skihero.com.pl), serving no site, and the FB page bears the name:
    the advertiser's slip, for a human. smyk.pl on smyk.shop stays hidden: smyk.pl is a site."""
    name = "".join(word_list(extract(domain).domain))
    hosts = [urllib.parse.urlsplit(c.strip() if "//" in c else f"https://{c.strip()}").hostname or ""
             for c in ad.get("ad_creative_link_captions", [])]
    return len(name) >= 4 and name in "".join(word_list(ad.get("page_name") or "")) and bool(hosts) and all(
        "".join(word_list(extract(host).domain)) == name and lands_on(host) is None for host in set(hosts))


LOOKALIKE = set("АВЕЅІЈКМНОРСТХҮаеіјорсхуѕԁԛԝΑΒΕΖΗΙΚΜΝΟΡΤΥΧοα")  # Cyrillic and Greek letters drawn like Latin ones
# The Chinese shop platform names its FB pages after the domain: Rrieceffa-store, Dalalecca-buy (17 of 19 blocked)
THROWAWAY_PAGE = re.compile(r"[a-z]+[-.](?:store|shop|mall|buy|bazaar)(?: pl)?", re.I)
# A made-up expert: 11 of 11 such pages on a shop not named after them were scams (Dr Piotr Nowak, ondyna-pl.com)
DOCTOR = re.compile(r"^\W*(?:dr|doktor|lek|prof)\b", re.I)
TITLES = {"dr", "doktor", "lek", "prof", "med", "hab", "inz"}
# A Polish name on a foreign ending (essanova-pl.co, hover-polska.com): a pass goes to a human,
# as real brands do it too (your-bedrock-pl.com)
POLISH_ABROAD = re.compile(r"(?:-pl|polska|poland)\.[^.]+(?:\.[^.]+)?$")


def fake_page(name: str, domain: str = "") -> str | None:
    """Why the ad's FB page name is made to deceive, None when it looks like any page's."""
    if domain and DOCTOR.match(name):  # Dr Irena Eris, Dr.Max, a doctor's own practice: their name is in the domain
        site = "".join(word_list(domain))
        if not any(word in site for word in word_list(name) if len(word) >= 3 and word not in TITLES):
            return "a doctor's name on a shop not named after them"
    if any(c.isalpha() and unicodedata.normalize("NFKC", c) != c for c in name):
        return "letters in a fancy font"  # 𝖡𝗂𝖾𝖽𝗋𝗈𝗇𝗄𝖺: people read Biedronka, filters see no such word
    found = re.findall(r"\w+", name)
    kinds = [{unicodedata.name(c, "").split(" ")[0] for c in word if c.isalpha()} for word in found]
    latin = any("LATIN" in kind for kind in kinds)  # "Твой обменник Velnox" is Russian with a brand, no disguise
    for word, kind in zip(found, kinds):
        if latin and kind & {"CYRILLIC", "GREEK"} and ("LATIN" in kind or set(word) <= LOOKALIKE):
            return "Cyrillic or Greek letters posing as Latin ones"  # ЅMҮК'Moda Dziecięca, the Smyk impersonation
    return "a throwaway shop's page name" if THROWAWAY_PAGE.fullmatch(name.strip()) else None


LOCALE = re.compile(r"^/([a-z]{2}(?:[-_][a-z]{2})?)(?:/|$)", re.I)  # /de-CH/service/contact


def locale(url: str) -> str | None:
    return m[1].lower().replace("_", "-") if (m := LOCALE.match(urllib.parse.urlsplit(url).path)) else None


COUNTRY_ORDER = ("pl", "uk", "gb", "us", "en")  # where to look for the company when the ad's page names none


def country_code(href: str, domain: str) -> str | None:
    """The country or language of a version of the site: pl.x.eu, x.eu/pl/, x.eu/en-gb/ (gb); None for others."""
    parts = urllib.parse.urlsplit(href)
    host = (parts.hostname or "").lower()
    if host != domain and not host.endswith(f".{domain}"):
        return None
    label = host[:-len(domain)].rstrip(".")
    if re.fullmatch(r"[a-z]{2}", label):
        return label
    return (found := locale(href)) and found.split("-")[-1] if label in ("", "www") else None


def country_version(domain: str, walked: str) -> str | None:
    """The Polish, else British or American version linked from a country picker on the home page (homeandmarker.eu:
    20 flags, pl./de./it.), other than the one already `walked`."""
    try:
        page = visit(f"https://{domain}/", light=True)
    except (Dead, Download):
        return None
    codes = {}
    for _, href in page[2] if page else []:
        if code := country_code(href, domain):
            codes.setdefault(code, href)
    if len(codes) < 3:  # one or two languages are a switch, not a picker
        return None
    done = country_code(walked, domain)
    return next((codes[code] for code in COUNTRY_ORDER if code in codes and code != done), None)


def is_info(label: str, href: str) -> bool:
    # the path only: query strings carry random tokens (flipkart.com ?ctx=eyJ...) that look like any short word
    return href.startswith("http") and bool(INFO_PAGE.search(f"{label} {urllib.parse.urlsplit(href).path}"))


def walk(url: str, shot: Path | None = None, everything: bool = False) -> tuple[str, str, list[str]] | None:
    """(html, text, manual) of the landing page and, until company details and a company number turn up, its legal
    and contact pages: the number often stands only in the terms or the privacy policy (wipcool.pl, slovvianki.sklep.pl).

    Legal links found on legal pages are followed too (Regulaminy -> Regulamin sklepu), up to 8 pages.
    `manual` lists what a human has to check, as "label -> link": files (a terms PDF), never opened, and, when no
    company turned up, the legal pages left unopened over the limit. `shot`: screenshot of the landing page.
    `everything`: read on past the company details, for a registry name the page with the number leaves out.
    """
    try:
        landing = visit(url, shot=shot)
    except Download:
        return "", "", [f"the ad link itself downloads a file -> {url}"]
    if not landing:
        return None
    html, text, links = landing
    seen, manual, unopened, files = {url.split("#")[0]}, [], {}, set()
    # the ad's domain and the one it sends people on to: dawidkarierowo.com opens salespros.pl, whose privacy
    # policy holds the NIP; with the first one alone those legal links looked foreign
    final = _landed.pop(url, url)
    _landed.clear()  # the legal pages' own entries from earlier walks: only the landing's is ever read
    sites = {extract(url).top_domain_under_public_suffix, extract(final).top_domain_under_public_suffix}
    # landing links first, Impressum and terms before cookies (stable: page order otherwise), then those on legal pages
    queue = sorted(links, key=lambda link: not NUMBER_PAGE.search(f"{link[0]} {urllib.parse.urlsplit(link[1]).path}"))
    # Stay in one language version: the ad's, else Polish, else the one most legal links lead to (signia.net/en/).
    versions = [found for label, href in links if is_info(label, href) and (found := locale(href))]
    home = locale(url) or next((v for v in versions if v.startswith("pl")), None) or (
        max(set(versions), key=versions.count) if versions else None)
    # An entry page (country picker on bestbuy.com, age gate) has a few links and no legal one: they are doors,
    # opened like legal pages so the legal links behind them count.
    doors = set() if versions or len(links) > 20 or any(is_info(*link) for link in links) else {
        href.split("#")[0] for _, href in links}
    # last, the home page: its footer may link a policy the product page leaves out (maasloop.com)
    parts = urllib.parse.urlsplit(url)
    if (front := f"{parts.scheme}://{parts.netloc}/") not in seen:
        queue.append(("", front))
        doors.add(front)
    # only after new text: 6000 links x 0.25 s on 220.lv took 17 minutes
    named, numbered = identified(company(text)), bool(company_number(text))
    while queue and (everything or not (named and numbered)):
        label, href = queue.pop(0)
        href = href.split("#")[0]
        if href in seen or href in unopened or href in files or not (is_info(label, href) or href in doors):
            continue
        if (extract(href).top_domain_under_public_suffix not in sites | POLICY_HOSTS) and not FILE.search(href):
            continue  # cookie banners link to the privacy policy of every vendor (Google, PayPal)
        if (other := locale(href)) and other != home:
            continue  # the same page in other countries (signia.net/de-CH/...) would use up the page limit
        if FILE.search(href):  # never opened, so no page of the limit (budma.pl: 6 PDF terms used it up before Kontakt)
            files.add(href)
            manual.append(f'file, not opened "{label[:60]}" -> {href}')
            continue
        if len(seen) > 8:
            unopened[href] = f'legal page over the limit, not opened "{label[:60]}" -> {href}'
            continue
        seen.add(href)
        try:
            try:
                page = visit(href, light=True)
            except Dead:  # a broken legal link says nothing about the landing page
                page = None
            if page:
                html, text = html + page[0], f"{text}\n{page[1]}"
                if extract(href).top_domain_under_public_suffix not in POLICY_HOSTS:  # not iubenda's own policy
                    queue += page[2]
                named, numbered = identified(company(text)), bool(company_number(text))
            elif href != front:  # big shops' bot guards cut every page after the first (galaxus.ch, komplett.no)
                manual.append(f'legal page did not load "{label[:60]}" -> {href}')
        except Download:  # a link with no file ending that downloads one all the same
            manual.append(f'file, not opened "{label[:60]}" -> {href}')
    if not numbered:  # the browser saw no number: the server's own HTML may hold it (kwant.net.pl)
        for href in [h for h in seen if not FILE.search(h)][:9]:
            if company_number(served := served_text(href)):
                text = f"{text}\n{served}"
                named = identified(company(text))
                break
    return html, text, manual + ([] if named else list(unopened.values())[:5])


def company(text: str) -> list[str]:
    """Kinds of company details on the site: honest shops publish them, throwaway scam shops rarely do."""
    own = THIRD_PARTY_IDS.sub(" ", THIRD_PARTY.sub(" ", text))  # not the UOKiK address or PayU's KRS in the terms
    no_ids = re.sub("|".join(f"(?:{COMPANY[kind]})" for kind in REGISTRY), " ", own, flags=re.I)  # RCS 904 295 003
    no_nip = re.sub(COMPANY["NIP"], " ", own, flags=re.I)  # VAT PL... is the NIP, not a second, foreign number
    texts = {"phone": no_ids, "foreign registry": no_nip}
    return [kind for kind, pattern in COMPANY.items() if re.search(pattern, texts.get(kind, own), re.I)]


def company_excerpt(text: str) -> str:
    """About 300 characters around the site's own company number, else its legal form: what the model gets to see
    of the company, which stands in the footer or the terms, past the 2000 characters it reads (kwant.net.pl)."""
    own = THIRD_PARTY_IDS.sub(" ", THIRD_PARTY.sub(" ", text))
    for kind in ("NIP", "KRS", "REGON", "legal form"):
        if m := re.search(COMPANY[kind], own, re.I):
            return own[max(0, m.start() - 200):m.end() + 100].strip()
    return ""


def identified(details: list[str]) -> bool:
    """Whether the details name a real company: a registry number, or a legal form with an address."""
    return bool(REGISTRY & set(details)) or {"legal form", "address"} <= set(details)


# MF VAT payers list, free and without a key (gov.pl/web/kas/api-wykazu-podatnikow-vat): the status alone allows
# 50 000 queries a day, the company name only 100; past a limit MF blocks the API and its web search until midnight.
VAT_STATUS = "https://wykazpodatnikowvat.mf.gov.pl/api2/status/nip/{}?date={}"
WHITE_LIST = "https://wykazpodatnikowvat.mf.gov.pl/api/search/nip/{}?date={}"
# the documented API on its own host: the server got 403 from the shield in front of the two above
BACKUP_LIST = "https://wl-api.mf.gov.pl/api/search/nip/{}?date={}"
# per process: the collector, the one judging again and the panel count apart from one address, together under
# 100, and the user's own searches on the MF site need some too
SEARCHES_PER_DAY = 30
_searches: dict[str, int] = {}  # date -> name lookups made that day
NIP_WEIGHTS = (6, 5, 7, 2, 3, 4, 5, 6, 7)
LEGAL_FORM_PL = re.compile(r"spółka (?:z ograniczoną odpowiedzialnością|akcyjna|komandytowo-akcyjna|komandytowa"
                           r"|jawna|partnerska|cywilna)|spółka"
                           r"|\b(?:е?оод|е?ад|ооо|тов)\b", re.I)  # the site writes "sp. z o.o.", MF in full; BG/RU/UA
# VIES gives a Bulgarian firm in Cyrillic, its Polish shop writes it in Latin letters (inaessentials.pl)
CYRILLIC = str.maketrans({**dict(zip("абвгдезийклмнопрстуфхъыьэюяёіїєґ", "abvgdezijklmnoprstufhayyeuaeiieg")),
                          "ж": "zh", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "sht", "ю": "yu", "я": "ya"})


def word_list(text: str) -> list[str]:
    """Lower-case Latin words without Polish letters: "ŁÓDŹ" on the list is "Lodz" on many sites, "ИНА" is "ina"."""
    plain = unicodedata.normalize("NFKD", text.casefold().replace("ł", "l").translate(CYRILLIC))
    return re.findall(r"\w+", "".join(c for c in plain if not unicodedata.combining(c)))


def words(text: str) -> set[str]:
    return set(word_list(text))


def mf_subject(url: str, nip: str, day: str) -> dict | None:
    try:
        return http_json(url.format(nip, day))["result"]["subject"] or {}
    except (OSError, KeyError, TypeError):  # limit used up, MF down: no proof either way
        return None


def vat_subject(nip: str) -> dict | None:
    """The NIP on the MF white list: statusVat, plus the name while today's lookups last.

    {} when the list has no such NIP, None when MF did not answer.
    """
    day = str(datetime.now(timezone.utc).date())
    if (subject := mf_subject(VAT_STATUS, nip, day)) is None and _searches.get(day, 0) < SEARCHES_PER_DAY:
        _searches[day] = _searches.get(day, 0) + 1  # a search there: the same daily limit as the names
        return mf_subject(BACKUP_LIST, nip, day)
    if not subject or subject.get("statusVat") == "Niezarejestrowany":
        return subject
    if _searches.get(day, 0) < SEARCHES_PER_DAY:
        _searches[day] = _searches.get(day, 0) + 1
        subject |= mf_subject(WHITE_LIST, nip, day) or {}
    return subject


# GUS REGON (BIR1.1): every Polish business, VAT payer or not; free key from GUS in .env as GUS_KEY
BIR = os.getenv("GUS_BIR_URL", "https://wyszukiwarkaregon.stat.gov.pl/wsBIR/UslugaBIRzewnPubl.svc")
GUS_KEY = os.getenv("GUS_KEY")


def bir(action: str, body: str, sid: str = "") -> str:
    """One SOAP call to GUS BIR1.1; the result unescaped, "" when there is none (also on a bad session)."""
    envelope = ('<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:ns="http://CIS/BIR/PUBL/2014/07"'
                ' xmlns:dat="http://CIS/BIR/PUBL/2014/07/DataContract"><soap:Header'
                f' xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:To>{BIR}</wsa:To><wsa:Action>'
                f"http://CIS/BIR/PUBL/2014/07/IUslugaBIRzewnPubl/{action}</wsa:Action></soap:Header>"
                f"<soap:Body><ns:{action}>{body}</ns:{action}></soap:Body></soap:Envelope>")
    request = urllib.request.Request(BIR, envelope.encode(), {"Content-Type": "application/soap+xml; charset=utf-8",
                                                              "sid": sid})
    with urllib.request.urlopen(request, timeout=30) as response:  # MTOM: the XML sits inside a MIME part
        reply = response.read().decode("utf-8", "replace")
    return unescape(m[1]) if (m := re.search(f"<{action}Result>(.*?)</{action}Result>", reply, re.S)) else ""


def gus_subject(number: str, kind: str = "Nip") -> dict | None:
    """{"name", "ended", "nip"} of the business under this NIP (or `kind` "Regon", "Krs": a site giving no NIP);
    {} when REGON has none; None without a key or an answer."""
    if not GUS_KEY:
        return None
    try:  # a new session per lookup (2 calls), fine for a few NIPs an hour; keep the sid if that grows
        sid = bir("Zaloguj", f"<ns:pKluczUzytkownika>{GUS_KEY}</ns:pKluczUzytkownika>")
        found = bir("DaneSzukajPodmioty", f"<ns:pParametryWyszukiwania><dat:{kind}>{number}</dat:{kind}>"
                                          "</ns:pParametryWyszukiwania>", sid) if sid else ""
    except (OSError, http.client.HTTPException):
        return None
    # one NIP may hold several entries: the live one, not an old one struck off (ozonee.pl: Alpha Fashion sp.k.
    # active, Alpha Fashion AR sp. z o.o. ended 2017), as ceidg_subject() does it
    entries = [dict(re.findall(r"<(\w+)>([^<]*)</\1>", block)) for block in re.findall(r"<dane>.*?</dane>", found, re.S)]
    fields = next((e for e in entries if e.get("Nazwa") and not e.get("DataZakonczeniaDzialalnosci")), None) or (
        entries[0] if entries else dict(re.findall(r"<(\w+)>([^<]*)</\1>", found)))
    if fields.get("Nazwa"):
        return {"name": fields["Nazwa"], "ended": fields.get("DataZakonczeniaDzialalnosci", ""), "nip": fields.get("Nip", ""),
                "regon": fields.get("Regon", "") if fields.get("Typ") == "P" else ""}  # P: a company, in KRS
    return {} if fields.get("ErrorCode") == "4" else None  # 4: no such entity


CEIDG = "https://dane.biznes.gov.pl/api/ceidg/v3/firma?nip={}"  # sole traders, free with a token from that site
CEIDG_TOKENS = [t for t in (os.getenv("CEIDG_TOKEN"), os.getenv("CEIDG_TOKEN2")) if t]  # second account: taken in turn
CEIDG_GAP, CEIDG_PAUSE = 3.6, 180  # per token: 3.6 s between calls (1000 an hour), and 180 s stopped past that
CEIDG_STOPPED = {"ZAWIESZONY": "suspended", "WYKRESLONY": "struck off"}  # such a business may not sell
CEIDG_LIVE = {"AKTYWNY", "WYLACZNIE_W_FORMIE_SPOLKI"}  # the latter trades as a partner of a civil partnership (lullalove.com)
_ceidg: dict[str, dict] = {}  # nip -> entry: a second ad of the same shop asks no more
_ceidg_lock = threading.Lock()
_ceidg_next: dict[str, float] = {}  # token -> when it may ask again


ANY_GOODS = re.compile(r"sprzeda\w*.*(?:niewyspecjalizowan|wysyłkow)", re.I)  # PKD 47.19, 47.91, 46.19...


def ceidg_subject(nip: str) -> dict | None:
    """A sole trader's entry: status, since when, suspension and trades (PKD, the main one first), which REGON does
    not give. {} when CEIDG has no such business (a company is in KRS); None without a token or an answer."""
    if not CEIDG_TOKENS:
        return None
    if nip in _ceidg:
        return _ceidg[nip]
    with _ceidg_lock:
        token = min(CEIDG_TOKENS, key=lambda t: _ceidg_next.get(t, 0.0))  # the one free soonest: they take turns
        time.sleep(max(0.0, _ceidg_next.get(token, 0.0) - time.monotonic()))
        _ceidg_next[token] = time.monotonic() + CEIDG_GAP
        request = urllib.request.Request(CEIDG.format(nip), headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                # one NIP keeps every business its owner ever ran: the live one, not an old one struck off (szklanka.pl)
                firm = {} if response.status == 204 else max(json.load(response)["firma"], key=lambda f: (
                    f.get("status") in CEIDG_LIVE, f.get("dataRozpoczecia") or ""))
        except urllib.error.HTTPError as e:
            if e.code == 429:  # over the hourly limit: CEIDG answers nothing for the next 180 s
                _ceidg_next[token] = time.monotonic() + CEIDG_PAUSE
            return None
        except (OSError, ValueError, KeyError, IndexError):
            return None
    main = (firm.get("pkdGlowny") or {}).get("nazwa")
    trades = [main] + [p.get("nazwa") for p in firm.get("pkd") or [] if p.get("nazwa") != main]
    _ceidg[nip] = firm and {"name": firm.get("nazwa"), "status": firm.get("status"), "since": firm.get("dataRozpoczecia"),
                            "suspended": firm.get("dataZawieszenia"), "resumed": firm.get("dataWznowienia"),
                            "pkd": [t for t in trades if t],  # a civil partnership has a NIP of its own, VAT under it
                            "partnerships": [s["nip"] for s in firm.get("spolki") or [] if s.get("nip")]}
    return _ceidg[nip]


# what a firm does, which sites shorten to letters: "PPUH Kombinat Budowlany" (kombinatbud.pl)
TRADE = re.compile(r"\b(?:przedsiębiorstw|produkcyjn|usługow|handlow|wytwórcz|zakład)\w*", re.I)


def unnamed(name: str, text: str, domain: str = "") -> bool:
    """Whether the site leaves out most of a registry name: a bank's NIP on a cream shop. Half is enough,
    "PHU ABC Jan Nowak" shortens "PRZEDSIĘBIORSTWO HANDLOWO-USŁUGOWE ABC JAN NOWAK".

    So is an address spelling the name: otozloto.com writes only "OTO ZŁOTO", REGON adds the owners of the
    "OTO ZŁOTO ADRIANNA STEC-KONIECZNY, CYNTHIA STEC SPÓŁKA CYWILNA".
    """
    name_words = word_list(TRADE.sub(" ", LEGAL_FORM_PL.sub(" ", name)))
    if len(set(name_words) & words(text)) * 2 >= len(set(name_words)):
        return False
    initials = "".join(word[0] for word in name_words)
    if len(initials) >= 3 and initials in words(text):  # "Grupa MTP": MIĘDZYNARODOWE TARGI POZNAŃSKIE (hobbycon.pl)
        return False
    label = re.sub(r"[^a-z0-9]", "", domain.split(".")[0])
    return len(label) < 5 or not any("".join(name_words[i:j]) == label
                                     for i in range(len(name_words)) for j in range(i + 1, len(name_words) + 1))


def nip_problem(text: str, domain: str = "") -> tuple[bool, str] | None:
    """(strong, why) when the site's NIP does not stand for it; strong = made up, closed or someone else's.

    A closed business's NIP is forgiven when a later one is sound: a sole trader turned into a company keeps the
    old number in the footer, the new one stands in the terms (y-s.eu, YourSkin sp. z o.o.)."""
    nips = list(dict.fromkeys("".join(re.findall(r"\d", m[0]))[-10:]
                              for m in re.finditer(COMPANY["NIP"], own_text(text), re.I)))
    if not nips or not (problem := one_nip_problem(nips[0], text, domain)) or not (old := STALE.search(problem[1])):
        return problem if nips else None
    for nip in nips[1:3]:  # each one costs registry calls
        # the successor keeps the name; a bank's or a marketplace's NIP in the terms does not stand for the shop
        entry = gus_subject(nip) or vat_subject(nip) or {}
        if name_words(old[1]) & name_words(entry.get("name") or "") and not one_nip_problem(nip, text, domain):
            return None
    return problem


# nip_problem's why for an ended business; a suspended sole trader too, when the page names the civil partnership
# she trades in with its own live NIP (grupamocy.pl: Agnieszka Kaczor Fitfreak suspended, Fitfreak s.c. live)
STALE = re.compile(r"belongs to (.+), (?:closed on |(?:struck off|suspended) in CEIDG)")


KRS_FULL = "https://api-krs.ms.gov.pl/api/krs/OdpisPelny/{}?rejestr=P&format=json"  # struck-off companies too


def krs_heir(krs: str) -> dict | None:
    """{"name", "krs"} of the company that took over one struck off by a merger (section 6 of the full court record):
    hossanova.pl's footer keeps HOSSANOVA 1, absorbed by HOSSANOVA sp. z o.o. in 2022. None: no merger, no answer."""
    try:
        events = http_json(KRS_FULL.format(krs))["odpis"]["dane"]["dzial6"].get("polaczeniePodzialPrzeksztalcenie") or []
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    for heir in (heir for event in events for heir in event.get("podmiotyPowstalePrzejmujace") or []):
        if name := ((heir.get("nazwa") or [{}])[-1].get("nazwa") or "").split(",")[0]:
            return {"name": name, "krs": ((heir.get("krs") or [{}])[-1].get("krs") or "")}
    return None


def former_names(regon: str = "", krs: str = "") -> list[str]:
    """A company's earlier names from its full KRS record: renoma-agency.pl's footer still says Beauty Marketing Agency,
    renamed Centrum Kompetencji Plus. With only the REGON, GUS's full report gives the KRS."""
    try:
        if not krs and regon and GUS_KEY:
            sid = bir("Zaloguj", f"<ns:pKluczUzytkownika>{GUS_KEY}</ns:pKluczUzytkownika>")
            report = bir("DanePobierzPelnyRaport", f"<ns:pRegon>{regon}</ns:pRegon>"
                                                   "<ns:pNazwaRaportu>BIR11OsPrawna</ns:pNazwaRaportu>", sid) if sid else ""
            krs = m[1] if (m := re.search(r"<praw_numerWRejestrzeEwidencji>(\d{10})<", report)) else ""
        if not krs:
            return []
        names = http_json(KRS_FULL.format(krs))["odpis"]["dane"]["dzial1"]["danePodmiotu"]["nazwa"]
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
        return []
    return [entry["nazwa"] for entry in names if entry.get("nrWpisuWykr") and entry.get("nazwa")]  # struck-out entries


def former_named(court: tuple[str, str], text: str, domain: str) -> str | None:
    """The former name the site gives instead of the company's current one. Not a pass on its own: a footer may name
    some other firm that once had that name, so a human looks (the user)."""
    return next((old for old in former_names(*court) if not unnamed(old, text, domain)), None)


def merged(why: str, court: str | None, text: str, domain: str) -> tuple[bool, str] | None:
    """(True, why) for a closed company, unless the site's KRS shows it was merged into another: then nothing when the
    site names the heir (old numbers left in a footer), a human otherwise."""
    own = THIRD_PARTY_IDS.sub(" ", THIRD_PARTY.sub(" ", text))
    courts = [court.split()[1]] if court and court.startswith("KRS ") else []
    # every KRS on the page, not only the first: winnicalidla.pl names Lidl's before the absorbed Delta Marketing's
    courts += ["".join(re.findall(r"\d", m[0])) for m in re.finditer(COMPANY["KRS"], own, re.I)]
    for krs in list(dict.fromkeys(courts))[:3]:  # each one costs a court call
        if heir := krs_heir(krs):
            if not unnamed(heir["name"], text, domain):
                return None
            return False, f"{why}: merged into {heir['name']} (KRS {heir['krs']})"
    return True, why


def name_words(name: str) -> set[str]:
    return words(TRADE.sub(" ", LEGAL_FORM_PL.sub(" ", name))) - {"spolka", "sp", "z", "o", "polska", "poland"}


def one_nip_problem(nip: str, text: str, domain: str) -> tuple[bool, str] | None:
    if re.search(rf"\b(?!PL)[A-Z]{{2}} ?{nip}\b", text):  # a foreign VAT number called "NIP" (dedoles.pl: SK2023541630)
        return None  # VIES checks it as a foreign registry
    if sum(int(d) * w for d, w in zip(nip, NIP_WEIGHTS)) % 11 != int(nip[9]):
        for country in foreign_vat(nip):  # a foreign VAT number written without its prefix: VIES says whose
            try:
                answer = vies(country, nip)
            except (OSError, ValueError):
                return None
            if answer.get("isValid"):
                if (name := answer.get("name", "---")) != "---" and unnamed(name, text, domain):
                    return True, f"VAT {country}{nip} belongs to {name}, the site never names it"
                return None
            if answer.get("userError") != "INVALID":
                return None  # the country did not answer: no proof either way
        return True, f"NIP {nip} is made up: wrong check digit"
    # REGON knows every Polish business, the MF list is the fallback: a foreign firm registered for Polish VAT has
    # a NIP and no REGON (MH HANDEL GMBH on aosom.pl, UAB HARMONY LIFE; 5 shops were "in no register")
    if entry := gus_subject(nip):
        if THIRD_PARTY.match(entry["name"]):  # the host's number, too far from its name to be cut (drgania.sklep.pl)
            return None
        if entry["ended"]:
            return merged(f"NIP {nip} belongs to {entry['name']}, closed on {entry['ended']}", court_number(text), text, domain)
        name, court = entry["name"], (entry.get("regon", ""), "")
    elif (subject := vat_subject(nip)) is None:  # MF did not answer: REGON's "none" stands alone
        return (True, f"NIP {nip} is in no Polish business register (GUS REGON)") if entry == {} else None
    elif not subject and entry == {}:
        return True, f"NIP {nip} is in no Polish business register (GUS REGON, MF VAT list)"
    elif not subject:  # a small VAT-exempt firm may be missing too: a human looks
        return False, f"NIP {nip} is not on the MF VAT white list"
    elif subject.get("statusVat") == "Niezarejestrowany":
        return False, f"NIP {nip} ({subject.get('name')}) was removed from the VAT register"
    else:
        name, court = subject.get("name") or "", ("", subject.get("krs") or "")  # empty when today's MF name lookups ran out
    if unnamed(name, text, domain):
        if old := former_named(court, text, domain):
            return False, f"NIP {nip} belongs to {name}, the site names only its former name {old} (KRS), a human looks"
        return True, f"NIP {nip} belongs to {name}, the site never names it"
    if (trader := ceidg_subject(nip)) and (stopped := CEIDG_STOPPED.get(trader["status"])):
        return True, f"NIP {nip} belongs to {trader['name']}, {stopped} in CEIDG"
    return None


@functools.lru_cache(maxsize=8)
def own_text(text: str) -> str:
    """The text without couriers', payment firms' and offices' details. Once per text: THIRD_PARTY takes 4 ms on a
    saved page, and the panel's card asked it three times, 1294 cards took 145 s of the server's CPU."""
    return THIRD_PARTY_IDS.sub(" ", THIRD_PARTY.sub(" ", text))


def court_number(text: str) -> str | None:
    """"KRS 0000123456" or "REGON 123456789", the first past other firms' ones: what a site giving no NIP names
    itself by (many more give a NIP beside it)."""
    own = own_text(text)
    for kind in ("KRS", "REGON"):
        if m := re.search(COMPANY[kind], own, re.I):
            return f"{kind} {''.join(re.findall(r'\d', m[0]))}"
    return None


REGON_WEIGHTS = (8, 9, 2, 3, 4, 5, 6, 7)


def nip_behind(court: str) -> str | None:
    """The NIP GUS REGON holds for a court_number() ("KRS …", "REGON …"); None when it has none or did not answer.
    Wherever it is shown, "no NIP on the site" goes with it (the user): the law wants the NIP in the offer."""
    kind, number = court.split()
    return (gus_subject(number, kind.capitalize()) or {}).get("nip") or None


def registry_problem(text: str, domain: str = "") -> tuple[bool, str] | None:
    """(strong, why) when the site's KRS or REGON does not stand for it in GUS REGON; like nip_problem().
    The why says the site gives no NIP, and names the one GUS holds when there is one."""
    if not (found := court_number(text)):
        return None
    kind, number = found.split()
    if kind == "REGON" and sum(int(d) * w for d, w in zip(number, REGON_WEIGHTS)) % 11 % 10 != int(number[8]):
        return True, f"REGON {number} (no NIP on the site) is made up: wrong check digit"
    if not (entry := gus_subject(number, kind.capitalize())):
        return (True, f"{found} (no NIP on the site) is in no Polish business register (GUS REGON)") if entry == {} else None
    label = f"{found} (no NIP on the site; GUS gives NIP {entry['nip']})" if entry.get("nip") else f"{found} (no NIP on the site)"
    if entry["ended"]:
        return merged(f"{label} belongs to {entry['name']}, closed on {entry['ended']}", found, text, domain)
    court = ("", number) if kind == "KRS" else (entry.get("regon", ""), "")
    if unnamed(entry["name"], text, domain):
        if old := former_named(court, text, domain):
            return False, f"{label} belongs to {entry['name']}, the site names only its former name {old} (KRS), a human looks"
        return True, f"{label} belongs to {entry['name']}, the site never names it"
    return None


VIES = "https://ec.europa.eu/taxation_customs/vies/rest-api/ms/{}/vat/{}"  # EU VAT numbers, free, no key


def vies(country: str, number: str) -> dict:
    """VIES's answer, asked up to 3 times while the country is busy with other askers: RO39167080 answered on the
    second try, 3 of 21 queued numbers were MS_MAX_CONCURRENT_REQ on one try."""
    for wait in (2, 4, 0):
        answer = http_json(VIES.format(country, number))
        if answer.get("userError") not in ("MS_MAX_CONCURRENT_REQ", "GLOBAL_MAX_CONCURRENT_REQ") or not wait:
            return answer
        time.sleep(wait)
# A VAT word, then an EU country prefix and the number: "USt-IdNr.: DE 811569869", "BTW NL123456789B01",
# also on the next line under a heading ("Numer VAT UE", then "DE815887577" below: holy.com).
# "NUMER PODATKOWY: SI 75679060" (mlandia.com), "Tax ID: ..." in English
EU_VAT = re.compile(r"(?:nip|vat|ust|tva|iva|btw|moms|mwst|dph|dič|pvm|pvn|afm|cif|nif|uid|cui|cod unic de [îi]nregistrare|tax|podatkow\w*)\b[^\n]{0,30}?\n?"
                    r"(?<![A-Za-z])(?-i:(AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PT|RO|SE|SI"
                    r"|SK|XI)) ?(?-i:([0-9A-Z]{2}[0-9 .]{5,13}[0-9][0-9A-Z]{0,3}))(?-i:(?![0-9a-z]))", re.I)  # "SI 20992882 W firmie": no W; "LT…218Adres" glued


# Shape of each country's VAT number after its prefix (VIES rules); matched at the start, as the text may run on.
VAT_FORMAT = {
    "AT": r"U\d{8}", "BE": r"[01]\d{9}", "BG": r"\d{9,10}", "CY": r"\d{8}[A-Z]", "CZ": r"\d{8,10}", "DE": r"\d{9}",
    "DK": r"\d{8}", "EE": r"\d{9}", "EL": r"\d{9}", "ES": r"[0-9A-Z]\d{7}[0-9A-Z]", "FI": r"\d{8}",
    "FR": r"[0-9A-Z]{2}\d{9}", "HR": r"\d{11}", "HU": r"\d{8}", "IE": r"\d[0-9A-Z+*]\d{5}[A-W][A-I]?",
    "IT": r"\d{11}", "LT": r"\d{12}|\d{9}", "LU": r"\d{8}", "LV": r"\d{11}", "MT": r"\d{8}", "NL": r"\d{9}B\d{2}",
    "PT": r"\d{9}", "RO": r"\d{2,10}", "SE": r"\d{12}", "SI": r"\d{8}", "SK": r"\d{10}", "XI": r"\d{9}|GD\d{3}|HA\d{3}",
}


def company_number(text: str, own: bool = True) -> str | None:
    """The first NIP or EU VAT number in a text, found as nip_problem() and vat_problem() find it; None when none.

    `own=False` keeps the text after couriers' and payment firms' names: footers put "Google Pay" or "InPost" right
    before the shop's own number (meblotico.pl), so the panel tries that too and the registry shows whose it is."""
    text = own_text(text) if own else THIRD_PARTY_IDS.sub(" ", text)  # not a courier's or PayU's number
    if m := re.search(COMPANY["NIP"], text, re.I):
        return "".join(re.findall(r"\d", m[0]))[-10:]
    return "".join(vat) if (vat := eu_vat(text)) else None


# A Spanish firm writes its CIF/NIF without the ES that VIES wants (natulim.pl: "NIF/CIF: B42864033")
ES_ID = re.compile(r"\b(?:cif|nif)\b(?:/(?:cif|nif)\b)?\W{0,3}(?-i:([A-HJNP-SUVW]\d{7}[0-9A-J]|\d{8}[A-Z]))\b", re.I)


def eu_vat(text: str) -> tuple[str, str] | None:
    """(country, number) of the first EU VAT number in a text."""
    if m := EU_VAT.search(text):
        return m[1], re.sub(r"[ .]", "", m[2])
    return ("ES", m[1]) if (m := ES_ID.search(text)) else None


def vat_malformed(country: str, number: str) -> bool:
    """A number of the wrong shape, or with a wrong check digit where the rule is public (IT, DE, FR)."""
    if not (m := re.match(VAT_FORMAT[country], number)):
        return True
    n = m[0]
    if country == "IT":  # Luhn
        return sum(d if i % 2 == 0 else d * 2 - 9 * (d > 4) for i, d in enumerate(map(int, n))) % 10 != 0
    if country == "DE":  # ISO 7064 MOD 11,10
        product = 10
        for d in map(int, n[:8]):
            product = 2 * ((d + product) % 10 or 10) % 11
        return (11 - product) % 10 != int(n[8])
    if country == "FR" and n[:2].isdigit():
        return (12 + 3 * (int(n[2:]) % 97)) % 97 != int(n[:2])
    return False


def foreign_vat(nip: str) -> list[str]:
    """EU countries whose 10-digit VAT number `nip` can be by its check digits, for a "NIP" that is no Polish one:
    a Slovak firm writes "NIP: 2120099014" without SK (Packeta Slovakia on naturu.pl). VIES is asked only
    about these, at most two, not all 27: its limits, and a made-up number would sooner hit some real firm."""
    month = int(nip[2:4])
    return [country for country, fits in (
        ("SK", nip[0] != "0" and nip[2] in "234789" and int(nip) % 11 == 0),
        ("CZ", int(nip) % 11 == 0 and any(low <= month <= low + 11 for low in (1, 21, 51, 71))),  # a birth number
        ("BE", nip[0] in "01" and 97 - int(nip[:8]) % 97 == int(nip[8:]))) if fits]


def vat_problem(text: str, domain: str = "") -> tuple[bool, str] | None:
    """(strong, why) when the site's EU VAT number does not stand for it in VIES; like nip_problem()."""
    if not (vat := eu_vat(own_text(text))):
        return None
    country, number = vat
    if vat_malformed(country, number):  # no such number can exist: made up, like a NIP with a wrong check digit
        return True, f"VAT {country}{number} is made up: wrong length or check digit"
    try:
        answer = vies(country, number)
    except (OSError, ValueError):
        return None
    if answer.get("userError") == "INVALID":  # not every small firm trades across the EU: a human looks
        return False, f"VAT {country}{number} is not valid in VIES"
    if answer.get("isValid") and (name := answer.get("name", "---")) != "---" and unnamed(name, text, domain):
        return True, f"VAT {country}{number} belongs to {name}, the site never names it"
    return None  # valid, or the country hides the name (DE) or did not answer


# llama3.2 sometimes names a scam sign and still answers scam=false ("Guaranteed profit and lack of effort").
ALARM = re.compile(r"fake|fraud|scam|phish|suspicious|deceptive|misleading|miracle|unrealistic|guaranteed|impersonat"
                   r"|made-up|too good|oszust|fa[łl]sz|podejrzan|gwarantowan"
                   r"|unproven|unsustainable|exaggerat|unregulat|unlicens|unclear terms|nierealn|niesprawdzon|przesadz"
                   r"|risk-free|no risk|bez ryzyka|bez wysiłku"  # "z gwarancją bez ryzyka" kwiatowaoaza.pl, "wygraj bez wysiłku" nmron.pl
                   # "Company details don't match advertised business": a roofer's baby creams (melalucky.pl)
                   r"|mismatch|(?:n't|not) match(?! (?:any |typical |known |common )?(?:scam|fraud|pattern))"
                   r"|niezgodn|nie pasuj"
                   # qwen passes "lacks Polish registration details" (bellmedi.pl), "registered for photography and hotels,
                   # not clothing retail" (lavastore.eu), "bankruptcy liquidation for new Philips coffee machine"
                   r"|\black(?:s|ing)?\b|registered (?:for|as) [^.]*?, not\b|liquidat|bankrupt", re.I)
DENIAL = re.compile(r"\b(?:no|not|without|nothing|isn't|doesn't|nie|brak\w*|bez|hay)\b", re.I)


# The small model repeats the prompt's "a shop with no company details" against the facts it got (exeldomy.pl)
# qwen praises "Company details confirm a legitimate business", so the bare words mean nothing
NO_COMPANY = re.compile(r"\bno (?:\w+ )?company|(?:missing|lacks?|lacking|without|incomplete|hidden)\W+(?:\w+\W+)?company details"
                        r"|company details\b[^.]{0,30}\b(?:missing|absent|incomplete|not (?:provided|found|listed|given|available))"
                        r"|without (?:a )?company|brak danych|unknown (?:company|developer)"
                        r"|\bno nip\b|nieznan\w* firm|(?:informacji|szczegółów|danych) o firmie|numer\w* identyfikac", re.I)


def contradicts(reason: str) -> bool:
    """A pass whose reason names a scam sign it does not deny earlier in the same sentence:
    "Fake shop with no company details" counts, "No clear sign of fraud" or "nie jest to oszustwo" does not."""
    return any(not DENIAL.search(re.split(r"[.!?\n]", reason[:m.start()])[-1]) for m in ALARM.finditer(reason))


def score(ad: dict, domain: str, age_days: int | None) -> int:
    points = sum(weight for pattern, weight in SIGNALS if re.search(pattern, ad_text(ad)))
    if age_days is None:
        points += 1  # registry hides the creation date
    elif age_days < 30:
        points += 3
    elif age_days < 180:
        points += 1
    return points + (domain.rsplit(".", 1)[-1] in RISKY_TLDS)


def ask_llm(ad: dict, domain: str, age_days: int | None, site: dict | None = None) -> dict | None:
    facts = {"domain": domain, "domain_age_days": age_days, "page": ad.get("page_name"), "text": ad_text(ad)}
    if fb := ad.get("fb_page"):
        facts |= {"fb_page_category": fb["categories"], "fb_page_likes": fb["likes"]}
    facts |= site or {}  # landing page text and company details, when the browser got there
    body = {
        "model": MODEL, "stream": False, "format": LLM_SCHEMA,
        "think": False,  # thinking models (Qwen3) answer many times slower and the verdict is no better
        "options": {"temperature": 0, "num_ctx": 8192}  # ad, page and every PKD of a sole trader; 128k needs 30+ GB
                   | ({"num_gpu": int(NUM_GPU)} if NUM_GPU else {}),
        "messages": [
            {"role": "system", "content": LLM_PROMPT},
            {"role": "user", "content": json.dumps(facts, ensure_ascii=False)},
        ],
    }
    try:
        answer = json.loads(http_json(f"{OLLAMA}/api/chat", body, timeout=300)["message"]["content"])
    except (OSError, ValueError, KeyError):
        return None
    return answer if isinstance(answer, dict) and isinstance(answer.get("scam"), bool) else None


PKD_PROMPT = """You check one claim. A Polish sole trader is registered for the listed kinds of business (PKD codes).
Each kind is a broad category: it covers every product or service that reasonably falls under it, sold online or in
person (sports education covers swimming lessons, food retail covers honey, publishing covers e-books).
First say in a few words what the ad sells, then copy exactly the one kind from the list that covers it,
or give an empty string when none of them does."""
PKD_SCHEMA = {"type": "object", "properties": {"ad_sells": {"type": "string"}, "covered_by": {"type": "string"}},
              "required": ["ad_sells", "covered_by"]}


def pkd_covers(ad: dict, domain: str, pkd: list[str]) -> str:
    """The PKD from the list the model names as covering what the ad sells; "" for a name not on the list, or no
    answer (the first verdict stands)."""
    facts = {"ad": ad_text(ad)[:1500], "page": (ad.get("landing") or {}).get(domain, "")[:800], "registered_activities": pkd}
    body = {"model": MODEL, "stream": False, "format": PKD_SCHEMA, "think": False,
            "options": {"temperature": 0, "num_ctx": 8192} | ({"num_gpu": int(NUM_GPU)} if NUM_GPU else {}),
            "messages": [{"role": "system", "content": PKD_PROMPT},
                         {"role": "user", "content": json.dumps(facts, ensure_ascii=False)}]}
    try:
        name = json.loads(http_json(f"{OLLAMA}/api/chat", body, timeout=300)["message"]["content"])["covered_by"]
    except (OSError, ValueError, KeyError, TypeError):
        return ""
    return next((p for p in pkd if isinstance(name, str) and name.strip().lower() == p.lower()), "")


# domain -> (link, site) walked while the LLM was down: the retry next cycle reuses them instead of walking again.
# at most 100 kept (a site holds its pages' html), the oldest dropped; enough for a few hours without Ollama
_waiting: dict[str, tuple] = {}


# A company number found to be fake, and the first domain it was on: the same one elsewhere is one network
FAKE_NUMBER = re.compile(r"(?:NIP|VAT|KRS|REGON) (\S+)(?: \([^)]*\))? is (?:made up|in no Polish business register|not valid in VIES)")
_fake_numbers: dict[str, str] = {}


def sold_out(url: str) -> tuple[str, str, list[str]] | None:
    """The shop's home page, walked, when the ad's product page is gone but the shop names its company: catalog ads
    show many products and some sell out (meskie-spodnie.pl). None: the shop names nobody, the dead page stands."""
    home = urllib.parse.urlsplit(url)._replace(path="/", query="", fragment="").geturl()
    if home == url:
        return None
    doing("strony produktu już nie ma, otwiera stronę główną sklepu", home)
    try:
        site = walk(home)
    except Dead:
        return None
    return site if site and identified(company(site[1])) else None


# A second opinion on the model's passes: words learned from human decisions. On the passes humans judged (folds
# by FB page) 0.7 sent 12 of 26 bad ones to a human and 2 of 55 good ones; the young-domain rule caught 6 and 1
WORDS_AT = 0.7
# So sure the words decide whatever the model said, a scam template seen before: from 0.9 all 48 human-decided cards
# were bad (folds by FB page), from 0.8 74 of 81
WORDS_SURE = 0.9
_words = None  # see train_words()
# The review check on the model's passes reads the words and frozen Polish ModernBERT together (their average): on
# qwen's passes humans judged (folds by FB page) 0.65 sent 120 of 219 bad ones to a human and 12 of 294 good,
# words alone at 0.7 108 and 12 (bench/bert_thresholds.txt). Blocking stays on words: the average at 0.9 70 of 72 bad
BOTH_AT = 0.65
BERT = "OPI-PIB/pl-ModernBERT-512-base"  # Apache-2.0, weights in the models volume (HF_HUB_OFFLINE: never fetched)
_bert = None  # (tokenizer, model) once loaded, False without torch or the weights: words alone then
_bert_words = None  # see train_bert()


def words_text(ad: dict, domain: str) -> str:
    """What the word model reads: the domain's end, its age band, the FB page, the ad and the start of the page."""
    age = (ad.get("age_days") or {}).get(domain)
    band = ("unknown" if not isinstance(age, int) else "new" if age < 90 else "young" if age < 365
            else "mid" if age < 1825 else "old")
    page = (ad.get("landing") or {}).get(domain) or ""
    return f"tld_{domain.rsplit('.', 1)[-1]} age_{band} {fb_words(ad)} {ad.get('page_name') or ''}\n{ad_text(ad)}\n{page[:3000]}"


def fb_words(ad: dict) -> str:
    """The FB page as words: likes band, numeric address, categories. On 504 human decisions a numeric
    facebook.com/61… page was bad 82% of the time, a named one 29%; under 100 likes ~80%; +2.4 points of accuracy."""
    if not (fb := ad.get("fb_page")):
        return ""
    likes = next(name for top, name in ((10, "0"), (100, "10"), (1000, "100"), (10000, "1k"), (10**12, "10k"))
                 if fb["likes"] < top)
    numeric = "fb_numeric" if re.search(r"facebook\.com/\d{6,}/?$", fb.get("profile") or "") else "fb_named"
    return " ".join([f"fb_likes_{likes}", numeric, *("fb_cat_" + re.sub(r"\W", "", c.lower()) for c in fb["categories"])])


# Human decisions taken while the browser could not start (NO_BROWSER) on cards with no page: the user ruled
# from the ad alone, so the models do not learn from them (about 28)
BLIND = ("AND NOT (coalesce(CASE WHEN json_valid(ad) THEN json_extract(ad, '$.landing.\"' || domain || '\"') END, '') = '' "
         "AND domain IN (SELECT domain FROM history WHERE \"by\" LIKE 'collector%' AND at BETWEEN ? AND ?))")


def human_rows(db: sqlite3.Connection) -> list[tuple[str, str, str]]:
    """(domain, verdict, ad) of every human decision the models learn from."""
    return db.execute("SELECT domain, verdict, ad FROM verdicts WHERE decided_by = 'human' "
                      "AND verdict IN ('block', 'doubtful', 'pass') " + BLIND, NO_BROWSER).fetchall()


def words_model():
    from sklearn.feature_extraction.text import TfidfVectorizer  # here, not on top: the panel imports this file
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline, make_union
    return make_pipeline(make_union(TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True),
                                    TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, sublinear_tf=True)),
                         LogisticRegression(C=4, class_weight="balanced", max_iter=2000))


def bert_model():
    from sklearn.linear_model import LogisticRegression
    return LogisticRegression(C=1, class_weight="balanced", max_iter=5000)


def train_words(db: sqlite3.Connection) -> int:
    """Learns again from every human decision (block or doubtful = bad, pass = good): scams change their words.
    A pass checked outside the site (decided_by "verified", a phone call) is left out: its page looked bad.
    Returns how many it read, 0 when too few to learn from (the old model, if any, stays)."""
    global _words
    rows = human_rows(db)
    bad = [verdict != "pass" for _, verdict, _ in rows]
    if len(rows) < 100 or all(bad) or not any(bad):
        return 0
    _words = words_model().fit([words_text(json.loads(ad or "{}"), domain) for domain, _, ad in rows], bad)
    return len(rows)


def words_score(ad: dict, domain: str) -> float:
    """How much the card reads like the ones humans blocked, 0–1; 0 before the first training."""
    return float(_words.predict_proba([words_text(ad, domain)])[0, 1]) if _words is not None else 0.0


def bert_vector(ad: dict, domain: str) -> str | None:
    """words_text() as frozen ModernBERT reads it, the mean of its last layer: 768 float16 in base64, kept on the card
    so training never runs the model. None without torch or the weights. On the CPU: the GPU belongs to qwen."""
    global _bert
    if _bert is None:
        try:
            from transformers import AutoModel, AutoTokenizer  # here, not on top: the panel imports this file
            _bert = AutoTokenizer.from_pretrained(BERT), AutoModel.from_pretrained(BERT).eval()
        except (ImportError, OSError) as e:
            print(f"no ModernBERT, words alone: {e}")
            _bert = False
    if not _bert:
        return None
    import torch
    tok, model = _bert
    with torch.no_grad():  # one text, no padding: the plain mean is the masked mean bench/bert_try.py used
        out = model(**tok(words_text(ad, domain), truncation=True, max_length=512, return_tensors="pt")).last_hidden_state
    return base64.b64encode(out[0].mean(0).numpy().astype("float16").tobytes()).decode()


def unpacked(vector: str):
    import numpy as np
    return np.frombuffer(base64.b64decode(vector), dtype=np.float16).astype(np.float32)


def train_bert(db: sqlite3.Connection) -> int:
    """The regression on the ModernBERT vectors of human decisions, like train_words(); returns how many it read."""
    global _bert_words
    # a card ruled before the model step (a decoy, a clone) gets its vector later from fill_vectors()
    rows = [(vector, verdict != "pass") for domain, verdict, ad in db.execute(
                "SELECT domain, verdict, ad FROM verdicts WHERE decided_by = 'human' "
                "AND verdict IN ('block', 'doubtful', 'pass') AND ad LIKE '%\"bert\"%' " + BLIND, NO_BROWSER)
            if (vector := (json.loads(ad).get("bert") or {}).get(domain))]
    bad = [b for _, b in rows]
    if len(rows) < 100 or all(bad) or not any(bad):
        return 0
    import numpy as np
    _bert_words = bert_model().fit(
        np.vstack([unpacked(vector) for vector, _ in rows]), bad)
    return len(rows)


def measure(db: sqlite3.Connection) -> list[tuple]:
    """How often each model is right on human decisions it never learned from: the decisions split in 5, each part
    judged by a model trained on the other 4 (the same folds every day). Bad = block or doubtful, the model says bad
    at 0.5. One row per model in `trainings`: (at, model, cards, accuracy, bad caught, good called bad); [] when too
    few to measure. "both" is the average judge() uses, on the cards with a vector."""
    import numpy as np
    from sklearn.model_selection import StratifiedKFold, cross_val_predict
    rows = human_rows(db)
    bad = np.array([verdict != "pass" for _, verdict, _ in rows])
    if len(rows) < 100 or bad.all() or not bad.any():
        return []
    folds = StratifiedKFold(5, shuffle=True, random_state=0)
    ads = [json.loads(ad or "{}") for _, _, ad in rows]
    words = cross_val_predict(words_model(), [words_text(ad, domain) for ad, (domain, _, _) in zip(ads, rows)], bad,
                              cv=folds, method="predict_proba")[:, 1]
    found = [(i, v) for i, (ad, (domain, _, _)) in enumerate(zip(ads, rows)) if (v := (ad.get("bert") or {}).get(domain))]
    measured = [("words", words, bad)]
    if len(found) >= 100 and 5 <= bad[[i for i, _ in found]].sum() <= len(found) - 5:
        has = [i for i, _ in found]
        bert = cross_val_predict(bert_model(), np.vstack([unpacked(v) for _, v in found]), bad[has], cv=folds,
                                 method="predict_proba")[:, 1]
        measured += [("bert", bert, bad[has]), ("both", (words[has] + bert) / 2, bad[has])]
    at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    results = []
    for name, p, truth in measured:
        said = p >= 0.5
        results.append((at, name, len(truth), float((said == truth).mean()), float(said[truth].mean()),
                        float(said[~truth].mean())))
    db.executemany("INSERT INTO trainings VALUES (?, ?, ?, ?, ?, ?)", results)
    db.commit()
    return results


def both_score(ad: dict, domain: str, like: float) -> float | None:
    """The average of the words (`like`) and ModernBERT; None without a trained BERT or the card's vector."""
    if _bert_words is None or not (vector := (ad.get("bert") or {}).get(domain)):
        return None
    return (like + float(_bert_words.predict_proba([unpacked(vector)])[0, 1])) / 2


def judge(ad: dict, domain: str, twin: str | None = None) -> tuple[str, int, str] | None:
    """(verdict, score, reason) with verdict block | pass | review; None = LLM unreachable, retry next cycle.

    `twin` is an already blocked domain with the same ad text: the clone shares its verdict.
    Then the ad's real link is opened in a browser: a decoy page or a shop that names no company anywhere blocks,
    company details found lower the score.
    With the LLM every new domain is read by it: keywords miss scams that avoid them ("ćwiczenia na krześle").
    Without it the keyword score decides alone.
    """
    ad.pop("model", None)  # set again below when the LLM reads this card
    if domain in PLATFORMS:
        return "review", 0, "a platform hosting many sites: a block would hit them all, a human decides"
    if domain in SHORTENERS:
        return "pass", 0, "a link shortener: its links lead elsewhere, those are judged"
    doing("sprawdza wiek domeny (RDAP, WHOIS)", domain)
    age = domain_age_days(domain)
    ad.setdefault("age_days", {})[domain] = age  # shown on the panel card
    points = score(ad, domain, age)
    established = age is not None and age > ESTABLISHED_DAYS  # real shops also shout "-50%, zyskaj"
    free = domain.endswith(FREE_HOSTS)  # no domain of its own, so no age: made in minutes, judged as young
    # a .pl that waited out NASK may be years old: an owner left unnamed or a break goes to a human (fakebake.pl)
    old = domain in _gave_up
    # a page gone or broken: an old firm gets a human (sephora.pl's ad link 404'd), a decoy mark blocks any age
    def gone(why: str) -> str:
        return "review" if established and not why.startswith("decoy") else "block"
    where = ad_link(ad, domain)  # reads the ad's FB page too, once per ad
    # a week-old domain and a FB page nobody likes: on 191 such cards 174 blocked, humans 14 blocks of 16
    if age is not None and age < NEWBORN_DAYS and no_likes(ad):
        faceless = True, f"{age}-day-old domain from a FB page with 0 likes"
    else:
        faceless = unliked(ad)
    if faceless:
        if where := where or next(iter(ad.get("destinations") or []), None):  # the panel opens it
            ad.setdefault("links", {})[domain] = where
        any_age, why = faceless  # an old domain otherwise only to a human: med.com, a scam's caption, passed
        return ("block" if any_age or not established else "review"), points, why
    if twin:  # the small LLM is not consistent across clones (huainsa.com passed, qenumysr.com blocked)
        # an aged domain is bought for this too (lunarpiath.com); biedronka.pl, 24 years, was a scam ad's caption:
        # where the ad really leads is read too, for the panel, and those domains get judged
        if not ad_link(ad, domain) and (hidden := lying_caption(ad)) and domain not in hidden:
            ad.setdefault("links", {})[domain] = ad["destinations"][0]
            return ("review" if established else "block"), points, f"the ad shows {domain} but leads to {', '.join(hidden)}; same ad as {twin}"
        return ("review" if age is not None and age > OLD_DAYS else "block"), points, f"same ad as {twin}"
    if mark := decoy_mark(ad, domain):  # no real business behind the ad: blocked even when old (bought)
        # a caption with no website, the ad opening another: its link kept for the panel, and the opened domain gets
        # judged (globistudiofitness.pl, the ad opens reklama.4wz.pl)
        if mark == "no website" and not ad_link(ad, domain) and (hidden := lying_caption(ad)):
            ad.setdefault("links", {})[domain] = ad["destinations"][0]
            mark += f", the ad opens {', '.join(hidden)}"
        return ("review" if (established or old) and MAINTENANCE.search(mark) else "block"), points, f"decoy: {mark}"
    if (hidden := len(HIDDEN_CHARS.findall(ad_text(ad)))) >= 50:
        return ("review" if established else "block"), points, f"{hidden} invisible characters hidden in the ad's words"
    link, site = _waiting.pop(domain, (None, None))
    colors, url, shown, fonts = set(), None, None, None
    if not site:
        link = ad_link(ad, domain)
        # a site builder's page is no domain to hide: the firm's own home is judged (karolpieczka.pl, its
        # sign-up page on prezentkarolpieczka.grwebsite.pl); the platform's domain cannot be blocked anyway
        if (not link and (hidden := lying_caption(ad)) and domain not in hidden  # caption smyk.pl, opens a scam shop
                and not set(hidden) <= PLATFORMS and not any(forwards(domain, other) for other in hidden)):
            ad.setdefault("links", {})[domain] = ad["destinations"][0]
            # the caption's own site still read, for the human: its terms may name the firm (goldenspa.pl's NIP, its ad
            # opening zabiegibeauty.pl)
            doing("otwiera stronę z podpisu reklamy", f"https://{domain}/")
            try:
                own = walk(f"https://{domain}/")
            except Dead:
                own = None
            if own:
                ad.setdefault("landing", {})[domain] = own[1][:LANDING_CHARS]
                if number := company_number(own[1]):
                    ad.setdefault("number", {})[domain] = number
            return "review", points, f"the ad shows {domain} but leads to {', '.join(hidden)}"  # those get judged too
        url = clicked(link, ad) if link else caption_url(ad, domain)
        doing("otwiera stronę z reklamy w przeglądarce", url)
        try:
            site = walk(url, shot=SHOTS / f"{domain}.jpg")  # "clicks" the ad
        except Dead as e:  # an ad paid to send people to an error page or nowhere: no model needed, even when old
            if not (site := sold_out(url)):
                if link:
                    ad.setdefault("links", {})[domain] = link
                return gone(str(e)), points, str(e)
        if (site and (m := DECOY.search(site[0])) and MAINTENANCE.search(m[0])
                and urllib.parse.urlsplit(url).hostname != domain):  # cms.apartamentymuseo.pl: a WordPress backend's
            try:                                                      # sample post, the shop and its NIP on the bare domain
                if home := walk(f"https://{domain}/", shot=SHOTS / f"{domain}.jpg"):
                    site, url = home, f"https://{domain}/"
            except Dead:
                pass
        colors, shown, fonts = loud(_looks.pop(url, [])), _shown.pop(url, None), _fonts.pop(url, None)
    if link:  # saved with the ad: the panel opens this page, not the bare domain
        ad.setdefault("links", {})[domain] = link
    if site:  # what the ad led to, kept with it: the page may be gone when someone appeals
        ad.setdefault("landing", {})[domain] = site[1][:LANDING_CHARS]
        if ids := trackers(f"{link or ''}\n{site[0]}"):  # the ad link may name the pixel too (relivital.com)
            ad.setdefault("trackers", {})[domain] = ids
        if number := company_number(site[1]):  # often on a legal page past the text kept: the panel checks it
            ad.setdefault("number", {})[domain] = number
        elif court := court_number(site[1]):  # no NIP on the site: the one GUS holds behind its KRS or REGON
            ad.setdefault("number", {})[domain] = (nip := nip_behind(court)) or court
            if nip:  # never one without the other: the panel shows "no NIP on the site" beside this NIP
                ad.setdefault("number_by", {})[domain] = court
    if site and (m := FOR_SALE.search(f"{site[0]}\n{site[1]}")):  # before DECOY: a parked one for sale is not blocked
        return "forget", points, f"domain for sale: {m[0]}"
    if site and (m := DECOY.search(site[0])):  # JS-built shops show their state only in a browser (smyk.brand-eu.com)
        return ("review" if (established or old) and MAINTENANCE.search(m[0]) else "block"), points, f"decoy: {m[0]}"
    # reached only behind a caption showing another domain: impersonation, unless that domain sends people here
    if domain in lying_caption(ad) and not any(forwards(shown, domain) for shown in ad_domains(ad)):
        return (("review" if established or caption_typo(ad, domain) else "block"), points,
                f"hidden behind the caption {', '.join(sorted(ad_domains(ad)))}")
    if why := fake_page(ad.get("page_name") or "", domain):
        return ("review" if established else "block"), points, f"FB page {ad['page_name']}: {why}"
    if colors == set(LOUD_AREA):  # the look of one-product cash-on-delivery scams, company named or not
        return ("review" if established else "block"), points, "loud red, yellow and green blocks on the page"
    if why := bad_fonts(fonts):  # a real shop sets its fonts, with Polish letters
        return ("review" if established else "block"), points, why
    if site and FORBIDDEN.search(site[1][:3000]):  # still refused a day later: look_again blocks it
        return "review", points, "page refuses the server (403 Forbidden), a human looks"
    if site and walled(site[0], site[1]):
        return "review", points, "page hidden behind a bot check, a human looks"
    if site and (m := QUIZ.search(f"{domain} {link or url} {site[1][:500]}")):  # what it is, not a shop's "quiz" tab
        if HEALTH.search(ad_text(ad)) and not identified(company(site[1])):  # smallpenisbigdreams.lol
            return "block", points, f"health promise in a quiz ({m[0]}) and no company named"
        if asked := PERSONAL.search(site[1][:1500]):
            return "block", points, f"quiz asking for age or sex: {asked[0][:40]}"
        if free:  # a subscription funnel on a rented subdomain (everdance.greatapps.co)
            return "block", points, f"quiz on a page with no domain of its own: {m[0]}"
        return "review", points, f"quiz or fortune telling: {m[0]}"
    if site and (original := same_page(site[1], domain)):  # a blocked shop again under a new domain, any age
        return "block", points, f"same page as {original}"
    # an error screen served with 200, an empty shop template ("StockDeal24 Archivi"), a fake captcha, nothing
    if site and not site[2] and (why := emptiness(site[0], site[1])):
        return gone(why), points, why
    # any other address the reviewer gets for it; a shop naming its company only sold out another product
    if not (site and identified(company(site[1]))) and (why := dead_link(ad, domain, skip=url)):
        return gone(why), points, why
    if site and not identified(company(site[1])) and (other := country_version(domain, url or link or "")):
        doing("otwiera krajową wersję strony", other)
        try:
            more = walk(other)
        except Dead:  # a broken version says nothing of the one the ad shows
            more = None
        if more:
            ad.setdefault("country", {})[domain] = other  # the panel names the version it was found in
            site = (site[0] + more[0], f"{site[1]}\n{more[1]}", site[2] + more[2])
    # an app's sign-up page links to no terms (app.graphik.pl/rejestracja): the company is on the bare domain
    if (site and not identified(company(site[1])) and (host := urllib.parse.urlsplit(url or link or "").hostname or "")
            .endswith(f".{domain}") and host != f"www.{domain}"):
        doing("otwiera stronę główną domeny", f"https://{domain}/")
        try:
            more = walk(f"https://{domain}/")
        except Dead:  # the app may live on while the bare domain is gone
            more = None
        if more:
            site = (site[0] + more[0], f"{site[1]}\n{more[1]}", site[2] + more[2])
    details = company(site[1]) if site else []
    nowhere = f"; social icons lead nowhere: {', '.join(socials)}" if site and (socials := dead_socials(site[0])) else ""
    if site and not identified(details):  # by law a Polish shop names its company; nowhere = throwaway shop
        found = f" (only: {', '.join(details)})" if details else ""
        if m := UNREGISTERED.search(site[1]):  # legal without a company, by name and address (malymadrala.com)
            return "review", points, f"unregistered activity: {m[0]}{found}{nowhere}"
        if len(broken := MOJIBAKE.findall(site[1])) >= 5:  # a machine-made page nobody Polish ever read
            return "block", points, f"broken Polish letters ({len(broken)}x, e.g. {broken[0]}) and no company named{found}"
        if site[2] and (free or (age is not None and age <= YOUNG_DAYS)):  # an unread legal page is no excuse for a new shop
            what = "a free-hosted site" if free else f"{age}-day-old domain"
            return "block", points, f"{what}, no company named{found}{nowhere}; not read: {'; '.join(site[2])}"
        if site[2]:
            return "review", points, f"no company named{found}{nowhere}; to check by hand: {'; '.join(site[2])}"
        if HEALTH.search(ad_text(ad)):  # a cure sold by nobody named: blocked on an aged domain too (vigoroa.com)
            return "block", points, f"health promise and no company named on the site or its legal pages{found}{nowhere}"
        # illegal for a shop (UŚUDE art. 5); a young site is blocked, an old one or of unknown age (.eu, .de) goes to a human
        young = free or (age is not None and age <= ESTABLISHED_DAYS)
        return ("block" if young else "review"), points, f"no company named on the site or its legal pages{found}{nowhere}"
    doing("sprawdza dane firmy w rejestrach", domain)
    def problem_in(text):
        return (("NIP" in details and nip_problem(text, domain))
                or ("foreign registry" in details and vat_problem(text, domain))
                or ("NIP" not in details and registry_problem(text, domain)))
    problem = site and problem_in(site[1])
    # a footer gives the number, the owner's name stands on the privacy policy not read yet (dataclub.pl),
    # or the closed business's number, the company it became stands in the terms (y-s.eu)
    if problem and (problem[1].endswith("the site never names it") or STALE.search(problem[1])):
        doing("szuka nazwy z rejestru na pozostałych stronach prawnych", domain)
        try:
            more = walk(url or f"https://{domain}/", everything=True)
        except Dead:
            more = None
        if more:
            problem = problem_in(f"{site[1]}\n{more[1]}")
    if problem:  # a number is easy to type in, so check it is real
        strong, why = problem
        if HEALTH.search(ad_text(ad)):  # a cure sold under a number that is not real
            return "block", points, f"health promise and {why}"
        if (m := FAKE_NUMBER.search(why)) and (other := _fake_numbers.setdefault(m[1], domain)) != domain:
            return "block", points, f"{why}, the same number as on {other}"  # one network (harmonyvita.pl, vitapolska.pl)
        return ("block" if strong and not (established or old) else "review"), points, why
    points -= len(details)
    if OLLAMA:
        facts = {"landing_page": (shown or site[1])[:2000], "company_details": details} if site else None
        if site and (excerpt := company_excerpt(site[1])):  # the footer or the terms, past what it reads of the page
            facts["company_excerpt"] = excerpt
        if site and (nip := company_number(site[1])) and nip.isdigit() and (trader := ceidg_subject(nip)):
            # sorted, no main one: qwen judged by the first only (styliq.pl, cosmetics before clothing); days, as it
            # took 2026 dates for the future (rockstone.pl); false alarms 4 -> 2 of 15 good
            started = trader["since"] and (datetime.now(timezone.utc).date() - date.fromisoformat(trader["since"])).days
            facts["company_register"] = {"started_days_ago": started}
            # retail of any goods covers any ad, yet qwen read "Pośrednictwo w sprzedaży detalicznej niewyspecjalizowanej"
            # as not retail (funidoo.pl 4 of 4); false alarms 2 -> 1 of 17 good, bad caught 3 of 9 both
            if not any(ANY_GOODS.search(kind) for kind in trader["pkd"]):
                facts["company_register"]["registered_activities"] = sorted(trader["pkd"])
        if nowhere:
            facts["social_icons_linking_nowhere"] = socials
        doing("model językowy czyta reklamę i stronę", domain)
        ad["model"] = MODEL  # its verdicts carry its name
        if (answer := ask_llm(ad, domain, age, facts)) is None:
            if len(_waiting) >= 100:
                _waiting.pop(next(iter(_waiting)))
            _waiting[domain] = (link, site)
            return None
        # qwen misses the PKD that covers the ad (mddressage.pl: riding lessons under sports education); a narrow
        # question names it, then the model judges again with only that one (bench/pkd_check.py: 11 of 11 right);
        # with no list at all it still wrote "unrelated to its PKD codes" (twoj-kurs.pl: training courses)
        pkd = ((facts or {}).get("company_register") or {}).get("registered_activities")
        if pkd and (answer["scam"] or contradicts(answer["reason"])) and (covering := pkd_covers(ad, domain, pkd)):
            facts["company_register"]["registered_activities"] = [covering]
            answer = ask_llm(ad, domain, age, facts) or answer
        # the second check, on whatever the model said; a card with no ad (named like a brand) gives it only the
        # ending and age, 0.99 for int-ikea.com checked by hand as no imitation
        like = words_score(ad, domain) if ad_text(ad).strip() else 0.0
        if ad_text(ad).strip() and (vector := bert_vector(ad, domain)):
            ad.setdefault("bert", {})[domain] = vector  # made fresh on every judging: the page may have changed
        if like >= WORDS_SURE:
            return "block", points, f"words like blocked ads ({like:.0%}), llm{'' if answer['scam'] else ' passed it'}: {answer['reason']}"
        if site and identified(details) and NO_COMPANY.search(answer["reason"]):  # its only argument is false
            # a .pl waiting out NASK is over 35 days old, and its NIP passed GUS and MF just now
            known = established or (domain in _gave_up and "NIP" in details)
            # a foreign number alone, or words like blocked ads, outweighs no model (humans held 11 of 35 such
            # passes bad, niebos.shop with a foreign number only; these two send 5 of the 11 to a human, none of 24 good)
            alone = "foreign registry" in details and not {"NIP", "KRS", "REGON"} & set(details)
            sure = not alone and like < WORDS_AT
            return ("pass" if known and sure else "review"), points, f"company named on the page ({', '.join(details)}), the model claimed none"
        if not answer["scam"] and contradicts(answer["reason"]):
            return "review", points, f"llm passed it but wrote: {answer['reason']}"
        if not answer["scam"] and (m := CLOSING.search(ad_text(ad))):
            return "review", points, f"llm passed it, but the ad tells a closing-down story: {m[0]}"
        if not answer["scam"] and not site:  # it read only the ad: a cloaker showed the browser nothing (natureceut.fit)
            return "review", points, f"page did not load, the model read only the ad: {answer['reason']}"
        if not answer["scam"] and nowhere:  # a sign of a template shop the model may not weigh
            return "review", points, f"llm passed it{nowhere}"
        if not answer["scam"] and age is not None and not established:
            # humans blocked or doubted 99 of 112 domains under a year old, and 6 of the 7 such the model passed
            return "review", points, f"young domain, llm passed it: {answer['reason']}"
        both = both_score(ad, domain, like)
        if not answer["scam"] and (like >= WORDS_AT if both is None else both >= BOTH_AT):
            return "review", points, f"words like blocked ads ({like if both is None else both:.0%}), llm passed it: {answer['reason']}"
        if not answer["scam"]:
            return "pass", points, f"llm: {answer['reason']}"
        # a small model errs; .eu and .my hide the creation date, a registered company there is no throwaway (twistcar.eu)
        trusted = established or (age is None and identified(details))
        return ("review" if trusted else "block"), points, f"llm: {answer['reason']}"
    if points < ASK_AT:
        return "pass", points, "heuristics"
    if points >= BLOCK_AT and age is not None and not established:
        return "block", points, "heuristics"
    return "review", points, "borderline, needs a human"


def read_list(path: Path) -> set[str]:
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    return {line.strip().removeprefix("*.") for line in lines if line.strip() and not line.startswith("#")}


def popular_domains(top: int = 20_000) -> set[str]:
    with urllib.request.urlopen(TRANCO, timeout=120) as response:
        archive = zipfile.ZipFile(io.BytesIO(response.read()))
    rows = csv.reader(io.TextIOWrapper(archive.open("top-1m.csv"), encoding="utf-8"))
    return {domain for _, domain in itertools.islice(rows, top)}


def mined_terms(db: sqlite3.Connection, top: int = 10) -> list[str]:
    """Words in many blocked ads and few passed ones: extra search terms, so the Library shows more of the same."""
    seen = {"block": Counter(), "pass": Counter()}
    blocked_in = {}  # word -> the blocked ads (row numbers) it stands in
    for row, (verdict, ad) in enumerate(db.execute("SELECT verdict, ad FROM verdicts WHERE verdict IN ('block', 'pass') "
                                                   "AND ad IS NOT NULL")):
        ad = json.loads(ad)
        # Polish versions only (a Polish letter in that text): foreign ads gave "watch", "autre", "gledati",
        # and each such term brought in more foreign ads
        texts = [t.lower() for t in ad.get("ad_creative_bodies", []) + ad.get("ad_creative_link_titles", [])
                 if re.search(r"[ąęłńśźż]", t.lower())]
        words = set(re.findall(r"[a-ząćęłńóśźż]{5,}", " ".join(texts)))
        seen[verdict].update(words)
        if verdict == "block":
            for word in words:
                blocked_in.setdefault(word, set()).add(row)
    ratio = {word: count / (seen["pass"][word] + 1) for word, count in seen["block"].items() if count >= 5}
    # Once all 10 terms were verbs of one campaign's long stories ("przeczytałam", "czekałam"): they found its blocked
    # domains again and 1.5 new ones a query (2.0 for the fixed terms). A word with over 10% of its ads reached by an
    # earlier term is skipped, so each term opens another kind of scam (stories, injections, jackpot, courier;
    # at 50% half the terms were still the stories' verbs)
    picked, reached = [], set()
    for word in sorted(ratio, key=ratio.get, reverse=True):
        if ratio[word] >= 3 and word not in SEARCH_TERMS and len(blocked_in[word] & reached) <= len(blocked_in[word]) / 10:
            picked.append(word)
            reached |= blocked_in[word]
    return picked[:top]


_rechecked: dict[str, date] = {}  # queued domain -> the day recheck() last opened its links


def recheck(db: sqlite3.Connection, batch: int = 25) -> int:  # ~68 cycles a day x 25 covers the ~1500 cards
    """Blocks queued domains of which any address the reviewer gets now serves an error page or nothing: pages die
    after the verdict and a dead one needs no human. Only entries no human decided, each once a day, `batch` per
    call: one cycle stays short (most are skipped at once) and the whole queue is done once a day. The number blocked."""
    today, blocked = date.today(), 0
    # names first, ads only of the picked ones: the whole queue's ads were 30 MB of RAM each cycle at 1539 cards
    picked = [domain for (domain,) in db.execute("SELECT domain FROM verdicts WHERE verdict = 'review' "
                                                 "AND decided_by IS NULL ORDER BY seen_at")
              if _rechecked.get(domain) != today][:batch]
    for domain in picked:
        ad_json = db.execute("SELECT ad FROM verdicts WHERE domain = ?", (domain,)).fetchone()[0]
        doing("sprawdza ponownie domeny z kolejki", domain)
        _rechecked[domain] = today
        ad = json.loads(ad_json or "{}")
        age = (ad.get("age_days") or {}).get(domain)
        # its age when the ad ran: judging again counts it from today, so older cards would never get the rule
        if age is not None and age < NEWBORN_DAYS and no_likes(ad):
            why = f"{age}-day-old domain from a FB page with 0 likes (recheck {today:%d.%m})"
            db.execute("UPDATE verdicts SET verdict = 'block', reason = ? WHERE domain = ?", (why, domain))
            log(db, domain, "block", why, "collector")
            db.commit()
            blocked += 1
            print(f"block  {domain} ({why})")
            continue
        if identified(company((ad.get("landing") or {}).get(domain, ""))):
            continue  # a shop naming its company with a product gone is no dead shop (meskie-spodnie.pl)
        if domain in PLATFORMS or (age is not None and age > ESTABLISHED_DAYS):
            # an old firm's campaign page ends with its ad: both blocks humans undid were these (mitsubishi-motors.pl)
            continue
        if why := dead_link(ad, domain):
            if not why.endswith(f" on https://{domain}/") and lives(f"https://{domain}/"):
                continue  # one product gone from a shop whose home page lives (elmich.pl): a human decides
            why += f" (recheck {today:%d.%m})"
            db.execute("UPDATE verdicts SET verdict = 'block', reason = ? WHERE domain = ?", (why, domain))
            log(db, domain, "block", why, "collector")
            db.commit()
            blocked += 1
            print(f"block  {domain} ({why})")
    return blocked


# A card with neither ad text nor page gives the models nothing to learn from (as SQL, on the verdicts row)
NOTHING = ("CASE WHEN json_valid(ad) THEN coalesce(json_array_length(ad, '$.ad_creative_bodies'), 0) + "
           "coalesce(json_array_length(ad, '$.ad_creative_link_titles'), 0) = 0 AND "
           "coalesce(json_extract(ad, '$.landing.\"' || domain || '\"'), '') = '' ELSE 1 END")


def skip_unlearnable(db: sqlite3.Connection) -> int:
    """Takes off the queue the cards no human decision would teach the models anything (user): those with
    nothing to learn from and those queued before the ad was kept. The row stays as
    "skipped": the stats still count it, it is never judged again. The number taken off."""
    rows = db.execute("SELECT domain FROM verdicts WHERE verdict = 'review' AND decided_by IS NULL "
                      f"AND (seen_at < '2026-10-26' OR {NOTHING})").fetchall()
    for (domain,) in rows:
        db.execute("UPDATE verdicts SET verdict = 'skipped' WHERE domain = ?", (domain,))
        log(db, domain, "skipped", "off the queue: no ad text or page to learn from", "collector")
    db.commit()
    return len(rows)


def fill_vectors(db: sqlite3.Connection, batch: int = 20) -> int:
    """ModernBERT vectors for cards settled before the model step (a decoy, a clone, a platform, a dead page), `batch` a cycle on the CPU: human decisions first (train_bert() reads them), then the queue.
    Only the card's "bert" key is written, so a verdict saved meanwhile loses nothing. The number made."""
    made = 0
    for domain, ad in db.execute(f"SELECT domain, ad FROM verdicts WHERE ad NOT LIKE '%\"bert\"%' AND NOT {NOTHING} "
                                 "ORDER BY decided_by = 'human' DESC, verdict = 'review' DESC LIMIT ?", (batch,)).fetchall():
        doing("liczy wektory ModernBERT", domain)
        if not (vector := bert_vector(json.loads(ad), domain)):
            break  # no torch or no weights
        db.execute("UPDATE verdicts SET ad = json_set(ad, '$.bert', json_object(?, ?)) WHERE domain = ?",
                   (domain, vector, domain))
        db.commit()
        made += 1
    return made


def traced(result: tuple[str, int, str], domain: str, ips: list[str], ids: list[str], age: int | None = None,
           number: str | None = None) -> tuple[str, int, str]:
    """judge()'s verdict sent to a human when the domain shares a trace with blocked ones or hides a Polish name."""
    if result[0] == "forget":  # a parking server is shared by thousands of domains for sale
        return result
    # a scam network keeps its servers when it swaps domains; a human looks, the address alone is no proof
    if result[0] != "block" and not domain.endswith(HOSTED) and (near := same_server(ips, domain)):
        why = f"same server as blocked {', '.join(near[:3])}"
        sure = len(near) >= SAME_SERVER_BLOCK and not (isinstance(age, int) and age > ESTABLISHED_DAYS)
        result = ("block" if sure else "review", result[1], why if result[0] == "pass" else f"{result[2]}; {why}")
    if result[0] != "block" and (near := same_owner(ids, domain)):  # one ad account, many shops
        why = f"same tracking id as blocked {', '.join(near[:3])}"
        result = ("review", result[1], why if result[0] == "pass" else f"{result[2]}; {why}")
    if result[0] != "block" and number and (near := same_owner([number], domain, _numbers)):
        why = f"same company number as blocked {', '.join(near[:3])}"
        result = ("review", result[1], why if result[0] == "pass" else f"{result[2]}; {why}")
    if result[0] == "pass" and not domain.endswith(".pl") and POLISH_ABROAD.search(domain):
        result = ("review", result[1], f"a Polish name on a foreign domain ending; {result[2]}")
    return result


# Verdicts that age, judged again with a new walk once their last one is this many days old: a dead page comes back
# (mixit.pl), a bot wall lets the browser in another day, an old pass meets the rules added since.
# A fourth field: judged again also when judged before then, here the walk reading legal pages to the number
# (a second process judging them broke the base's writes on the Windows mount twice).
AGING = (("block", "dead page%", 1), ("block", "the page shows almost nothing%", 1), ("review", "%bot check%", 1),
         ("review", "page refuses the server%", 1), ("review", "page did not load%", 1),  # judged with no browser
         ("review", "no company named%", 7, "2026-11-03T14:54:00+00:00"), ("pass", "%", 7))
# Passes judged on the server with no age (rdap.org refused the server's cloud addresses): judged again first, once,
# now that the registry answers; once judged their last verdict is after this window
NO_AGE = ("2026-11-06T00:00:00+00:00", "2026-11-07T13:24:00+00:00")
# Reviews judged while the browser could not start: no page, FB page, Instagram or NIP; judged again at once,
# NO_BROWSER_BATCH a cycle on top of AGING, each once (after that its last verdict is after this window)
# NO_BROWSER_BATCH may go once no review is left in the window ; BLIND needs the window
NO_BROWSER, NO_BROWSER_BATCH = ("2026-11-09T09:37:00+00:00", "2026-11-09T19:52:00+00:00"), 20


def look_again(db: sqlite3.Connection, batch: int = 5, until: float = 0.0, skip: frozenset[str] = frozenset()) -> int:
    """Judges afresh up to `batch` domains of AGING no human decided, the longest unjudged first; each verdict
    is written and logged, an unchanged one too (its day counts from then). Again `batch` more while time.monotonic()
    is before `until`, the cycle's spare time: 5 a cycle judged ~200 a day of ~520 due. Registries keep up:
    CEIDG paces itself, MF's name searches have their own daily count. The number whose
    verdict changed."""
    waiting = json.dumps(sorted(skip))  # waiting since an earlier round: not walked again this cycle
    rows = db.execute("SELECT domain, verdict, ad, last, reason FROM (SELECT domain, verdict, ad, reason, (SELECT max(at) FROM history h "
                      "WHERE h.domain = v.domain) AS last FROM verdicts v WHERE verdict = 'pass' AND decided_by IS NULL "
                      "AND domain NOT LIKE '%.pl' AND CASE WHEN json_valid(ad) THEN json_extract(ad, '$.age_days.\"' || "
                      "domain || '\"') ELSE 0 END IS NULL AND domain NOT IN (SELECT value FROM json_each(?))) WHERE last BETWEEN ? "
                      "AND ? ORDER BY last", (waiting, *NO_AGE)).fetchall()
    rows = [row for row in rows if has_registry(row[0])][:batch]  # judged again for nothing: still no age
    for verdict, reason, days, *since in AGING:
        cutoff = max([(datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds"), *since])
        rows += db.execute("SELECT domain, verdict, ad, last, reason FROM (SELECT domain, verdict, ad, reason, (SELECT max(at) FROM "
                           "history h WHERE h.domain = v.domain) AS last FROM verdicts v WHERE verdict = ? AND "
                           "reason LIKE ? AND decided_by IS NULL AND domain NOT IN (SELECT value FROM json_each(?))) WHERE last < ? "
                           "ORDER BY last LIMIT ?", (verdict, reason, waiting, cutoff, batch - len(rows))).fetchall()
    picked = {row[0] for row in rows}
    rows += [row for row in db.execute(
        "SELECT domain, verdict, ad, last, reason FROM (SELECT domain, verdict, ad, reason, (SELECT max(at) FROM history h "
        "WHERE h.domain = v.domain) AS last FROM verdicts v WHERE verdict = 'review' AND decided_by IS NULL AND domain NOT IN "
        "(SELECT value FROM json_each(?))) WHERE last BETWEEN ? AND ? ORDER BY domain LIKE '%.pl' AND CASE WHEN json_valid(ad) THEN json_extract(ad, "
        "'$.age_days.\"' || domain || '\"') END IS NULL, last LIMIT ?",  # a .pl of unknown age waits for NASK: last
        (waiting, *NO_BROWSER, NO_BROWSER_BATCH)) if row[0] not in picked]
    changed, skipped = 0, []
    for domain, verdict, ad_json, last, old in rows:
        doing("ocenia ponownie stare werdykty", domain)
        ad = json.loads(ad_json or "{}")
        ips = ad.setdefault("ips", {})[domain] = addresses(domain)
        ages = ad.get("age_days") or {}
        if isinstance(age := ages.get(domain), int):
            _known[domain] = age + (datetime.now(timezone.utc) - datetime.fromisoformat(last)).days
        try:
            result = judge(ad, domain)
        except OSError:  # a registry's rate limit
            # judged before with its age unknown: it waited out the registry once, so it goes so again; it waited
            # every cycle instead and .pl domains kept no FB page or NIP for a day (NASK 429 all day)
            if domain not in ages or ages[domain] is not None or domain in _gave_up:
                skipped.append(domain)
                continue
            _gave_up.add(domain)
            try:
                result = judge(ad, domain)
            except OSError:
                skipped.append(domain)
                continue
            finally:
                _gave_up.discard(domain)
        finally:
            _known.pop(domain, None)
        if not result:  # the LLM is down
            skipped.append(domain)
            continue
        # an old pass's own entry in _servers/_trackers shields it; fine while those signals only queue
        result = traced(result, domain, ips, (ad.get("trackers") or {}).get(domain, []), (ad.get("age_days") or {}).get(domain),
                        (ad.get("number") or {}).get(domain))
        if result[0] == "forget" and verdict != "block":  # blocked ones stay blocked (the user's rule)
            forget(db, domain, result[2])
            changed += 1
            print(f"again  {domain}: {verdict} -> forgotten ({result[2]})")
            continue
        if result[0] == "forget":
            result = ("block", *result[1:])
        if verdict == "block" and result[2].startswith(("dead page", "the page shows almost nothing")):
            result = ("block", *result[1:])  # still dead: an old domain's would go to a human (pharmacyherb.com)
        if (old or "").startswith("page refuses the server") and result[2].startswith("page refuses the server"):
            result = ("block", result[1], "still 403 Forbidden a day later")  # the user's rule
        now =datetime.now(timezone.utc).isoformat(timespec="seconds")
        db.execute("UPDATE verdicts SET verdict = ?, score = ?, reason = ?, ad = ?, seen_at = "
                   "CASE WHEN verdict = ? THEN seen_at ELSE ? END WHERE domain = ?",  # a new verdict shows as new
                   (*result, json.dumps(ad, ensure_ascii=False), result[0], now, domain))
        log(db, domain, result[0], result[2], f"collector {ad['model']}" if "model" in ad else "collector")
        db.commit()
        if result[0] != verdict:
            changed += 1
            print(f"again  {domain}: {verdict} -> {result[0]} ({result[2]})")
    if skipped:  # silent before: the same rows came back each cycle and nothing showed it
        STATS["scamdns_look_again_skipped_total"] += len(skipped)
        print(f"judged again: {len(rows) - len(skipped)} of {len(rows)}, waiting (registry limit or LLM down): "
              f"{', '.join(skipped[:5])}{' ...' if len(skipped) > 5 else ''}")
    if len(rows) > len(skipped) and time.monotonic() < until:
        return changed + look_again(db, batch, until, skip | set(skipped))
    return changed


def overdue(db: sqlite3.Connection, grace: int = 2) -> tuple[int, str | None]:
    """Verdicts of AGING whose turn to be judged again passed over `grace` days ago, and the oldest last judging:
    look_again stuck or too slow. Read by alarm.sh and the quick test (265 skipped for a day and a half unseen)."""
    count, oldest = 0, None
    now = datetime.now(timezone.utc)
    late = (now - timedelta(days=grace)).isoformat(timespec="seconds")
    for verdict, reason, days, *since in AGING:
        cutoff = max([(now - timedelta(days=days + grace)).isoformat(timespec="seconds"), *(s for s in since if s < late)])
        n, first = db.execute("SELECT count(*), min(last) FROM (SELECT (SELECT max(at) FROM history h WHERE h.domain = "
                              "v.domain) AS last FROM verdicts v WHERE verdict = ? AND reason LIKE ? AND decided_by IS NULL) "
                              "WHERE last < ?", (verdict, reason, cutoff)).fetchone()
        count, oldest = count + n, min(filter(None, (oldest, first)), default=None)
    return count, oldest


REPORTS_PER_CYCLE = 3  # /zglos takes up to 500 a day; ~70 cycles judge ~200 of them, the most often sent first


def reported(db: sqlite3.Connection, allowed: set[str]) -> list[tuple[str, dict]]:
    """Sites sent on /zglos with no verdict yet, as (domain, card with no ad): the address sent stands as the
    caption, so the browser opens that very page (its path too) and the domain is judged like an ad's. The sender's
    note never reaches the model: anyone may write "block it" there."""
    try:
        rows = db.execute("SELECT domain, url FROM suspects GROUP BY domain ORDER BY count(*) DESC, min(at)").fetchall()
    except sqlite3.OperationalError:  # no table before the panel's first start
        return []
    forgotten = (datetime.now(timezone.utc) - timedelta(days=FORGET_DAYS)).isoformat(timespec="seconds")
    picked = {}
    for host, url in rows:
        domain = extract(host).top_domain_under_public_suffix
        if (not domain or domain in allowed or domain in picked or db.execute(
                "SELECT 1 FROM verdicts WHERE domain = ? UNION SELECT 1 FROM waiting WHERE domain = ? UNION SELECT 1 "
                "FROM history WHERE domain = ? AND verdict = 'forgotten' AND at > ?", (domain, domain, domain, forgotten)
        ).fetchone() or not public(host)):  # a redirect inward finds nothing: the browser is on its own network
            continue
        picked[domain] = {"id": None, "ad_creative_link_captions": [url]}
        if len(picked) == REPORTS_PER_CYCLE:
            break
    return list(picked.items())


def collect(db: sqlite3.Connection, token: str, allowed: set[str], queries: list[str]) -> None:
    limited = set()  # TLDs whose registry answered 429 this cycle; their domains wait for the next one
    # only clones seen after the block; an earlier passed clone stays passed until a human looks
    blocked = {fingerprint(json.loads(ad)): domain for domain, ad in
               db.execute("SELECT domain, ad FROM verdicts WHERE verdict = 'block' AND ad IS NOT NULL")}
    blocked.pop(None, None)
    _blocked_pages.clear()  # an unblocked domain is no pattern any more
    _fake_numbers.clear()
    for domain, reason in db.execute("SELECT domain, reason FROM verdicts WHERE reason LIKE '% is %'"):
        if m := FAKE_NUMBER.search(reason or ""):
            _fake_numbers.setdefault(m[1], domain)
    for domain, ad in db.execute("SELECT domain, ad FROM verdicts WHERE verdict = 'block' AND ad LIKE '%\"landing\"%'"):
        if text := (json.loads(ad).get("landing") or {}).get(domain):
            _blocked_pages[domain] = shingles(text)
    _servers.clear()
    _trackers.clear()
    _numbers.clear()
    for domain, verdict, ad in db.execute("SELECT domain, verdict, ad FROM verdicts WHERE verdict IN ('block', 'pass', "
                                          "'doubtful') AND (ad LIKE '%\"ips\"%' OR ad LIKE '%\"trackers\"%' "
                                          "OR ad LIKE '%\"number\"%')"):
        ad = json.loads(ad)
        remember(_servers, (ad.get("ips") or {}).get(domain, []), domain, verdict)  # a doubtful one counts in neither
        remember(_trackers, (ad.get("trackers") or {}).get(domain, []), domain, verdict)
        if number := (ad.get("number") or {}).get(domain):
            remember(_numbers, [number], domain, "block" if verdict == "doubtful" else verdict)
    chase, chased = {}, set()  # FB pages with a domain blocked this cycle (ordered), pages already fetched

    def keep(domain: str, ad: dict) -> None:  # with its ad: the ad may never come up in a search again (.pl lost most)
        db.execute("INSERT OR IGNORE INTO waiting VALUES (?, ?, ?)", (domain, json.dumps(ad, ensure_ascii=False),
                                                                     datetime.now(timezone.utc).isoformat(timespec="seconds")))
        db.commit()

    def consider(ad: dict, todo: list[str] | None = None) -> None:
        fresh = todo is None  # a new ad, not one taken from the waiting list
        STATS["scamdns_ads_total"] += fresh  # a waiting ad was counted when it came
        todo = todo or list(ad_domains(ad) - allowed)
        while todo:
            domain = todo.pop(0)
            tld = domain.rsplit(".", 1)[-1]
            if db.execute("SELECT 1 FROM verdicts WHERE domain = ?", (domain,)).fetchone():
                continue
            if db.execute("SELECT 1 FROM history WHERE domain = ? AND verdict = 'forgotten' AND at > ?", (domain, (
                    datetime.now(timezone.utc) - timedelta(days=FORGET_DAYS)).isoformat(timespec="seconds"))).fetchone():
                continue
            # already waiting with its ad, judged first once the LLM answers: its other ads opened it again for nothing
            # (home off: ~640 openings in a night, one cycle of DokiShop's ads ran 4 h)
            if fresh and db.execute("SELECT 1 FROM waiting WHERE domain = ?", (domain,)).fetchone():
                continue
            started = time.monotonic()
            ips = ad.setdefault("ips", {})[domain] = addresses(domain)
            try:
                if tld in limited and domain not in _gave_up and domain not in _young:  # its age needs no registry
                    raise OSError("429")
                # a domain of this very ad is no clone of another: underarmour.ie went to CERT as the twin of the
                # underarmour.eu the same ad showed, headandshoulders.com as the twin of a scam naming it
                twin = blocked.get(fingerprint(ad))
                result = judge(ad, domain, None if twin in ad_domains(ad) | set(hidden_domains(ad)) else twin)
            except OSError as e:
                if not str(e).startswith("429"):
                    raise
                keep(domain, ad)
                if tld not in limited:
                    limited.add(tld)
                    STATS[f'scamdns_rdap_limited_total{{tld="{tld}"}}'] += 1
                    print(f"RDAP rate limit for .{tld}: its new domains wait for the next cycle")
                continue
            STATS[f'scamdns_judged_total{{verdict="{result[0] if result else "waiting for llm"}"}}'] += 1
            STATS["scamdns_judge_seconds_total"] += time.monotonic() - started
            ids = (ad.get("trackers") or {}).get(domain, [])
            if not result:  # the LLM is down (home's computer off, on a server): judged again when it answers
                keep(domain, ad)
            if result and result[0] == "forget":
                forget(db, domain, result[2])
                print(f"forgot {domain}: {result[2]}")
                continue
            if result:
                result = traced(result, domain, ips, ids, (ad.get("age_days") or {}).get(domain), (ad.get("number") or {}).get(domain))
            if result:  # every write here ends in the commit below: an open one locks the panel out
                remember(_servers, ips, domain, result[0])
                remember(_trackers, ids, domain, result[0])
                if number := (ad.get("number") or {}).get(domain):
                    remember(_numbers, [number], domain, result[0])
                db.execute("DELETE FROM waiting WHERE domain = ?", (domain,))
                now = datetime.now(timezone.utc).isoformat(timespec="seconds")
                db.execute("INSERT INTO verdicts (domain, verdict, score, reason, ad_id, page, seen_at, ad) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                           (domain, *result, ad["id"], ad.get("page_name"), now, json.dumps(ad, ensure_ascii=False)))
                log(db, domain, result[0], result[2], f"collector {ad['model']}" if "model" in ad else "collector")
                db.commit()
                if result[0] == "block":
                    if key := fingerprint(ad):
                        blocked[key] = domain
                    if text := (ad.get("landing") or {}).get(domain):
                        _blocked_pages[domain] = shingles(text)
                    if ad.get("page_id"):
                        chase[ad["page_id"]] = ad.get("page_name")
                    try:  # on DNS now, not at the cycle's end: a cycle runs for hours (41 blocks waited from 16:06)
                        publish(db)
                    except OSError as e:
                        print(f"publish failed: {e}")
                print(f"{result[0]:6} {domain} (score {result[1]}, {result[2]})")
                todo += [d for d in hidden_domains(ad) if d not in allowed and d not in todo]  # what the ad really opens

    # while the LLM is down each would be opened again for nothing
    if (waiting := db.execute("SELECT domain, ad, since FROM waiting ORDER BY since").fetchall()) and llm_up(db):
        cutoff = (datetime.now(timezone.utc) - PATIENCE).isoformat(timespec="seconds")
        _gave_up.clear()
        _gave_up.update(domain for domain, _, since in waiting if since < cutoff)
        print(f"{len(waiting)} domain(s) waiting for a registry rate limit, judged first; "
              f"{len(_gave_up)} of them waited {PATIENCE} and go with their age unknown")
        doing("ocenia domeny czekające na limit rejestru", f"{len(waiting)} w kolejce")
        for domain, ad, _ in waiting:
            consider(json.loads(ad), [domain])
    for domain, ad in reported(db, allowed):  # browser, screenshot, registries and model, as for an ad's domain
        doing("ocenia stronę zgłoszoną na /zglos", domain)
        consider(ad, [domain])
    for query in queries:
        doing("pobiera reklamy z Biblioteki reklam Meta", f"hasło: {query}")
        for ad in fetch_ads(token, query):
            consider(ad)
            doing("pobiera reklamy z Biblioteki reklam Meta", f"hasło: {query}")  # the next page of ads
    # Scammers swap domains but keep their FB page: every other ad of a page that got a block is judged too.
    # Up to 10 pages share a call (2 pages of 100 ads); a block found there chases its own page in the same loop.
    while todo := [page for page in chase if page not in chased][:10]:
        chased.update(todo)
        print(f"chasing {len(todo)} FB page(s) with a blocked domain: {', '.join(str(chase[p]) for p in todo)}")
        doing("pobiera inne reklamy stron FB z zablokowaną domeną", ", ".join(str(chase[p]) for p in todo))
        for ad in fetch_ads(token, pages=2, page_ids=todo):
            consider(ad)


_llm_down = False


def llm_up(db: sqlite3.Connection) -> bool:
    """False while the LLM does not answer. When it answers again the waiting domains' wait starts afresh: none was
    tried while it was down, NASK neither, and a night off would send every waiting .pl on with its age unknown."""
    global _llm_down
    if not OLLAMA:
        return True
    try:
        http_json(f"{OLLAMA}/api/tags", timeout=15)
    except (OSError, ValueError):
        _llm_down = True
        return False
    if _llm_down:
        db.execute("UPDATE waiting SET since = ?", (datetime.now(timezone.utc).isoformat(timespec="seconds"),))
        db.commit()
        _llm_down = False
    return True


def publish(db: sqlite3.Connection) -> bool:
    """Writes fb.txt and reloads Blocky when the blocks changed; True when it reloaded."""
    rows = db.execute("SELECT domain FROM verdicts WHERE verdict = 'block' ORDER BY domain")
    content = "".join(f"*.{domain}\n" for (domain,) in rows)  # wildcard covers the domain and its subdomains
    target = LISTS / "fb.txt"
    if target.exists() and target.read_text(encoding="utf-8") == content:
        return False
    tmp = target.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(target)  # atomic swap: Blocky never reads a half-written list
    reload_blocky()
    return True


def reload_blocky() -> None:
    if not BLOCKY:
        return
    urllib.request.urlopen(urllib.request.Request(f"{BLOCKY}/api/lists/refresh", method="POST"), timeout=120).close()


STATS: Counter = Counter()  # Prometheus counters since start, "name{labels}" -> value


def doing(what: str, detail: str = "", until: float | None = None) -> None:
    """The current step in lists/teraz.json, shown by the start window (start_gui.py); `until` = end of a wait."""
    try:
        (LISTS / ("teraz_again.json" if AGAIN else "teraz.json")).write_text(json.dumps({"what": what, "detail": detail, "since": time.time(), "until": until},
                                                     ensure_ascii=False), encoding="utf-8")
    except OSError:  # only a display: collecting goes on without it
        pass


class Metrics(BaseHTTPRequestHandler):
    """STATS for Prometheus on :9100/metrics, inside the Docker network only."""

    def do_GET(self) -> None:
        body = "".join(f"{key} {value}\n" for key, value in sorted(STATS.items())).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


def explain(error: OSError) -> tuple[str, int]:
    """Log line and seconds to wait after a failed cycle, based on the Graph API error code."""
    code = int(m[1]) if (m := re.search(r'"code":\s*(\d+)', str(error))) else None
    if code == 190:
        return ("META TOKEN EXPIRED OR INVALID: create a new token, put it in .env as META_TOKEN, "
                f"then run: docker compose up -d collector ({error})"), CYCLE_SECONDS
    if code in {4, 17, 32, 613}:  # rate limits; Meta says retrying early only extends the block
        return f"META RATE LIMIT (code {code}): pausing for an hour so the rolling window clears ({error})", 3600
    return f"cycle failed: {error}", CYCLE_SECONDS


def open_db(path: Path | str) -> sqlite3.Connection:
    """Verdicts with their evidence; `ad` keeps the whole ad (JSON) as training data, the library drops old ads.

    `decided_by` and `decided_at` mark a human decision from the panel: the best labels there are.
    """
    if path == VERDICTS and not VERDICTS.exists() and (LISTS / "verdicts.db").exists():
        raise SystemExit("verdicts.db is still in lists/: copy it to the verdicts volume first (README), "
                         "else an empty base would start beside it")
    db = sqlite3.connect(path, timeout=30)  # the panel writes too
    # readers never block a writer: with the old journal 16 one-off scripts beside the collector and the panel locked
    # every write out for over 30 s; fine on the Docker volume, all processes share its kernel
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE IF NOT EXISTS verdicts (domain TEXT PRIMARY KEY, verdict TEXT, score INT, reason TEXT, "
               "ad_id TEXT, page TEXT, seen_at TEXT, ad TEXT, decided_by TEXT, decided_at TEXT)")
    columns = {column for _, column, *_ in db.execute("PRAGMA table_info(verdicts)")}
    for column in ("ad", "decided_by", "decided_at"):  # older bases
        if column not in columns:
            try:
                db.execute(f"ALTER TABLE verdicts ADD COLUMN {column} TEXT")
            except sqlite3.OperationalError as e:  # the panel and the collector start together
                if "duplicate column" not in str(e):
                    raise
    # the panel's tab counts: without it each count read every row's ad, 0.7 s for three
    db.execute("CREATE INDEX IF NOT EXISTS verdicts_verdict ON verdicts (verdict, decided_by)")
    # domains whose registry answered 429, with their ad: judged first in the next cycle
    db.execute("CREATE TABLE IF NOT EXISTS waiting (domain TEXT PRIMARY KEY, ad TEXT, since TEXT)")
    # the panel's sample batch: drawn once, kept until a human decided each (panel.sample)
    db.execute("CREATE TABLE IF NOT EXISTS sample (domain TEXT PRIMARY KEY)")
    # newly registered domains seen on the daily lists, with the latest possible registration date
    db.execute("CREATE TABLE IF NOT EXISTS registered (domain TEXT PRIMARY KEY, born TEXT)")
    # each model's accuracy after the day's training, see measure()
    db.execute("CREATE TABLE IF NOT EXISTS trainings (at TEXT, model TEXT, cards INT, accuracy REAL, caught REAL, "
               "false_alarms REAL)")
    try:  # every verdict, decision, exception and CERT report, oldest first; `verdicts` keeps only the latest
        db.execute("CREATE TABLE history (domain TEXT, verdict TEXT, reason TEXT, by TEXT, at TEXT)")
        db.execute("CREATE INDEX history_domain ON history (domain)")
        # an older base starts with the current state only, what came before is gone
        db.execute("INSERT INTO history SELECT domain, verdict, reason, coalesce(decided_by, 'collector'), "
                   "coalesce(decided_at, seen_at) FROM verdicts")
        db.commit()
    except sqlite3.OperationalError as e:  # there already, also when the other process made it a moment ago
        if "already exists" not in str(e):
            raise
    if "who" not in {column for _, column, *_ in db.execute("PRAGMA table_info(history)")}:
        try:  # which auditor decided, for their ranking later; NULL: the collector, or the owner on the server
            db.execute("ALTER TABLE history ADD COLUMN who TEXT")
        except sqlite3.OperationalError as e:  # the panel and the collector start together
            if "duplicate column" not in str(e):
                raise
    return db


def forget(db: sqlite3.Connection, domain: str, reason: str) -> None:
    """Drops a domain from verdicts, the waiting list and its shot; only history keeps it, as "forgotten"."""
    db.execute("DELETE FROM verdicts WHERE domain = ?", (domain,))
    db.execute("DELETE FROM waiting WHERE domain = ?", (domain,))
    log(db, domain, "forgotten", reason, "collector")
    db.commit()
    (SHOTS / f"{domain}.jpg").unlink(missing_ok=True)


def log(db: sqlite3.Connection, domain: str, verdict: str, reason: str | None, by: str, who: str | None = None) -> None:
    db.execute("INSERT INTO history (domain, verdict, reason, by, at, who) VALUES (?, ?, ?, ?, ?, ?)",
               (domain, verdict, reason, by, datetime.now(timezone.utc).isoformat(timespec="seconds"), who))


def main() -> None:
    token = os.getenv("META_TOKEN")
    if not token:
        print("META_TOKEN not set: collector idle, DNS keeps blocking CERT Polska + KAD domains")
        doing("nic nie robi: brak META_TOKEN w .env")
        return
    if HOME and not HOME_TOKEN:
        raise SystemExit("HOME_URL set without HOME_TOKEN: home's relay would refuse every question")
    db = open_db(VERDICTS)
    if not AGAIN:
        doing("pobiera listę popularnych domen (Tranco)")
        popular = popular_domains()  # fail fast: never auto-block without the popularity guard
    threading.Thread(target=ThreadingHTTPServer(("0.0.0.0", 9100), Metrics).serve_forever, daemon=True).start()
    day, terms = None, iter(())
    while True:
        if day != date.today():  # once a day the newest verdicts add their own search terms
            doing("wybiera nowe hasła z werdyktów i pobiera listę nowych domen")
            if not AGAIN:
                mined = mined_terms(db)
                print(f"search terms mined from verdicts: {', '.join(mined) or 'none yet'}")
                terms = itertools.cycle(SEARCH_TERMS + mined)
            day = date.today()
            doing("uczy model słów na decyzjach ludzi")
            try:
                print(f"word model trained on {train_words(db)} human decisions")
            except ValueError as e:  # e.g. no word left after the filters: yesterday's model stays
                print(f"word model not trained: {e}")
            print(f"ModernBERT regression trained on {train_bert(db)} human decisions with a vector")
            if not AGAIN:  # once a day, by the collector: 5 more trainings of each model on the CPU
                doing("mierzy trafność modeli na decyzjach ludzi")
                try:
                    for _, name, cards, right, caught, wrong in measure(db):
                        print(f"{name}: right on {right:.1%} of {cards} human decisions it did not learn from, "
                              f"bad caught {caught:.1%}, good called bad {wrong:.1%}")
                except ValueError as e:  # e.g. a fold with no word left: no measure today
                    print(f"models not measured: {e}")
            try:
                fresh = newly_registered()
                _young.clear()
                _young.update(registered_history(db, fresh))
                print(f"newly registered {'/'.join(NRD_TLDS)} domains: {len(fresh)} on the lists, "
                      f"{len(_young)} in our history")
                if not AGAIN:  # blocks once, by the collector
                    queued = impersonators(db, popular | TRUSTED | SHORTENERS | read_list(LISTS / "allow.txt"))
                    print(f"new domains named like a Polish brand: {len(_branded)}, {queued} newly blocked")
            except (OSError, ValueError, http.client.HTTPException) as e:  # CDN down: yesterday's list stays
                print(f"newly registered domains not loaded: {e}")
            try:
                _edges[:] = [*map(ipaddress.ip_network, EDGE_NETS), *aws_edges()]
            except (OSError, ValueError, KeyError) as e:  # CloudFront then looks like a server of its own: a human looks
                print(f"AWS address ranges not loaded: {e}")
        if AGAIN:
            again_cycle(db)
            continue
        wait, failed, judging, started = CYCLE_SECONDS, None, True, time.monotonic()
        try:
            collect(db, token, popular | TRUSTED | SHORTENERS | read_list(LISTS / "allow.txt"),
                    list(itertools.islice(terms, TERMS_PER_CYCLE)))
        except (OSError, Offline) as e:  # API or network hiccup: verdicts so far are in SQLite, retry next cycle
            message, wait = explain(e)
            STATS["scamdns_cycle_failures_total"] += 1
            print(message)
            failed, judging = message, meta_refused(e)  # Meta down: nothing judged again
        if skipped := skip_unlearnable(db):
            print(f"queued cards with nothing to learn from, taken off the queue: {skipped}")
        if filled := fill_vectors(db):
            print(f"ModernBERT vectors made for cards without one: {filled}")
        try:
            if judging and (blocked := recheck(db)):  # after a failed cycle the network may still be down
                print(f"queued domains with a dead page now, blocked: {blocked}")
            # the LLM down (home off at night): each would be walked for nothing; one judging takes ~30 s, so 60 s spare
            if judging and not APART and llm_up(db) and (changed := look_again(db, until=started + CYCLE_SECONDS - 60)):
                print(f"aged verdicts judged again, changed: {changed}")
        except Offline as e:
            print(f"recheck stopped: {e}")
        STATS["scamdns_last_cycle_timestamp_seconds"] = time.time()
        try:
            publish(db)  # also after a failed cycle: domains judged before the error still get blocked
        except OSError as e:
            print(f"publish failed: {e}")
        if not failed:  # 15 min from the cycle's start, not its end: Meta still gets at most 45 calls per 15 min
            wait = max(0.0, wait - (time.monotonic() - started))
        doing("czeka po błędzie" if failed else "czeka na następny cykl", failed or "", time.time() + wait)
        kill_browser()  # an idle Chromium held ~0.9 GB for the whole wait and pushed the server into swap
        time.sleep(wait)


def again_cycle(db: sqlite3.Connection, idle: int = 300) -> None:
    """One turn of the process judging again: rounds for up to a cycle, then a pause with the browser closed when
    nothing was due or the LLM is down (home off at night: each would be walked for nothing)."""
    started = time.monotonic()
    try:
        if llm_up(db) and (changed := look_again(db, until=started + CYCLE_SECONDS)):
            print(f"aged verdicts judged again, changed: {changed}")
    except Offline as e:
        print(f"judging again stopped: {e}")
    STATS["scamdns_last_cycle_timestamp_seconds"] = time.time()
    if time.monotonic() - started < 60:
        doing("czeka na werdykty do ponownej oceny albo na model", "", time.time() + idle)
        kill_browser()
        time.sleep(idle)


if __name__ == "__main__":
    main()
