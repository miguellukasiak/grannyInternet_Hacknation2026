# grannyInternet: od pojedynczej reklamy do kampanii

Demonstrator do zadania „Kolekcjoner fejków / FOLLOW THE FAKE”. Dla każdej reklamy od razu pokazuje,
**co w niej zwraca uwagę** (wstępny werdykt z punktami i powodami). Potem **łączy reklamy w kampanie** po
sygnałach tekstowych, wizualnych, semantycznych i infrastrukturalnych. Każde powiązanie ma dowód zapisany
jednym zdaniem.

Obok działa system, który te reklamy zbiera: kolektor przeszukujący bibliotekę reklam Meta według
harmonogramu, panel weryfikacji dla ludzi i filtr DNS (Blocky), który blokuje domeny oszustw.

## Szybki start (sam demonstrator kampanii)

Potrzebny jest tylko Docker.

```powershell
git clone https://github.com/miguellukasiak/grannyInternet_Hacknation2026
cd grannyInternet_Hacknation2026
docker compose up --build kampanie
```

Potem otwórz http://127.0.0.1:8501 i wgraj materiały w przeglądarce: pliki, cały folder albo ZIP (do 2 GB),
adres strony albo sam tekst reklamy.

- Tryb offline: ustaw `ONLINE=0` (PowerShell: `$env:ONLINE=0`, bash: `ONLINE=0 docker compose up --build kampanie`). Wtedy nic nie wychodzi z kontenera, a wklejony adres jest tylko zapisany. Bez tej zmiennej moduł pyta RDAP o wiek domen docelowych i pobiera wklejoną stronę (z blokadą adresów prywatnych, SSRF).
- Wgrane materiały i ich cechy trafiają do wolumenu `kampanie` (`/data/baza.json`). Materiał usuwa się na jego stronie, całą bazę przyciskiem „Wyczyść bazę”.
- Domeny zablokowane przez kolektor: gdy działa cały system, kontener widzi `verdicts.db` tylko do odczytu (wolumen `verdicts`, zmienna `KOLEKTOR`) i przycisk „Wczytaj zablokowane domeny” wczytuje je jako materiały: tekst reklamy, stronę, linki, IP, wiek domeny, piksele i stronę FB. Bez tej bazy przycisku nie ma.
- Bez GUI: `docker compose run --rm -v "${PWD}/folder:/x:ro" kampanie python kampanie.py /x` wypisuje kampanie i werdykty jako tekst (każdy podfolder to jeden materiał).
- Testy: `docker compose run --rm --no-deps kampanie python -m unittest -v`.

### Co przyjmuje

Jedno wgranie zamienia się w materiały tak:

- pliki jednego incydentu (zrzuty, zapisana strona, HAR) dają **jeden materiał**;
- folder albo ZIP, w którym wszystkie pliki leżą w podfolderach, daje **materiał na podfolder** (zestaw incydentów);
- foldery-opakowania, w których jest tylko jeden podfolder, są pomijane, a ostatni z nich daje nazwę;
- adres strony albo tekst reklamy razem z plikami daje zawsze jeden materiał.

Zestaw wielu incydentów jest analizowany w tle, a strona sama się odświeża. Rozpoznawane są:

| Plik | Co z niego bierzemy |
|---|---|
| `.html`, `.htm`, `.mhtml` | tekst, linki, domeny, identyfikatory śledzące (piksel Meta, GA, GTM i inne), schemat parametrów linku, zasoby strony, szablon HTML |
| `.har` | łańcuch przekierowań, adresy IP serwerów, wszystkie domeny i zasoby z ruchu |
| `.png`, `.jpg`, `.webp`, `.gif`, `.bmp` | OCR (tesseract pol+eng): podpis reklamy, adres z paska przeglądarki; dHash obrazu |
| `.info.json` (yt-dlp) | opis i tytuł wideo, identyfikatory reklamy |
| `.mp4`, `.webm` i inne wideo | odnotowane jako materiał; treść tylko z metadanych |
| `.txt` | tekst reklamy, adresy w treści |

Pojedynczy materiał od razu pokazuje
werdykt, przypisanie do istniejącej kampanii (z dowodem najsilniejszego powiązania) albo informację
„nowy wzorzec”.

## Metodyka

### 1. Cechy materiału

Tekst (z HTML, OCR, metadanych), 5-wyrazowe fragmenty tekstu (shingles), wektor TF-IDF narracji, znane osoby,
marki, pod które strona się podszywa, tematy (inwestycje, zdrowie, hazard…), domeny strony docelowej
i przekierowań (tldextract), identyfikatory reklamowe i analityczne, schemat parametrów linku z reklamy,
adresy IP, dHash obrazów, nazwy plików zasobów i struktura szablonu HTML.

### 2. Porównanie par: przesłanki

Dwa materiały są porównywane sygnał po sygnale. Każdy pasujący sygnał to jedna przesłanka z siłą i zdaniem
„dlaczego”:

| Przesłanka | Siła |
|---|---|
| ten sam identyfikator reklam/analityki | 0,95 |
| ta sama domena strony docelowej | 0,90 |
| wspólne 5-wyrazowe fragmenty tekstu (Jaccard ≥ 15%) | 0,3 + udział, do 0,95 |
| te same obrazy (dHash całości i środka po obcięciu 5% i 10% brzegów, różnica ≤ 4 z 64 bitów) | 0,6 + 0,1 za każdy kolejny, do 0,9 |
| podobna narracja (kosinus TF-IDF ≥ 0,25) | 0,8 × kosinus, do 0,7 |
| ten sam schemat parametrów linku | 0,6 |
| wspólne domeny w linkach i zasobach | 0,3 za domenę, do 0,6 |
| te same pliki strony | 0,15 za plik, do 0,6 |
| zbliżony szablon HTML (≥ 30% wspólnej struktury) | 0,6 × udział |
| ten sam adres IP serwera (poza CDN i hostingiem współdzielonym) | 0,4 |
| te same osoby | 0,35 |
| ta sama podrabiana marka | 0,30 |
| ten sam temat | 0,15 |

Przesłanki składają się jak niezależne poszlaki: `wynik = 1 − ∏(1 − siła)`. Sygnały wspólne dla co najmniej
40% materiałów (platformy, CDN-y, popularne biblioteki) i lista domen ogólnych (facebook.com,
googleapis.com…) nie są przesłanką. Adresy anycast Cloudflare i Shopify też nie, bo odpowiadają z nich tysiące
niezwiązanych stron. To samo dotyczy każdego IP, z którego w bazie odpowiada co najmniej 20 domen: to hosting
współdzielony (w bazie kolektora np. Lovable, Netlify, Vercel), a nie jeden właściciel. Wspólny serwer ma siłę poniżej progu kampanii, bo hosting współdzielony obsługuje wiele obcych
sobie stron, więc sam nie tworzy kampanii. Subdomeny platform (x.netlify.app, y.myshopify.com, z.lovable.app) to
osobne strony, a nie jedna domena.

**Brak danych to brak przesłanki, nigdy przesłanka przeciw.** Strona, która już nie działa, łączy się dalej
tekstem reklamy i zrzutem ekranu. Każdy materiał ma listę tego, czego zabrakło (np. „brak tekstu”, „RDAP: brak
odpowiedzi”), więc widać, na czym opiera się wynik.

### 3. Grupowanie

- **Kampania**: grupowanie aglomeracyjne z pojedynczym wiązaniem (single linkage) na odległości `1 − wynik`
  przy progu 0,5. Każdy członek kampanii ma co najmniej jedno powiązanie o sile ≥ 0,5 i właśnie to powiązanie
  jest pokazane jako dowód. Powiązanie musi mieć co najmniej jedną twardą przesłankę (identyfikator, domena,
  tekst skopiowany co najmniej w 40%, obraz, szablon, pliki). Sama narracja, temat, osoba, marka i serwer nie
  wystarczą: na 5404 zablokowanych domenach kolektora skleiły w łańcuch 1054 domeny ze zdrowiem, paczkami i
  inwestycjami naraz. Schemat parametrów linku też jest tylko poszlaką (`utm_source,utm_medium,utm_campaign`
  ma każdy reklamodawca), a 15–20% wspólnego tekstu to zwykle stopka kasy tej samej platformy sklepowej: razem
  trzymały jeszcze łańcuch 431 domen.
- **Rodzina kampanii**: wiązanie średnie (average linkage) przy progu 0,2. Słabe poszlaki, takie jak temat
  czy osoba, łączą wtedy kampanie w rodziny, ale nie sklejają wszystkiego w łańcuch.
- **Duplikaty i warianty**: ten sam tekst (Jaccard fragmentów ≥ 0,9) albo ta sama domena docelowa przy
  Jaccardzie ≥ 0,7. Kopia pod inną domeną jest więc oznaczona jako duplikat, a reszta kampanii to warianty.
- **Nowy materiał**: trafia do kampanii, z którą ma najsilniejsze powiązanie ≥ 0,5 z twardą przesłanką. Jeśli takiego nie ma,
  dostaje status „nowy wzorzec” razem z informacją, co było najbliżej.

### 4. Wstępny werdykt

Punkty za cechy oszustwa, każda z powodem:

| Cecha | Punkty |
|---|---|
| wizerunek znanej osoby przy obietnicy zarobku | 3 |
| strona podaje się za markę, a działa na obcej domenie | 3 |
| sensacyjna „wiadomość” o znanej osobie; znana osoba poleca środek na zdrowie | 2 |
| nazwa domeny udaje markę; młoda domena (RDAP) | 2 |
| obietnica cudownego leczenia; gra hazardowa w reklamie | 2 |
| tania domena jednorazowa; przekierowania przez kilka domen | 1 |
| formularz zbiera telefon; presja czasu; wklejone „komentarze z Facebooka” | 1 |
| strona udająca medium mierzy ruch z reklam pikselem | 1 |

Wynik: ≥ 4 punkty to **wysokie ryzyko**, ≥ 2 to **podejrzane**, a mniej to brak wyraźnych cech.

### 5. Weryfikacja zrzutu strony

Zrzut ekranu jest pełnoprawnym materiałem. OCR odczytuje podpis reklamy i adres z paska przeglądarki, który
trafia do domen jak link. dHash łączy ten sam obraz po przeskalowaniu, ponownej kompresji, zmianie jasności i obcięciu brzegów. Na 147 obrazach zestawu organizatora daje 20 par, wszystkie trafne; przy progu 5 łączył też dwie pary różnych twarzy w jednakowej okrągłej ramce. Nie łączy obrazu przyciętego z jednej strony ani przerobionego (inne imię na tym samym fałszywym panelu banku). Zrzut strony,
która zniknęła, nadal łączy się z kampanią przez tekst, adres i obraz.

### 6. Interfejs

- `/#zglos`: zgłoszenie podejrzanej domeny, tak jak na grannyinternet.me. Domena, którą baza już zna, od razu pokazuje, kto ją zablokował (reguła, model albo człowiek) i do jakiej kampanii należy. Nowa domena staje się materiałem i dostaje werdykt.
- `/`: wgrywanie materiałów (pliki, folder, ZIP, adres, tekst), kampanie z rodzinami, domenami, duplikatami i najmocniejszymi parami wraz z przesłankami oraz tabela materiałów z werdyktami.
- `/m/<id>`: werdykt z punktami, cechy, brakujące dane oraz kampania i najbliższe materiały; tu materiał usuwa się z bazy.
- `/graf`: graf powiązań (SVG), kampanie jako pierścienie.
- `/eksport.json`: kampanie, pary i przesłanki do dalszej obróbki.

Serwer to biblioteka standardowa Pythona (`ThreadingHTTPServer`). Ma nagłówek CSP i escapowanie każdego pola,
a w `docker-compose.yml` port jest wystawiony tylko na 127.0.0.1.

## Cały system

`docker compose up -d` uruchamia resztę (potrzebny jest plik `.env` na wzór `.env.example`):

| Usługa | Rola |
|---|---|
| `collector` | **Automatyczne przeszukiwanie biblioteki reklam Meta według harmonogramu.** Hasła są dobierane z zablokowanych reklam z różnych kampanii. Kolektor otwiera reklamę w Chromium (Playwright) jak użytkownik telefonu, sprawdza firmę (CEIDG, GUS REGON, biała lista VAT, VIES) i domenę (RDAP), stosuje reguły i lokalny model językowy, a wynik zapisuje w `verdicts.db`. Nie pobiera plików ze skanowanych stron. |
| `again` | ta sama logika, która drugi raz ocenia starsze werdykty |
| `panel` | panel weryfikacji: człowiek zatwierdza albo odrzuca decyzje z kolejki (http://127.0.0.1:8080) |
| `lists` | składa listy blokad z `sources.toml` i `lists/` w jedną bazę SQLite dla Blocky |
| `blocky` | filtr DNS, który blokuje domeny oszustw |
| `warp` | Cloudflare WARP jako proxy tylko dla stron, które odcinają adresy serwerowe |
| `home` | przekaźnik do lokalnej Ollamy, gdy reszta działa na serwerze |
| `prometheus`, `grafana` | metryki i pulpit (http://127.0.0.1:3000) |

`site/` to strona projektu i strona dla jury (Cloudflare Pages). Adres panelu audytora jest w niej zastąpiony
symbolem `https://panel.example.org`.

### Wyniki na naszej bazie

Liczby z kopii bazy kolektora, porównane z decyzjami ludzi:

- Osiem małych modeli lokalnych oceniało 2 008 decyzji ludzi. **qwen3.5:4b** zgadzał się w 57,6% przypadków
  i dawał najmniej fałszywych alarmów. Razem z regułami kolektora daje 73,5%.
- Klasyfikator na słowach osiąga 80,1%, pl-ModernBERT 79,2%, a oba razem 80,6%.

## Zgodność z wymaganiami zadania

| Wymaganie | Gdzie |
|---|---|
| grupowanie w kampanie po sygnałach tekstowych, wizualnych, semantycznych, infrastrukturalnych | `kampanie/kampanie.py` (`Base.compare`, `Base.campaigns`) |
| duplikaty i warianty | `Base.duplicate`, sekcja „Duplikaty” w GUI |
| nowy materiał → kampania albo nowy wzorzec | `Base.place`, formularz w GUI |
| dowody powiązań | przesłanki z siłą i zdaniem przy każdej parze, graf, eksport JSON |
| brakujące dane | lista „czego zabrakło” przy każdym materiale; brak danych nie obniża wyniku |
| GUI | `kampanie/app.py`, port 8501 |
| kontener | `kampanie/Dockerfile`, usługa `kampanie` w `docker-compose.yml` |
| bonus: biblioteki reklam i harmonogram | `collector/collector.py` (Meta Ad Library, cykle z hasłami) |

## Komponenty zewnętrzne i licencje

Kod tego repozytorium jest na licencji MIT (`LICENSE`).

| Komponent | Do czego | Licencja |
|---|---|---|
| Python 3.14 | środowisko | PSF-2.0 |
| Pillow 12.0.0 | obrazy, dHash | MIT-CMU (HPND) |
| scikit-learn 1.7.2 | TF-IDF, grupowanie aglomeracyjne | BSD-3-Clause |
| NumPy (zależność scikit-learn) | obliczenia | BSD-3-Clause |
| tldextract 5.4.0 | domeny rejestrowalne | BSD-3-Clause |
| Tesseract OCR + dane pol/eng | OCR zrzutów | Apache-2.0 |
| Playwright 1.55.0 + Chromium | otwieranie reklam w kolektorze | Apache-2.0 / BSD-3-Clause |
| PyTorch 2.14.1 (CPU) | ModernBERT | BSD-3-Clause |
| Transformers 5.22.1 | ModernBERT | Apache-2.0 |
| OPI-PIB/pl-ModernBERT-512-base | druga opinia o reklamie | Apache-2.0 |
| Ollama | lokalny model językowy | MIT |
| qwen3.5:4b | ocena reklam w kolektorze | Apache-2.0 |
| Blocky v0.35.0 | filtr DNS | Apache-2.0 |
| Prometheus v3.5.0 | metryki | Apache-2.0 |
| Grafana 12.1.0 | pulpit | AGPL-3.0 |
| Cloudflare WARP | proxy dla kolektora | własnościowa (warunki Cloudflare) |
| Atkinson Hyperlegible Next, Libre Franklin (`site/fonts`) | fonty strony | SIL OFL 1.1 |

Usługi, z których korzysta kolektor: Meta Ad Library API (warunki Meta), CEIDG API, GUS REGON (BIR), biała
lista podatników VAT (MF), VIES (KE), RDAP (rdap.org, dns.pl). Moduł kampanii korzysta tylko z RDAP i tylko
w trybie `ONLINE=1`.

Listy blokad są pobierane w czasie działania i nie są rozpowszechniane w repozytorium. Każda ma w
`sources.toml` adres i licencję. Część z nich jest niekomercyjna (np. someonewhocares, MVPS) albo ma licencję
nieznaną. Przed użyciem komercyjnym takie listy trzeba wyłączyć.

Dane organizatora nie są częścią repozytorium. Wgrywa się je w przeglądarce i zostają w lokalnym wolumenie Dockera.
