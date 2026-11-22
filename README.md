# grannyInternet: od pojedynczej reklamy do kampanii

Demonstrator do zadania „Kolekcjoner fejków / FOLLOW THE FAKE”. Dla każdej reklamy od razu pokazuje,
**co w niej zwraca uwagę** (wstępny werdykt z punktami i powodami). Potem **łączy reklamy w kampanie** na
podstawie sygnałów tekstowych, wizualnych, semantycznych i infrastrukturalnych. Każde powiązanie ma dowód
opisany jednym zdaniem.

Obok działa system, który te reklamy zbiera: kolektor przeszukujący bibliotekę reklam Meta według
harmonogramu, panel weryfikacji dla ludzi i filtr DNS (Blocky), który blokuje domeny oszustw.

## Działa na żywo

| Adres | Co tam jest |
|---|---|
| https://kampanie.grannyinternet.me/ | demonstrator kampanii: wgrywanie materiałów, kampanie z dowodami, graf, eksport |
| https://grannyinternet.me/ | w czasie hackathonu przekierowuje (302) na demonstrator |
| https://grannyinternet.me/audytorzy/ | strona dla jury i dla ludzi: jak działa cały system |

Demonstrator działa na naszym serwerze razem z kolektorem i ma dostęp tylko do odczytu do jego bazy werdyktów.
Najszybciej sprawdzić go tak:

1. **Wczytaj zablokowane domeny** (sekcja „Dodaj materiał”). Domeny zablokowane przez kolektor wchodzą jako
   materiały: tekst reklamy, strona, linki, IP, wiek domeny, piksele i strona na Facebooku. Po chwili widać
   kampanie, które z nich powstały.
2. **Dodaj własny materiał** (`/#dodaj`): zrzut reklamy, zapisaną stronę, HAR, folder, ZIP, sam adres albo
   sam tekst reklamy. Materiał dostaje werdykt i trafia do kampanii albo zostaje nowym wzorcem.
3. Otwórz dowolną kampanię i parę materiałów. Przy każdej parze widać przesłanki: z jaką siłą i dlaczego.

Gdyby serwer przestał działać, na końcu tego pliku jest [uruchomienie u siebie w Dockerze](#ostatnia-deska-ratunku-uruchomienie-u-siebie).

## Jak łączymy reklamy w kampanie

W skrócie: każdy materiał rozkładamy na cechy. Każdą parę materiałów porównujemy cecha po cesze. Każda wspólna
cecha jest jedną przesłanką z siłą od 0 do 1 i ze zdaniem „dlaczego”. Przesłanki składamy jak niezależne
poszlaki. Wcześniej wyrzucamy to, co wspólne dla platform, a nie dla jednego autora. Kampania powstaje tylko
z powiązań, w których jest co najmniej jedna **twarda** przesłanka. Cały kod jest w `kampanie/kampanie.py`.

### 1. Materiał

Materiał to jeden incydent: jedna reklama ze wszystkim, co o niej wiadomo. Jedno wgranie zamienia się
w materiały tak:

- pliki jednego incydentu (zrzuty, zapisana strona, HAR) dają **jeden materiał**;
- folder albo ZIP, w którym wszystkie pliki leżą w podfolderach, daje **materiał na każdy podfolder** (zestaw incydentów);
- foldery-opakowania z jednym tylko podfolderem są pomijane, a ostatni z nich daje nazwę;
- adres strony albo tekst reklamy razem z plikami daje zawsze jeden materiał.

| Plik | Co z niego bierzemy |
|---|---|
| `.html`, `.htm`, `.mhtml` | tekst, tytuł, linki, domeny, identyfikatory śledzące, e-maile, pola formularzy, nazwy zasobów, szablon HTML |
| `.har` | łańcuch przekierowań, adresy IP serwera strony, wszystkie domeny z ruchu, zapytania strony do własnego API, treść własnych plików CSS/JS |
| `.png`, `.jpg`, `.webp`, `.gif`, `.bmp` | OCR (tesseract pol+eng): podpis reklamy, adres z paska przeglądarki; dHash obrazu |
| `.info.json` (yt-dlp) | opis i tytuł wideo, identyfikatory reklamy, nazwa strony reklamodawcy na Facebooku |
| `.css`, `.js` z folderu `_files` zapisanej strony | odcisk (sha1) własnego pliku strony |
| `robots.txt` | nietypowe reguły jako ślad autora; sam „Disallow: /” jako cecha strony |
| `.txt` | tekst reklamy, adresy w treści |
| `.mp4`, `.webm` i inne wideo | odnotowane; treść tylko z metadanych i zrzutów |

Sam adres strony demonstrator pobiera (tylko HTML, nigdy plików): idzie za przekierowaniami, każde sprawdzając,
czy prowadzi na adres publiczny (ochrona przed SSRF), czyta `robots.txt` i pyta RDAP o wiek domeny. Gdy podstrona
odmawia (403, 429, 503), czyta stronę główną tej samej domeny. Szablon, piksele, pliki, `robots.txt` i IP sklepu
są tam te same, a karta materiału nadal mówi, że podstrona odmówiła.

### 2. Cechy

| Cecha | Skąd | Do czego |
|---|---|---|
| tekst i 5-wyrazowe fragmenty (shingles, crc32) | HTML, OCR, metadane, wklejony tekst | kopie i warianty tego samego tekstu |
| wektor TF-IDF | tekst bez słów funkcyjnych | podobna narracja innymi słowami |
| znane osoby, marki, tematy | słowniki (rdzenie z odmianą: Brzoska, Brzoskę) | poszlaki i werdykt |
| domeny strony docelowej i przekierowań | adres, HAR, zapisana strona, pasek z OCR | ta sama strona |
| pozostałe domeny | linki, zasoby, ruch | wspólna infrastruktura |
| identyfikatory | piksel Meta, GA, GTM, Google Ads, piksel TikTok, Yandex Metrica, `ad_id`, `campaign_id`, weryfikacja domeny Meta/Google | to samo konto reklamowe = ten sam właściciel |
| schemat parametrów linku | nazwy parametrów linku z reklamy (co najmniej 3) | ten sam system kampanii |
| ślady autora | wygenerowana nazwa parametru, nietypowy `robots.txt`, e-mail (zapisane jako skrót sha1) | jeden autor wielu stron |
| własne pliki CSS/JS | sha1 treści (nazwa nie ma znaczenia) | ten sam plik = ten sam autor |
| zestaw (API strony) | zapytania POST/PUT strony do własnego serwera, z identyfikatorami zamienionymi na `*` | ten sam „zestaw do oszustw” po stronie serwera |
| szablon HTML | crc32 6-tagowych ciągów struktury strony (tag + 2 klasy) | ta sama strona z innym tekstem |
| obrazy | dHash 64-bitowy całości i środka (po obcięciu 5% i 10% brzegów) | ten sam obraz po przeskalowaniu i przycięciu |
| adresy IP serwera | HAR, pobrana strona | wspólny serwer (tylko poszlaka) |

### 3. Przesłanki i ich siła

Dwa materiały porównujemy sygnał po sygnale (`Base.compare`). Każdy pasujący sygnał to jedna przesłanka.

| Przesłanka | Siła | Twarda? |
|---|---|---|
| ten sam identyfikator reklam lub analityki | 0,95 | tak |
| ta sama domena strony docelowej | 0,90 | tak |
| identyczne własne pliki CSS/JS | 0,7 + 0,1 za plik, do 0,9 | tak |
| te same obrazy | 0,6 + 0,1 za każdy kolejny, do 0,9 | tak |
| wspólna wygenerowana nazwa parametru w linku | 0,85 | tak |
| to samo API strony (zestaw) | 0,4 za ścieżkę, do 0,8 | tak |
| wspólne 5-wyrazowe fragmenty tekstu (Jaccard ≥ 15%) | 0,3 + udział, do 0,95 | tak, gdy udział ≥ 40% |
| ten sam nietypowy `robots.txt` | 0,6 | tak |
| zbliżony szablon HTML (≥ 30% wspólnej struktury) | 0,6 × udział | tak |
| wspólne domeny w linkach i zasobach | 0,3 za domenę, do 0,6 | tak |
| te same pliki strony (po nazwie) | 0,15 za plik, do 0,6 | tak |
| ten sam e-mail na stronie | 0,45 | tak |
| podobna narracja (kosinus TF-IDF ≥ 0,25) | 0,8 × kosinus, do 0,7 | nie |
| ten sam schemat parametrów linku | 0,6 | nie |
| ten sam adres IP serwera | 0,4 | nie |
| te same osoby | 0,35 | nie |
| ta sama podrabiana marka | 0,30 | nie |
| ten sam temat | 0,15 | nie |

Przesłanki składają się jak niezależne poszlaki:

```
wynik = 1 − ∏(1 − siła)
```

Przykład rachunku: 50% wspólnego tekstu (0,8), ten sam obraz (0,6) i ten sam temat (0,15) dają
`1 − 0,2 × 0,4 × 0,85 = 0,93`. Każda przesłanka może tylko podnieść wynik. Żadna go nie obniża.

**Ślady autora.** To cechy, które zostawia jeden człowiek albo jeden zestaw do oszustw, a nie platforma.
Sprawdziliśmy je na bazie kolektora z 22.11 na unikalnych stronach docelowych (zablokowane : przepuszczone):

- wygenerowana nazwa parametru w linku (np. 15 liter bez samogłosek, której nikt nie wybrał ręcznie): 62 : 0, w 16 grupach i żadna nie jest mieszana;
- ten sam nietypowy `robots.txt` (co najmniej 3 reguły, bez domyślnych reguł WordPressa i Shopify): 183 : 0;
- ten sam e-mail: 125 zablokowanych stron, ale część grup to agencje i hostingi z mieszanymi stronami, dlatego ma najniższą siłę.

Wartości śladów zapisujemy tylko jako skrót sha1, bo to tokeny oszustów albo czyjś e-mail.

### 4. Co nie jest dowodem

Większość fałszywych powiązań bierze się z rzeczy wspólnych dla tysięcy niezwiązanych stron. Dlatego przed
porównaniem odrzucamy:

- **wszystko, co ma co najmniej 40% materiałów** w bazie (domena, zasób, IP, plik, API, ślad). To platforma, nie kampania;
- **własne API i pliki CSS/JS** odrzucamy dopiero od 10 materiałów. W małym zbiorze wspólny plik to zwykle sama kampania;
- **listę domen ogólnych**: facebook.com, googleapis.com, gstatic.com, jsdelivr.net, amazon.*, allegro.pl,
  temu.com, linktr.ee, bit.ly, wa.me i podobne (amazon.com był celem 121 naszych zablokowanych domen);
- **adresy anycast Cloudflare i Shopify**, bo z jednego IP odpowiadają tysiące stron;
- **każde IP, z którego odpowiada co najmniej 20 domen bazy**. To hosting współdzielony (w bazie kolektora
  np. Lovable, Netlify, Vercel), a nie jeden właściciel. Próg wyliczamy z samych danych;
- **kopie popularnych bibliotek** (jQuery, Bootstrap, fbevents, Swiper, skrypty Map Google…) i pliki motywów
  WordPressa i Shopify. Ten sam motyw obsługuje tysiące sklepów;
- **subdomeny platform** (x.netlify.app, y.myshopify.com, z.lovable.app, a także b-cdn.net, surge.sh, tilda.ws
  i inne spoza Public Suffix List). To osobne strony osobnych właścicieli, a nie jedna domena;
- **nazwy parametrów, które ktoś wybrał** (`campaign`, `source`, `utm_*`, `variant`, `pixel`…). Za ślad autora
  uznajemy tylko nazwy wygenerowane.

Wspólny serwer ma siłę 0,4, czyli poniżej progu kampanii. Nawet po tych filtrach jeden serwer obsługuje wiele
obcych sobie stron.

### 5. Twarde i miękkie przesłanki

Miękkie przesłanki to narracja, temat, osoba, marka, serwer i schemat parametrów. Bez twardej przesłanki
powiązanie nie tworzy kampanii (`Base.link`), choćby wynik był wysoki. Przykład: podobna narracja (0,7),
ta sama osoba (0,35), ten sam temat (0,15) i ten sam serwer (0,4) dają razem 0,90, a nie dowodzą niczego.
Tak samo wyglądają niezwiązane oszustwa, które pożyczają tę samą twarz.

Sprawdziliśmy to na 5404 domenach zablokowanych przez kolektor:

- same miękkie przesłanki skleiły w jeden łańcuch **1054 domeny** ze zdrowiem, paczkami i inwestycjami naraz;
- po wyłączeniu narracji, tematów i osób łańcuch **431 domen** trzymały jeszcze dwie rzeczy: schemat
  `utm_source,utm_medium,utm_campaign`, który ma każdy reklamodawca, i 15–20% wspólnego tekstu. Tyle zwykle
  zajmuje stopka kasy tej samej platformy sklepowej. Dlatego tekst jest twardy dopiero od 40% wspólnych fragmentów.

### 6. Grupowanie

- **Kampania**: grupowanie aglomeracyjne (scikit-learn) z pojedynczym wiązaniem (single linkage) na odległości
  `1 − wynik` przy progu 0,5. Liczymy je na macierzy samych twardych powiązań. Każdy członek ma co najmniej
  jedno powiązanie o sile ≥ 0,5 z twardą przesłanką. Właśnie to powiązanie jest pokazane jako dowód, więc
  każdy element kampanii da się prześledzić do konkretnej pary.
- **Rodzina kampanii**: wiązanie średnie (average linkage) przy progu 0,2 na pełnej macierzy, z miękkimi
  przesłankami. Temat czy osoba łączą wtedy kampanie w rodziny, ale nie sklejają wszystkiego w łańcuch, bo
  liczy się średnia ze wszystkich par, a nie jedna para.
- **Duplikaty i warianty**: duplikat to ten sam tekst (Jaccard fragmentów ≥ 0,9) albo ta sama domena przy
  Jaccardzie ≥ 0,7. Kopia pod inną domeną jest więc duplikatem, a reszta kampanii to warianty.
- **Nowy materiał** (`Base.place`): trafia do kampanii, z którą ma najsilniejsze twarde powiązanie ≥ 0,5. Jeśli
  takiego nie ma, dostaje status „nowy wzorzec” razem z ośmioma najbliższymi materiałami i średnim dopasowaniem
  do każdej kampanii. Materiał wgrany drugi raz jest rozpoznawany i nie powstaje jego kopia w bazie.
- **Etykieta kampanii**: trzy najczęstsze osoby, marki lub tematy jej członków. Przy kampanii widać też,
  jakie przesłanki ją łączą, jej domeny, duplikaty i cztery najmocniejsze pary.

### 7. Skala

Porównanie każdej pary z każdą przy tysiącach materiałów trwałoby zbyt długo, więc `Base.candidates` wybiera
tylko pary, które coś łączy: wspólna domena, IP, plik, identyfikator, ślad, osoba czy temat. Kosinusy tekstów
i Jaccardy fragmentów oraz szablonów liczymy iloczynami macierzy rzadkich w blokach po 1000 wierszy. Pary bez
żadnej wspólnej cechy mają wynik 0 i nigdy nie są porównywane.

### 8. Brak danych

**Brak danych to brak przesłanki, nigdy przesłanka przeciw.** Strona, która już nie działa, łączy się dalej
tekstem reklamy i zrzutem ekranu. Każdy materiał ma listę tego, czego zabrakło (np. „brak tekstu”, „RDAP: brak
odpowiedzi”, „strona główna też niedostępna”), więc widać, na czym opiera się wynik.

### 9. Weryfikacja zrzutu i obrazów

Zrzut ekranu jest pełnoprawnym materiałem. OCR odczytuje podpis reklamy i adres z paska przeglądarki, który
trafia do domen tak jak link. dHash łączy ten sam obraz po przeskalowaniu, ponownej kompresji, zmianie jasności
i obcięciu brzegów. Dwa obrazy są tym samym, gdy różnią się co najwyżej 4 z 64 bitów. Na 147 obrazach zestawu
organizatora daje to 20 par i wszystkie są trafne. Przy progu 5 łączyły się też dwie pary różnych twarzy
w jednakowej okrągłej ramce, dlatego próg wynosi 4. dHash nie łączy obrazu przyciętego z jednej strony ani
przerobionego (inne imię na tym samym fałszywym panelu banku). Zrzut strony, która zniknęła, nadal łączy się
z kampanią przez tekst, adres i obraz.

## Wstępny werdykt

Niezależnie od kampanii każdy materiał dostaje punkty za cechy oszustwa, każdą z powodem (`flags`):

| Cecha | Punkty |
|---|---|
| wizerunek znanej osoby przy obietnicy zarobku | 3 |
| strona podaje się za markę, a działa na obcej domenie | 3 |
| sensacyjna „wiadomość” o znanej osobie; znana osoba poleca środek na zdrowie | 2 |
| nazwa domeny udaje markę; młoda domena (RDAP, poniżej 180 dni) | 2 |
| obietnica cudownego leczenia; gra hazardowa w reklamie | 2 |
| chiński dwukropek „：” w polskim tekście | 2 |
| co najmniej 50 niewidocznych znaków wciśniętych w słowa | 2 |
| strona na FB nazwana jak sklep-wydmuszka („xxx-store”) | 2 |
| „lekarz” na FB, a sklep nie nosi jego nazwiska | 2 |
| cyrylica w parametrze linku strony | 2 |
| tania domena jednorazowa; przekierowania przez kilka domen | 1 |
| formularz zbiera telefon; presja czasu; wklejone „komentarze z Facebooka” | 1 |
| strona udająca medium mierzy ruch z reklam pikselem | 1 |
| strona nie używa żadnego narzędzia do mierzenia ruchu | 1 |
| cyrylica lub greka w środku łacińskiego słowa (ЅMҮК); litery z ozdobnej czcionki Unicode | 1 |
| `robots.txt` zamyka całą stronę; link prowadzi do losowego tokenu; słowo „WYŁĄCZONY” w kodzie strony | 1 |

Wynik: ≥ 4 punkty to **wysokie ryzyko**, ≥ 2 to **podejrzane**, mniej to słaby sygnał albo brak wyraźnych cech.

Nowe cechy sprawdziliśmy na danych, zanim dostały punkty:

- na unikalnych stronach docelowych z bazy kolektora z 22.11 (zablokowane : przepuszczone): goły `robots.txt`
  526 : 4, token w linku 481 : 6 (oba naraz 342 : 1), „WYŁĄCZONY” 136 : 5, cyrylica w linku 14 : 0, chiński
  dwukropek 87 : 0. Brak narzędzi do mierzenia ruchu ma 45% zablokowanych (1850 z 4143) i 9% przepuszczonych
  (79 z 884), dlatego daje tylko 1 punkt;
- na decyzjach ludzi z kopii bazy kolektora z 21.11 (886 złych, 914 dobrych): ozdobna czcionka 15 : 16 i
  cyrylica w nazwie strony FB 4 : 5. Same nic nie znaczą, dlatego dają po 1 punkcie. Strona FB typu
  „xxx-store” wypadła 7 : 1, a „lekarz” na sklepie nienazwanym od niego 10 : 2.

## Interfejs

- `/`: sekcje „Dodaj materiał” (`/#dodaj`: pliki, folder, ZIP, adres, tekst oraz wczytanie domen zablokowanych
  przez kolektor), „Kampanie” (rodziny, domeny, duplikaty, najmocniejsze pary z przesłankami, serwery stron)
  i „Materiały” (tabela z werdyktami i filtrami).
- `/m/<id>`: werdykt z punktami, cechy, brakujące dane, kampania i najbliższe materiały. Tu materiał usuwa się z bazy.
- `/graf`: graf powiązań (SVG), kampanie jako pierścienie; `/graf.json` to jego dane.
- `/eksport.json`: kampanie, pary i przesłanki do dalszej obróbki.

„Serwery stron” przy kampanii pokazują dostawcę (ASN) i kraj z DB-IP Lite, sprawdzane lokalnie w kontenerze.
To tylko informacja, a nie dowód powiązania.

Serwer to biblioteka standardowa Pythona (`ThreadingHTTPServer`). Ma nagłówek CSP i escapowanie każdego pola.

## Cały system

| Usługa | Rola |
|---|---|
| `collector` | **Automatyczne przeszukiwanie biblioteki reklam Meta według harmonogramu.** Hasła są dobierane z zablokowanych reklam z różnych kampanii. Kolektor otwiera reklamę w Chromium (Playwright) jak użytkownik telefonu, sprawdza firmę (CEIDG, GUS REGON, biała lista VAT, VIES) i domenę (RDAP), stosuje reguły i lokalny model językowy, a wynik zapisuje w `verdicts.db`. Nie pobiera plików ze skanowanych stron. |
| `again` | ta sama logika, która drugi raz ocenia starsze werdykty |
| `panel` | panel weryfikacji: człowiek zatwierdza albo odrzuca decyzje z kolejki |
| `kampanie` | ten demonstrator; bazę kolektora widzi tylko do odczytu |
| `lists` | składa listy blokad z `sources.toml` i `lists/` w jedną bazę SQLite dla Blocky |
| `blocky` | filtr DNS, który blokuje domeny oszustw |
| `warp` | Cloudflare WARP jako proxy tylko dla stron, które odcinają adresy serwerowe |
| `home` | przekaźnik do lokalnej Ollamy, gdy reszta działa na serwerze |
| `prometheus`, `grafana` | metryki i pulpit |

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
| grupowanie w kampanie po sygnałach tekstowych, wizualnych, semantycznych, infrastrukturalnych | `kampanie/kampanie.py` (`Base.compare`, `Base.link`, `Base.campaigns`) |
| duplikaty i warianty | `Base.duplicate`, sekcja „Duplikaty” przy kampanii |
| nowy materiał → kampania albo nowy wzorzec | `Base.place`, sekcja „Dodaj materiał” |
| dowody powiązań | przesłanki z siłą i zdaniem przy każdej parze, graf, eksport JSON |
| brakujące dane | lista „czego zabrakło” przy każdym materiale; brak danych nie obniża wyniku |
| GUI | `kampanie/app.py`, https://kampanie.grannyinternet.me/ |
| kontener | `kampanie/Dockerfile`, usługa `kampanie` w `docker-compose.yml` |
| bonus: biblioteki reklam i harmonogram | `collector/collector.py` (Meta Ad Library, cykle z hasłami) |

## Komponenty zewnętrzne i licencje

Kod tego repozytorium jest na licencji MIT (`LICENSE`). Niżej wszystko, czego używamy, a czego nie napisaliśmy:
biblioteki, modele, obrazy, usługi i dane, z licencją, ograniczeniami i sposobem uzyskania dostępu.
Graf, interfejs demonstratora i panel to nasz kod, bez zewnętrznych bibliotek JS.

### Biblioteki i narzędzia

| Komponent | Do czego | Licencja | Ograniczenia |
|---|---|---|---|
| Python 3.14 (obraz `python:3.14-slim`, Debian) | środowisko | PSF-2.0; pakiety Debiana na własnych licencjach | brak |
| SQLite (moduł `sqlite3` Pythona) | bazy werdyktów i list | domena publiczna | brak |
| Pillow 12.0.0 | obrazy, dHash | MIT-CMU (HPND) | brak |
| scikit-learn 1.7.2 | TF-IDF, grupowanie aglomeracyjne | BSD-3-Clause | brak |
| NumPy, SciPy (zależności scikit-learn) | obliczenia, macierze rzadkie | BSD-3-Clause | brak |
| tldextract 5.4.0 + Public Suffix List | domeny rejestrowalne | BSD-3-Clause; lista: MPL-2.0 | brak |
| maxminddb 3.3.0 | odczyt bazy DB-IP | Apache-2.0 | brak |
| Tesseract OCR + dane `pol`, `eng` (pakiety Debiana) | OCR zrzutów | Apache-2.0 | brak |
| Playwright 1.55.0 | sterowanie przeglądarką w kolektorze | Apache-2.0 | brak |
| Chromium (pobierany przez Playwright) | otwieranie reklam i stron | BSD-3-Clause + licencje składników | brak |
| Xvfb, xauth (Debian) | ekran dla Chromium bez trybu headless | MIT/X11 | brak |
| PyTorch 2.14.1 (CPU) | ModernBERT | BSD-3-Clause | brak |
| Transformers 5.22.1 | ModernBERT | Apache-2.0 | brak |
| Ollama | uruchamianie lokalnego modelu | MIT | brak |
| Blocky v0.35.0 (`ghcr.io/0xerr0r/blocky`) | filtr DNS | Apache-2.0 | brak |
| Prometheus v3.5.0 (`prom/prometheus`) | metryki | Apache-2.0 | brak |
| Grafana 12.1.0 (`grafana/grafana`) | pulpit | AGPL-3.0 | używana bez zmian; zmieniona i wystawiona w sieci wymagałaby udostępnienia kodu zmian |
| Debian bookworm-slim, socat, curl, gpg (obraz `warp`) | proxy WARP | licencje Debiana (socat GPL-2.0, curl licencja curl, gpg GPL-3.0) | brak |
| Cloudflare WARP (`cloudflare-warp`) | proxy kolektora dla stron, które odcinają adresy serwerowe | własnościowa | [warunki Cloudflare](https://www.cloudflare.com/application/terms/); darmowy plan, bez konta |
| Atkinson Hyperlegible Next (Braille Institute), Libre Franklin (`site/fonts`) | fonty strony i demonstratora | SIL OFL 1.1 (`site/fonts/OFL.txt`) | fontów nie wolno sprzedawać osobno |
| Archivo, JetBrains Mono, Newsreader (Google Fonts) | fonty panelu weryfikacji | SIL OFL 1.1 | ładowane z serwerów Google, które widzą adres IP przeglądarki |

### Modele

| Model | Do czego | Licencja | Ograniczenia |
|---|---|---|---|
| qwen3.5:4b (Qwen, Alibaba; przez Ollamę) | ocena reklam w kolektorze | Apache-2.0 | brak; pobierany przez `ollama pull`, bez konta |
| OPI-PIB/pl-ModernBERT-512-base (Hugging Face) | wektory tekstu reklamy (model zamrożony, na nich regresja logistyczna) | Apache-2.0 | brak; wagi pobrane raz z Hugging Face bez konta, potem tylko z wolumenu (`HF_HUB_OFFLINE`) |
| klasyfikator słów (TF-IDF + regresja logistyczna, scikit-learn) | ocena reklam w kolektorze | nasz, MIT | uczony na naszych decyzjach, nie jest rozpowszechniany |

Demonstrator kampanii nie używa żadnego modelu językowego.

### Usługi i API

W repozytorium nie ma żadnych kluczy. Każdy klucz jest opcjonalny: bez niego dana funkcja się wyłącza, a reszta
działa. Nazwy zmiennych są w `.env.example`. Do oceny wystarczy demonstrator na https://kampanie.grannyinternet.me/
albo uruchomiony u siebie (niżej), który nie potrzebuje żadnego klucza.

| Usługa | Do czego | Dostęp | Ograniczenia |
|---|---|---|---|
| Meta Ad Library API (`graph.facebook.com`) | wyszukiwanie reklam w kolektorze | konto Facebook z potwierdzoną tożsamością ([facebook.com/ID](https://www.facebook.com/ID)), aplikacja na developers.facebook.com, token z Graph API Explorer → `META_TOKEN` | [warunki platformy Meta](https://developers.facebook.com/terms/), limity zapytań; token wygasa |
| CEIDG API (`dane.biznes.gov.pl`) | status, data startu i branża jednoosobowej firmy | darmowy token po zgłoszeniu na dane.biznes.gov.pl → `CEIDG_TOKEN` | limity zapytań; dane jawne z rejestru |
| GUS REGON, BIR 1.1 (`wyszukiwarkaregon.stat.gov.pl`) | dane firmy po NIP | darmowy klucz zamawiany w GUS → `GUS_KEY`; GUS ma też środowisko testowe z publicznym kluczem | warunki GUS |
| Biała lista podatników VAT (`wl-api.mf.gov.pl`) | status VAT i rachunki firmy | bez klucza | dzienny limit wyszukiwań MF |
| KRS API (`api-krs.ms.gov.pl`) | odpis spółki z KRS | bez klucza | dane jawne z rejestru |
| VIES (`ec.europa.eu`) | numer VAT z UE | bez klucza | limity Komisji Europejskiej |
| RDAP (IANA bootstrap, `rdap.org`, `rdap.dns.pl`, rejestry) | wiek i rejestrator domeny | bez klucza | limity rejestrów; w demonstratorze tylko przy `ONLINE=1` |
| Cloudflare Turnstile | ochrona formularzy (demonstrator, zgłoszenia, odwołania) | darmowe klucze strony i sekretu z panelu Cloudflare → `TURNSTILE_SITE`, `TURNSTILE_SECRET` | bez kluczy formularze działają bez tej ochrony |
| Cloudflare Pages, Tunnel, Access | hosting strony, dostęp do demonstratora i panelu | darmowe konto Cloudflare | [warunki Cloudflare](https://www.cloudflare.com/website-terms/); niepotrzebne przy uruchomieniu u siebie |
| Resend (`api.resend.com`) | potwierdzenia mailowe zgłoszeń i odwołań | darmowe konto, klucz API → `RESEND_KEY`, domena nadawcy potwierdzona rekordami DNS | 100 maili dziennie w darmowym planie |
| ntfy.sh | powiadomienie na telefon o zgłoszeniu | bez konta, nazwa tematu → `NTFY_TOPIC` | temat czyta każdy, kto zna jego nazwę |
| Quad9, Cloudflare 1.1.1.1 for Families | serwery DNS, do których Blocky przekazuje niezablokowane zapytania | bez klucza | warunki operatorów |
| YouTube | film z działania systemu | publiczny link | warunki YouTube |

### Dane i ich pochodzenie

| Dane | Skąd | Licencja | Ograniczenia |
|---|---|---|---|
| reklamy z biblioteki Meta | Meta Ad Library API | warunki Meta | nie ma ich w repozytorium; zostają w bazie kolektora |
| DB-IP Lite (kraj, ASN) | [db-ip.com](https://db-ip.com), pobierane przy budowaniu obrazu `kampanie` | CC BY 4.0 | wymaga wzmianki „IP Geolocation by DB-IP”; jest przy „Serwerach stron” w demonstratorze |
| Tranco top 1M | [tranco-list.eu](https://tranco-list.eu) | bezpłatna; autorzy proszą o cytowanie (Le Pochat i in., NDSS 2019) | brak |
| zakresy adresów AWS | `ip-ranges.amazonaws.com` | publiczny plik AWS | brak |
| nowo zarejestrowane domeny (NRD) | [HaGeZi NRD](https://github.com/hagezi/nrd) przez jsDelivr | GPL-3.0 | brak |
| lista ostrzeżeń CERT Polska | `hole.cert.pl` | CERT Polska: dowolny cel | CERT prosi o pobieranie nie częściej niż co 5 minut |
| pozostałe listy blokad | adresy w `sources.toml` | licencja każdej listy w `sources.toml` | niżej |
| statystyki na stronie projektu | NBP, CERT Polska (raport 2025), badanie Banku Pocztowego | źródła podlinkowane przy liczbach | cytowane, nie kopiowane |
| dane organizatora | wyzwanie Hack Nation 2026 | warunki organizatora | tylko na potrzeby wyzwania; nie ma ich w repozytorium (`dane/` w `.gitignore`), wgrywa się je w przeglądarce i zostają w lokalnym wolumenie Dockera |

Listy blokad są pobierane w czasie działania i nie są rozpowszechniane w repozytorium. Większość jest na GPL-3.0,
MIT, MPL-2.0, Apache-2.0 albo CC BY(-SA). Listy niekomercyjne (someonewhocares, MVPS, certyficateit, StevenBlack,
hBlock) są wyłączone (`enabled = false`). Część list ma licencję „nieznana” albo „brak”: używamy ich w projekcie
niekomercyjnym, a przed użyciem komercyjnym trzeba to wyjaśnić z autorami albo te listy wyłączyć.

## Ostatnia deska ratunku: uruchomienie u siebie

Ta część jest potrzebna tylko wtedy, gdy https://kampanie.grannyinternet.me/ nie odpowiada.

**Film z działania systemu**, nagrany, gdy wszystko działało na serwerze: https://youtu.be/Q_Dz_FCzqKo

### Sam demonstrator kampanii

Potrzebny jest tylko Docker.

```powershell
git clone https://github.com/miguellukasiak/grannyInternet_Hacknation2026
cd grannyInternet_Hacknation2026
docker compose up --build kampanie
```

Potem otwórz http://127.0.0.1:8501 (port jest wystawiony tylko na 127.0.0.1) i wgraj materiały w przeglądarce:
pliki, cały folder albo ZIP (do 2 GB), adres strony albo sam tekst reklamy.

- Tryb offline: ustaw `ONLINE=0` (PowerShell: `$env:ONLINE=0`, bash: `ONLINE=0 docker compose up --build kampanie`).
  Wtedy nic nie wychodzi z kontenera, a wklejony adres jest tylko zapisany. Bez tej zmiennej moduł pyta RDAP
  o wiek domen docelowych i pobiera wklejoną stronę (z blokadą adresów prywatnych).
- Wgrane materiały i ich cechy trafiają do wolumenu `kampanie` (`/data/baza.json`). Materiał usuwa się na jego
  stronie, całą bazę przyciskiem „Wyczyść bazę”.
- Domeny zablokowane przez kolektor: gdy działa cały system, kontener widzi `verdicts.db` tylko do odczytu
  (wolumen `verdicts`, zmienna `KOLEKTOR`) i pokazuje przycisk „Wczytaj zablokowane domeny”. Bez tej bazy
  przycisku nie ma, a demonstrator pracuje na tym, co wgrasz.
- Strony zapisane przez kolektor: `lists/pages` zamontowany tylko do odczytu jako `/strony` (zmienna `STRONY`).
  Przy domenie z bazy kolektora strona materiału ma wtedy przycisk „Pobierz stronę zapisaną przez kolektor”:
  HTML i tekst strony, przekierowania z reklamy, adresy, które strona odpytuje, certyfikat TLS i jego historia
  w logach Certificate Transparency (`.json.gz`).
- Bez GUI: `docker compose run --rm -v "${PWD}/folder:/x:ro" kampanie python kampanie.py /x` wypisuje kampanie
  i werdykty jako tekst (każdy podfolder to jeden materiał).
- Testy: `docker compose run --rm --no-deps kampanie python -m unittest -v`.

### Cały system

`docker compose up -d` uruchamia wszystkie usługi. Potrzebny jest plik `.env` na wzór `.env.example` (token
Meta Ad Library, klucze CEIDG i GUS, adres Ollamy). Panel weryfikacji jest wtedy pod http://127.0.0.1:8080, a pulpit Grafany
pod http://127.0.0.1:3000.
