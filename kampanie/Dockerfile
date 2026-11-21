FROM python:3.14-slim
# tesseract reads screenshots: the address bar, ad captions, the text of a page that is gone
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-pol \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY kampanie/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# DB-IP Lite (CC BY 4.0) for the campaign card's hosting firms: fetched at build, so 18 MB never sit in the repository.
# shortcut: one month's files, the URL dies when DB-IP drops it; bump DBIP (or pass --build-arg) when a build fails here
ARG DBIP=2026-11
# with curl, as DB-IP's page shows (it refuses Python's urllib); own layer so the ones above stay cached
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/* \
    && for k in country asn; do curl -fsSL "https://download.db-ip.com/free/dbip-$k-lite-$DBIP.mmdb.gz" | gunzip > "dbip-$k-lite.mmdb" || exit 1; done
COPY kampanie/kampanie.py kampanie/app.py kampanie/baza.py kampanie/test_kampanie.py ./
COPY kampanie/static static
COPY site/fonts static/fonts
RUN useradd --create-home --uid 1000 app && mkdir /data && chown 1000 /data
ENV PYTHONUNBUFFERED=1 TLDEXTRACT_CACHE=/tmp/tldextract
USER app
EXPOSE 8501
CMD ["python", "app.py"]
