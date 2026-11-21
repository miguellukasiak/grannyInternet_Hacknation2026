FROM python:3.14-slim
# tesseract reads screenshots: the address bar, ad captions, the text of a page that is gone
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-pol \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY kampanie.py app.py test_kampanie.py ./
RUN useradd --create-home --uid 1000 app && mkdir /data && chown 1000 /data
ENV PYTHONUNBUFFERED=1 TLDEXTRACT_CACHE=/tmp/tldextract
USER app
EXPOSE 8501
CMD ["python", "app.py"]
