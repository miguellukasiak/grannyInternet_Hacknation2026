FROM python:3.14-slim
WORKDIR /app
COPY requirements.txt .
# Chromium "clicks" ads like a phone user, with a window on a virtual screen (Xvfb): shops let a headless one in
# less often. Shared browser path so the non-root user can start it.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN apt-get update && apt-get install -y --no-install-recommends xvfb xauth && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt && playwright install --with-deps chromium
# ModernBERT for the second opinion, on the CPU (the 4 GB card holds qwen); the weights come from the models volume
RUN pip install --no-cache-dir torch==2.14.1 --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir transformers==5.22.1
COPY collector.py lists.py panel.py panel.html login.html report.html appeal.html accounts.html home.py ./
# a fresh named volume copies this ownership, so the non-root user can write /data and /verdicts;
# a real account with a home: Chromium crashes at start under a bare uid without one
RUN useradd --create-home --uid 1000 app && mkdir /data /verdicts && chown 1000 /data /verdicts
ENV PYTHONUNBUFFERED=1 TLDEXTRACT_CACHE=/tmp/tldextract
USER app
CMD ["xvfb-run", "-a", "python", "collector.py"]
