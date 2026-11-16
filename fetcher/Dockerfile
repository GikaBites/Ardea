FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --system --uid 10001 ardea && mkdir -p /app/keys && chown -R ardea /app
USER ardea

# healthy = main loop touched the heartbeat within the last 10 minutes (fetch interval is 3 minutes)
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s --retries=3 \
  CMD python -c "import os,time,sys; sys.exit(0 if time.time()-os.path.getmtime('/tmp/heartbeat')<900 else 1)"

CMD ["python", "-u", "fetcher.py"]
