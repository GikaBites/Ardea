FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --system --uid 10001 --create-home ardea && chown -R ardea /app
USER ardea
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/healthz',timeout=4).status==200 else 1)"
# gthread workers: SSE streams hold a thread each; Flask's dev server is not for production
CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "2", "-k", "gthread", "--threads", "16", "--timeout", "0", "app:app"]
