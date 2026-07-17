# RedTee Screening Room - central deployment (stdlib only, no pip installs)
FROM python:3.11-slim
WORKDIR /app

# --- code lives in /app (baked into the image, read-only at runtime) ---
COPY server.py export_sidecar.py config.example.json ./

# --- persistent state lives in /data (mount a volume here) ---
# Keeping state OUT of /app means a mounted volume never shadows the code.
ENV REDTEE_DATA_DIR=/data \
    REDTEE_REVIEW_HOST=0.0.0.0 \
    REDTEE_REVIEW_PORT=8712

# non-root user that owns both the code dir and the state dir
RUN useradd --system --uid 10001 --home-dir /app redtee \
    && mkdir -p /data \
    && chown -R redtee:redtee /app /data
USER redtee

EXPOSE 8712
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,os,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('REDTEE_REVIEW_PORT','8712')+'/health',timeout=3).status==200 else 1)"
CMD ["python", "server.py"]
