# RedTee Screening Room - central deployment (stdlib only, no pip installs)
FROM python:3.11-slim
WORKDIR /app
COPY server.py export_sidecar.py config.example.json ./
# platform state (config, reviews, bundles) lives in /app - mount a volume over it.
# Run as a non-root user; give it ownership of the state dir so writes to the mounted volume work.
RUN useradd --system --uid 10001 --home-dir /app redtee && chown -R redtee:redtee /app
USER redtee
ENV REDTEE_REVIEW_HOST=0.0.0.0 REDTEE_REVIEW_PORT=8712
EXPOSE 8712
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,os,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('REDTEE_REVIEW_PORT','8712')+'/health',timeout=3).status==200 else 1)"
CMD ["python", "server.py"]
