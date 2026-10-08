# Build context = repo root.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 TEMPLATE_DIR=/app/templates
WORKDIR /app
COPY common/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY common /opt/common
RUN pip install --no-cache-dir /opt/common
COPY services/scan-engine/app /app/app
COPY services/scan-engine/templates /app/templates
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --retries=5 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
