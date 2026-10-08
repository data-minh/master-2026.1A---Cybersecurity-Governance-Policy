# Demo vulnerable target (testing only). Build context = repo root.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
RUN pip install --no-cache-dir "fastapi>=0.110" "uvicorn[standard]>=0.29"
COPY services/vuln-target/app /app/app
# Listen on 80 so the recon HTTP probe (which tries http/https on 80/443)
# can reach it just like a real web host.
EXPOSE 80
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "80"]
