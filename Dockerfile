# SOC-X Recommendation Simulator container
FROM python:3.12-slim

# Keep Python output unbuffered and skip .pyc files
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

WORKDIR /app

# Install dependencies first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY cloud_mock_server.py permanent_responses.py main.py ./
# Optional: pre-load pinned rules from JSON files if present
COPY recommendations/ ./recommendations/

# Use a STABLE, committed self-signed TLS certificate (certs/server.{crt,key}).
# ADE (anomaly-detection-engine) always calls the SOC-X cloud over https:// and
# validates the cert against its Java truststore, so the cert must NOT change on
# every build (otherwise the truststore import would need redoing each time).
# SAN covers the docker service name and the host IP used in staging configs.
COPY certs/ ./certs/

EXPOSE 8080

# Healthcheck against the built-in /health endpoint over HTTPS (self-signed -> unverified)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,ssl,os; ctx=ssl._create_unverified_context(); urllib.request.urlopen(f'https://127.0.0.1:{os.environ.get(\"PORT\",\"8080\")}/health', context=ctx)" || exit 1

# Serve both / and /socx_sim over HTTPS on the chosen port
CMD ["sh", "-c", "uvicorn main:root_app --host 0.0.0.0 --port ${PORT} --ssl-keyfile /app/certs/server.key --ssl-certfile /app/certs/server.crt"]

