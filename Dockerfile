# Security Group Risk Dashboard — production container image
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py sg_risk_analyzer_live.py dashboard.html sample_findings.json ./

# Not root, out of caution — read-only AWS calls don't need elevated privileges
RUN useradd -m appuser
USER appuser

EXPOSE 5001

# gunicorn, not the Flask dev server: multiple workers so several teammates
# can run scans concurrently without blocking each other. Long --timeout
# because a full multi-region scan + AI summary (especially local Ollama
# models) can take a while.
CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:5001", "--timeout", "180", "app:app"]
