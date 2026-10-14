# AegisApex agent: runs next to your network devices, talks to Supabase over
# outbound HTTPS only.
#   docker build -t aegisapex-agent agent/
#   docker run -d --restart unless-stopped --env-file agent/.env aegisapex-agent
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY collector.py hostkeys.py worker.py scheduler.py ./

RUN useradd --system --uid 10001 aegis
USER aegis

CMD ["python", "worker.py"]
