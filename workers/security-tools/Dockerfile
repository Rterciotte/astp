FROM python:3.12.11-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends nmap=7.93+dfsg1-1 && rm -rf /var/lib/apt/lists/*
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /worker
COPY workers/security-tools/worker.py /worker/astp_worker.py
RUN useradd --create-home --uid 10001 astp
USER astp
ENTRYPOINT ["python", "-I", "/worker/astp_worker.py"]
