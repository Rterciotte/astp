# Build blueprint only. Qualification requires a built digest and authorized field test.
FROM mcr.microsoft.com/playwright/python:v1.55.0-noble
WORKDIR /worker
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 astp-worker
COPY worker_stub.py /worker/worker_stub.py
USER 10001
ENTRYPOINT ["python", "/worker/worker_stub.py"]
