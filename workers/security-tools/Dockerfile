# Build blueprint only. Tool binaries remain outside readiness until pinned and field-qualified.
FROM python:3.13-slim-bookworm
WORKDIR /worker
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 astp-worker
COPY worker_stub.py /worker/worker_stub.py
USER 10001
ENTRYPOINT ["python", "/worker/worker_stub.py"]
