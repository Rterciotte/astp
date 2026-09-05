FROM mcr.microsoft.com/playwright/python:v1.55.0-noble
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /worker
COPY workers/playwright/worker.py /worker/astp_worker.py
USER pwuser
ENTRYPOINT ["python", "-I", "/worker/astp_worker.py"]
