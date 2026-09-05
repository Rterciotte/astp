FROM mcr.microsoft.com/playwright/python:v1.55.0-noble
RUN useradd --create-home --uid 10001 astp
USER astp
WORKDIR /worker
COPY entrypoint.py /worker/entrypoint.py
ENTRYPOINT ["python", "/worker/entrypoint.py"]
