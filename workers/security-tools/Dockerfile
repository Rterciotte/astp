FROM python:3.13-slim
RUN useradd --create-home --uid 10001 astp
USER astp
WORKDIR /worker
COPY entrypoint.py /worker/entrypoint.py
ENTRYPOINT ["python", "/worker/entrypoint.py"]
