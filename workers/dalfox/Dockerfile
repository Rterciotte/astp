FROM hahwul/dalfox@sha256:11c1249ef35f8eb3482d180e247304b351b37da2929eecd518dd8057d2687dc7 AS tool
FROM python:3.12.11-slim-bookworm
COPY --from=tool /app/dalfox /usr/local/bin/dalfox
RUN groupadd --gid 10001 astp && useradd --uid 10001 --gid astp --create-home astp
COPY --chown=10001:10001 workers/dalfox/worker.py /worker/worker.py
COPY --chown=10001:10001 workers/dalfox/reflected-payloads.txt /opt/astp/reflected-payloads.txt
USER 10001
ENTRYPOINT ["python", "-I", "/worker/worker.py"]
