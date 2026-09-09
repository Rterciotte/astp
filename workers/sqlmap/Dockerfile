FROM alpine:3.22 AS source
RUN apk add --no-cache git && git clone --depth 1 --branch 1.9.9 https://github.com/sqlmapproject/sqlmap.git /sqlmap
FROM python:3.12.11-alpine3.22
COPY --from=source /sqlmap /opt/sqlmap
RUN addgroup -g 10001 astp && adduser -D -u 10001 -G astp astp
COPY --chown=10001:10001 workers/sqlmap/worker.py /worker/worker.py
USER 10001
ENTRYPOINT ["python", "-I", "/worker/worker.py"]
