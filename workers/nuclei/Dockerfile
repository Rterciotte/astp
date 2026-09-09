FROM projectdiscovery/nuclei@sha256:aeb5ea2db32a252b8135707d2ad0e89b90e19a18ea7816d38759bc51efb46b97 AS nuclei
FROM python:3.12.11-alpine3.22
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
WORKDIR /worker
ENV HOME=/tmp/home XDG_CONFIG_HOME=/tmp/home/.config
COPY workers/nuclei/worker.py /worker/worker.py
COPY workers/nuclei/templates /opt/astp/templates
RUN adduser -D -u 10001 astp && chown -R astp:astp /worker /opt/astp
USER astp
ENTRYPOINT ["python", "-I", "/worker/worker.py"]
