FROM ghcr.io/zaproxy/zaproxy:stable
USER root
COPY workers/zap/worker.py /home/zap/astp_worker.py
USER zap
ENTRYPOINT ["python3", "-I", "/home/zap/astp_worker.py"]
