FROM astp/playwright-worker:qualification
USER root
COPY --chown=10001:10001 workers/playwright-field/worker.py /worker/astp_field_worker.py
USER 10001
ENTRYPOINT ["python", "-I", "/worker/astp_field_worker.py"]
