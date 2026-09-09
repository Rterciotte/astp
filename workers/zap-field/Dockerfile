FROM astp/zap-worker:qualification
USER root
COPY --chown=zap:zap workers/zap-field/worker.py /worker/astp_field_worker.py
USER zap
ENTRYPOINT ["python", "-I", "/worker/astp_field_worker.py"]
