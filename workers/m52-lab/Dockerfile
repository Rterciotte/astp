FROM python:3.12.11-alpine3.22
WORKDIR /lab
COPY src/astp/m52_acceptance_lab.py /lab/server.py
RUN adduser -D -u 10001 astp && chown -R astp:astp /lab
USER astp
EXPOSE 8080
ENTRYPOINT ["python", "-I", "/lab/server.py"]
