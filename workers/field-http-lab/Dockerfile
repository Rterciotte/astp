FROM python:3.12.11-alpine3.22
WORKDIR /app
COPY workers/field-http-lab/server.py /app/server.py
RUN addgroup -g 10003 lab && adduser -D -u 10003 -G lab lab
USER 10003
EXPOSE 8080
ENTRYPOINT ["python", "/app/server.py"]
