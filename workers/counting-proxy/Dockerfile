FROM python:3.12.11-alpine3.22
WORKDIR /app
RUN pip install --no-cache-dir pydantic==2.13.5
COPY src/astp /app/astp
RUN addgroup -g 10002 proxy && adduser -D -u 10002 -G proxy proxy
USER 10002
ENTRYPOINT ["python", "-m", "astp.counting_proxy"]
