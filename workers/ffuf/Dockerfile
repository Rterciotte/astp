FROM golang:1.24.7-alpine3.22 AS build
RUN apk add --no-cache git && git clone --depth 1 --branch v2.1.0 https://github.com/ffuf/ffuf.git /src
WORKDIR /src
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /ffuf .
FROM python:3.12.11-alpine3.22
COPY --from=build /ffuf /usr/local/bin/ffuf
RUN addgroup -g 10001 astp && adduser -D -u 10001 -G astp astp \
    && mkdir -p /home/astp/.config/ffuf/scraper \
    && chown -R 10001:10001 /home/astp/.config
COPY --chown=10001:10001 workers/ffuf/worker.py /worker/worker.py
USER 10001
ENTRYPOINT ["python", "-I", "/worker/worker.py"]
