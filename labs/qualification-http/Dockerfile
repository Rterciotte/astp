FROM python:3.12.11-slim-bookworm
WORKDIR /lab
COPY labs/qualification-http/server.py /lab/server.py
RUN useradd --create-home --uid 10002 astplab
USER astplab
EXPOSE 8080
ENTRYPOINT ["python", "-I", "/lab/server.py"]
