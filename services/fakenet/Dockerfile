FROM python:3.12-slim-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY fakenet.py /app/fakenet.py
RUN mkdir -p /net

# Runs as root deliberately: binding :53 and :80 needs CAP_NET_BIND_SERVICE, and Docker
# does not grant ambient capabilities to a non-root USER, so `cap_add` would be a no-op
# here. Compose drops every other capability and sets no-new-privileges, so this process
# holds exactly one privilege. It only ever parses input -- it never executes samples.
CMD ["python", "-u", "/app/fakenet.py"]
