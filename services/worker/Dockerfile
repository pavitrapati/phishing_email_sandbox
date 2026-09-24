# The detonation environment. Everything an attachment might need to reveal itself,
# and nothing it could use to reach the outside world.
FROM python:3.9-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NODE_OPTIONS=--max-old-space-size=512

RUN apt-get update && apt-get install -y --no-install-recommends \
        strace \
        p7zip-full \
        cabextract \
        unzip \
        binutils \
        file \
        libmagic1 \
        curl \
        ca-certificates \
        gnupg \
 && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && apt-get purge -y gnupg \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

# box-js emulates the Windows Script Host, which is the only honest way to detonate a
# .js/.vbs dropper on Linux -- node alone has no WScript for the sample to call.
RUN npm install -g box-js@1.9.29 --unsafe-perm \
 && npm cache clean --force

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Deliberately do NOT pre-create /tmp/work here: a tmpfs mounted over /tmp at runtime
# copies in whatever exists at the mountpoint, and an image-created /tmp/work lands
# root-owned and unwritable by uid 1000. The entrypoint creates it fresh on the empty
# tmpfs instead, where it is owned by the analyst user.
RUN useradd -u 1000 -m -s /bin/bash analyst \
 && mkdir -p /opt/worker /job

COPY --chown=root:root entrypoint.py /opt/worker/entrypoint.py
COPY --chown=root:root analyzers /opt/worker/analyzers
COPY --chown=root:root simulate_mouse.sh /opt/worker/simulate_mouse.sh
RUN chmod -R a-w /opt/worker
RUN chmod +x /opt/worker/simulate_mouse.sh

# The sample runs as this user. It cannot write to its own tooling.
USER analyst
WORKDIR /home/analyst

ENTRYPOINT ["python", "/opt/worker/entrypoint.py"]
