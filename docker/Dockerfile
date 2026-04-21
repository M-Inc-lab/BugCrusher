# BugCrusher v3.5 — Dockerfile
# Multi-arch: linux/amd64, linux/arm64
FROM python:3.12-slim-bookworm

LABEL maintainer="morningstar"
LABEL org.opencontainers.image.title="BugCrusher v3.5"
LABEL org.opencontainers.image.description="Autonomous Bug Bounty Hunter"

# Build args
ARG TARGETOS=linux TARGETARCH=amd64
ARG UID=1000 GID=1000

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget nmap nuclei dalfox sqlmap ffuf metashape python3-pip \
    chromium browser-chromium burpsuite community idna \
    golang-go ruby default-jdk \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u $UID -g $GID -s /bin/bash hunter \
    && mkdir -p /workspace /home/hunter/.config \
    && chown -R $UID:$GID /workspace

# Install Python packages
COPY BugCrusher/requirements.txt /tmp/reqs.txt
RUN pip install --no-cache-dir -r /tmp/reqs.txt 2>/dev/null || true \
    && rm /tmp/reqs.txt

# Workspace
WORKDIR /workspace
COPY --chown=$UID:$GID BugCrusher/ /workspace/BugCrusher/
COPY --chown=$UID:$GID BugCrusher/BugCrusher/ /workspace/BugCrusher/BugCrusher/

# Tools
COPY Skills/ /workspace/Skills/
COPY Skills/critical-audit/SKILL.md /workspace/Skills/critical-audit/
COPY Skills/multi-test-auditor/SKILL.md /workspace/Skills/multi-test-auditor/

# Entrypoint
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER hunter
ENV PYTHONUNBUFFERED=1
ENV WORKSPACE=/workspace

ENTRYPOINT ["/entrypoint.sh"]
