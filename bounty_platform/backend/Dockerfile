FROM golang:1.24-bookworm AS go-tools

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/pd && \
    GOBIN=/opt/pd go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    GOBIN=/opt/pd go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    GOBIN=/opt/pd go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    GOBIN=/opt/pd go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    GOBIN=/opt/pd go install github.com/ffuf/ffuf/v2@latest

FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    nmap \
    && rm -rf /var/lib/apt/lists/*

COPY --from=go-tools /opt/pd/ /usr/local/bin/

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app
RUN chmod +x /app/entrypoint.sh
