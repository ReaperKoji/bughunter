# syntax=docker/dockerfile:1.7

# --- ESTÁGIO 1: Ferramentas em GO ---
FROM golang:1.24-bookworm AS go-tools

ENV GOBIN=/opt/hunterops-bin

# IMPORTANTE: libpcap-dev aqui para o Naabu compilar
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git libpcap-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p "${GOBIN}"

RUN set -eux; \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest; \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest; \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest; \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest; \
    go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest; \
    (go install github.com/lc/gau/v2/cmd/gau@latest || true); \
    (go install github.com/tomnomnom/assetfinder@latest || true); \
    (go install github.com/tomnomnom/waybackurls@latest || true); \
    (go install github.com/ffuf/ffuf/v2@latest || true); \
    (go install github.com/projectdiscovery/katana/cmd/katana@latest || true); \
    (go install github.com/hakluke/hakrawler@latest || true); \
    (go install github.com/jaeles-project/gospider@latest || true); \
    (go install github.com/owasp-amass/amass/v4/...@latest || go install github.com/owasp-amass/amass/v3/...@latest || true); \
    for tool in subfinder httpx naabu nuclei interactsh-client amass gau assetfinder waybackurls ffuf katana hakrawler gospider; do \
      if [ -f "/go/bin/${tool}" ]; then install -m 0755 "/go/bin/${tool}" "${GOBIN}/${tool}"; fi; \
    done

# --- ESTÁGIO 2: Ferramentas em RUST ---
FROM rust:1.86-slim-bookworm AS rust-tools

RUN mkdir -p /opt/hunterops-bin
WORKDIR /build
# Certifique-se que esta pasta existe no seu repo antes do build
COPY tools/rust-analyzer ./tools/rust-analyzer
RUN set -eux; \
    cd tools/rust-analyzer; \
    cargo build --release; \
    install -m 0755 target/release/hunterops_rust_analyzer /opt/hunterops-bin/hunterops_rust_analyzer

# --- ESTÁGIO 3: RUNTIME FINAL ---
FROM python:3.11-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=0 \
    PIP_CACHE_DIR=/var/cache/pip \
    HUNTEROPS_HOME=/opt/hunterops

WORKDIR /opt/hunterops

# Precisamos de libpcap no runtime também para as ferramentas funcionarem, e tini para o entrypoint
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    libpcap-dev \
    procps \
    tini \
    && rm -rf /var/lib/apt/lists/*

# Copia e instala requirements primeiro para aproveitar cache do Docker
COPY requirements.txt ./requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install --cache-dir "${PIP_CACHE_DIR}" -r requirements.txt

# Copia binários compilados dos estágios anteriores
COPY --from=go-tools /opt/hunterops-bin/ /usr/local/bin/
COPY --from=rust-tools /opt/hunterops-bin/ /usr/local/bin/

# Ajusta permissões dos binários
RUN set -eux; \
    for tool in subfinder httpx naabu nuclei interactsh-client amass hunterops_rust_analyzer gau assetfinder waybackurls ffuf katana hakrawler gospider; do \
      if command -v "${tool}" >/dev/null 2>&1; then chmod 0755 "$(command -v "${tool}")"; fi; \
    done

# Copia o resto do código
COPY . /opt/hunterops
COPY scripts/docker_entrypoint.sh /usr/local/bin/docker_entrypoint.sh

# Setup de usuário e pastas de dados
RUN chmod 0755 /usr/local/bin/docker_entrypoint.sh \
    && groupadd --system hunterops \
    && useradd --system --gid hunterops --home /opt/hunterops --shell /usr/sbin/nologin hunterops \
    && mkdir -p /opt/hunterops/data /opt/hunterops/reports /opt/hunterops/data/evidence \
    && chown -R hunterops:hunterops /opt/hunterops

# Variáveis de ambiente padrão (vazias)
ENV HACKERONE_API_USER="" \
    HACKERONE_API_TOKEN="" \
    HUNTEROPS_OOB_CALLBACK_DOMAIN="" \
    HUNTEROPS_OOB_POLL_URL="" \
    HUNTEROPS_OOB_API_TOKEN="" \
    HUNTEROPS_CRITICAL_WEBHOOK="" \
    HUNTEROPS_POSTGRES_DSN=""

# Usa Tini para gerenciar processos corretamente no container
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker_entrypoint.sh"]
CMD ["python", "scripts/research_pipeline.py", "--config", "config/engine.yaml", "--targets-file", "config/targets/robinhood_in_scope_hosts.txt"]
