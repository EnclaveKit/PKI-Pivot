FROM python:3.15-slim

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN groupadd --system proxyuser \
    && useradd --system --gid proxyuser --no-create-home --shell /usr/sbin/nologin proxyuser

WORKDIR /app

COPY pyproject.toml README.md LICENSE.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir . \
    && rm -rf /tmp/* /var/tmp/*

USER proxyuser:proxyuser

ENTRYPOINT ["pki-pivot"]
