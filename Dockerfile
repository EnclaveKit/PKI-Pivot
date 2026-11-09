FROM python:3.15-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

ENTRYPOINT ["pki-pivot"]
