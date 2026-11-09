
# Running PKI Pivot

This page shows two ways to start PKI Pivot and check that it is serving:

* [In a Docker container](#running-in-docker)
* [Locally, outside a container](#running-locally)

Both use a **demo configuration**. It satisfies startup validation but points
at an issuer that doesn't exist. The health, IMDSv2 token, and role-list
endpoints work. The credential endpoint returns `502`, which is expected
without a real issuer.

---

## Required configuration

PKI Pivot reads all of its configuration from environment variables. It
refuses to start (`Configuration error: …`) unless these are set:

| Variable             | Demo value                  | Notes                                                    |
|----------------------|-----------------------------|----------------------------------------------------------|
| `TARGET_CSPS`        | `AWS`                       | Comma-separated list of CSPs to enable                   |
| `AWS_ORGANIZATION`   | `demo-org`                  |                                                          |
| `AWS_ACCOUNT_ID`     | `123456789012`              |                                                          |
| `AWS_IAM_ROLE_NAME`  | `demo-role`                 | Must be a single path segment                            |
| `AWS_ISSUER_URL`     | `http://issuer.invalid`     | `http://` skips loading the client certificate           |
| `AWS_TLS_CERT_FILE`  | path to a readable file     | Any file works with an `http://` issuer                  |
| `AWS_TLS_KEY_FILE`   | path to a readable file     | Any file works with an `http://` issuer                  |

Useful optional settings:

| Variable              | Default     | Notes                                                                 |
|-----------------------|-------------|-----------------------------------------------------------------------|
| `HTTP_BIND_HOST`      | `localhost` | Use `0.0.0.0` inside a container                                     |
| `HTTP_PORT`           | `8080`      |                                                                       |
| `SHARED_DIR`          | `/shared`   | Directory checked for the exit file; if missing, only a warning is logged |
| `EXIT_FILE_NAME`      | `EXIT`      | Creating `<SHARED_DIR>/<EXIT_FILE_NAME>` stops the proxy             |
| `EXIT_CHECK_DISABLED` | `false`     | Turns off exit-file monitoring                                        |
| `LOG_LEVEL`           | `INFO`      | Standard Python logging level name                                    |

> For a real deployment, use an `https://` issuer URL. `AWS_TLS_CERT_FILE` and
> `AWS_TLS_KEY_FILE` must then be a valid client certificate and private key,
> and `AWS_TLS_CA_FILE` can point to a custom CA bundle.

---

## Running in Docker

### 1. Build the image

From the repository root:

```shell
docker build -t pki-pivot:local .
```

### 2. Create the demo files

```shell
mkdir -p demo/tls demo/shared
touch demo/tls/client.crt demo/tls/client.key
```

Create `demo/demo.env`:

```dotenv
TARGET_CSPS=AWS
HTTP_BIND_HOST=0.0.0.0
HTTP_PORT=8080
AWS_ORGANIZATION=demo-org
AWS_ACCOUNT_ID=123456789012
AWS_IAM_ROLE_NAME=demo-role
AWS_ISSUER_URL=http://issuer.invalid
AWS_TLS_CERT_FILE=/tls/client.crt
AWS_TLS_KEY_FILE=/tls/client.key
```

> Don't put quotes around values; `docker --env-file` passes them through
> literally. Keep `demo/` out of version control.

### 3. Start the container

```shell
docker run --rm --name pki-pivot \
  -p 8080:8080 \
  --env-file demo/demo.env \
  -v "$PWD/demo/tls:/tls:ro" \
  -v "$PWD/demo/shared:/shared" \
  pki-pivot:local
```

The logs should include:

```text
... INFO pki_pivot.http_proxy: Routing configured for CSP AWS
... INFO pki_pivot.http_proxy: HTTP server listening on 0.0.0.0:8080
```

### 4. Check that it is running

From another terminal:

```shell
# Health check -> "ok"
curl -i http://localhost:8080/health

# IMDSv2 token -> "pki-pivot-imds-v2-token"
curl -X PUT http://localhost:8080/latest/api/token

# Role discovery -> "demo-role"
curl http://localhost:8080/latest/meta-data/iam/security-credentials/
```

Optional: requesting credentials returns `502 Upstream credential provider
error`, because the demo issuer doesn't exist.

```shell
curl -i http://localhost:8080/latest/meta-data/iam/security-credentials/demo-role
```

### 5. Stop the container

Any of these triggers a clean shutdown (`Shutting down` appears in the logs):

* Press `CTRL+C` in the terminal running the container (`SIGINT`).
* Run `docker stop pki-pivot` (`SIGTERM`).
* Create the exit file in the mounted shared directory:

  ```shell
  touch demo/shared/EXIT
  ```

  Delete `demo/shared/EXIT` before starting the container again, or it will
  stop right away.

---

## Running locally

### 1. Install

You need Python 3.13 or newer. From the repository root:

```shell
uv sync
```

> Without `uv`, use a virtual environment instead:
> `python -m venv .venv`, activate it, then `pip install -e .`

### 2. Create the demo files

```shell
mkdir -p .local/tls .local/shared
touch .local/tls/client.crt .local/tls/client.key
```

### 3. Set the environment and start

macOS / Linux (bash, zsh):

```shell
export TARGET_CSPS=AWS
export AWS_ORGANIZATION=demo-org
export AWS_ACCOUNT_ID=123456789012
export AWS_IAM_ROLE_NAME=demo-role
export AWS_ISSUER_URL=http://issuer.invalid
export AWS_TLS_CERT_FILE=.local/tls/client.crt
export AWS_TLS_KEY_FILE=.local/tls/client.key
export SHARED_DIR=.local/shared

uv run pki-pivot
```

Windows (PowerShell):

```powershell
$env:TARGET_CSPS = "AWS"
$env:AWS_ORGANIZATION = "demo-org"
$env:AWS_ACCOUNT_ID = "123456789012"
$env:AWS_IAM_ROLE_NAME = "demo-role"
$env:AWS_ISSUER_URL = "http://issuer.invalid"
$env:AWS_TLS_CERT_FILE = ".local\tls\client.crt"
$env:AWS_TLS_KEY_FILE = ".local\tls\client.key"
$env:SHARED_DIR = ".local\shared"

uv run pki-pivot
```

> On Windows, a warning that signal handlers can't be installed is expected.
> `CTRL+C` and the exit file still stop the proxy.

If you used a plain virtual environment, run `pki-pivot` (or
`python -m pki_pivot.http_proxy`) with the environment active.

The server listens on `localhost:8080` by default.

### 4. Check that it is running

```shell
curl -i http://localhost:8080/health
curl -X PUT http://localhost:8080/latest/api/token
curl http://localhost:8080/latest/meta-data/iam/security-credentials/
```

The responses match the [Docker check](#4-check-that-it-is-running).

### 5. Stop

* Press `CTRL+C`, or
* Create the exit file: `touch .local/shared/EXIT` (delete it before the next
  start).

---

## Troubleshooting

| Symptom                                                         | Cause / Fix                                                                 |
|-----------------------------------------------------------------|-----------------------------------------------------------------------------|
| `Configuration error: Environment variable TARGET_CSPS is not defined…` | Set `TARGET_CSPS=AWS`.                                              |
| `Configuration error: Missing required environment variable(s)…` | Every `AWS_*` variable listed in the error must be set.                    |
| `Configuration error: AWS_TLS_CERT_FILE '…' is not a readable file` | The path is wrong, or the volume isn't mounted in the container.        |
| `curl` can't connect to the container                           | Set `HTTP_BIND_HOST=0.0.0.0` and publish the port with `-p 8080:8080`.      |
| Container or process exits right after starting                 | An `EXIT` file is left in the shared directory; delete it.                 |
| `Shared directory '/shared' does not exist` warning             | Harmless. Mount or create the directory, set `SHARED_DIR`, or set `EXIT_CHECK_DISABLED=true`. |
```