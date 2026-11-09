# PKI Pivot

## Description
PKI Pivot is a tool designed to facilitate pivoting between IAM roles within a network using Public Key Infrastructure (PKI) certificates. It provides a seamless way to navigate through different network segments across different Cloud Service Providers (CSPs). This tool is particularly useful for DevOps professionals deploying applications to Kubernetes and Cloud environments on isolated networks.

---

## Documentation
* [Architecture](docs/architecture.md)
* [Contributing](CONTRIBUTING.md)
* [How to Run the Proxy](docs/running.md)

---

## Local Development
### Install Dependencies
1. Clone the repository
2. Navigate to the project directory: `cd pki-pivot`
3. Install the required dependencies: `uv sync --group=dev`

### Run Linting
* Format: `ruff format`
* Syntax Check: `ruff check --fix`
* Pyright: `pyright`

### Run Tests
1. Run unit tests only: `pytest tests/unit`
2. Run integration tests only: `pytest tests/integration`
3. Run all tests: `pytest`

---

## Contributing

We welcome contributions from the community. You can help improve data handling, add CSPs handlers,
 add documentation, fix bugs, and improve the user experience.

---

## License

PKI Pivot is released under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).
