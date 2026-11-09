# Contributors

We ❤️ all contributions, big and small!

## Creating a feature pull request

When creating a PR for a feature, include screenshots where applicable to show data flow in
the new feature. If the feature requires a new interface (either externally facing applications
calling the proxy or within the business logic), include details of the new interface in the
[Architecture](docs/architecture.md) file.

When creating a PR for a bug fix, include screenshots where applicable to show the bug and its fix.
Include details of the bug and where the bug disrupts the expected behavior.

All PRs need to include the following sections completed for consideration
* Overview
  * What does this PR accomplish in 1 to 2 sentences.
* Details
  * Specific changes made to the codebase.
  * What tests were added or modified to cover the new feature or bug fix.
    * Codebase modifications must cover the new or repaired functionality.
* Testing
  * Was linting completed.
    * List which linting was completed (`ruff format`, `ruff check --fix`, `pyright`)
  * Were unit tests passing.
  * Were integration tests passing.
  * Was container build passing (if applicable).