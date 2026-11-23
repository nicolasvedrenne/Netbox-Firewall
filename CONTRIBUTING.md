# Contributing

Use Python 3.12–3.14 and install the package locally with `python -m pip install -e '.[test,dev]'`. Run `ruff format --check .`, `ruff check .`, `mypy`, `pytest`, `bandit -r netbox_firewall`, and `python -m build`. The default pytest run includes the driver conformance tests and does not require a running firewall.

For integration tests, download exact NetBox source versions used in [CI](.github/workflows/ci.yml) and use disposable PostgreSQL and Redis instances. Install the selected NetBox requirements and set `PYTHONPATH` to its application directory and this checkout's tests directory. Set `NETBOX_CONFIGURATION=netbox_configuration`, `DJANGO_SETTINGS_MODULE=netbox.settings` and the `NB_TEST_DB_PASSWORD` and optional test port variables. Run `python -m django check`, `python -m django migrate --noinput`, `python -m django makemigrations netbox_firewall --check --dry-run` and `pytest tests/integration`. Use a dedicated lab appliance for any live tests.

Include a clear problem statement and test evidence in pull requests. Keep a human-readable change entry in `CHANGELOG.md`. Review permissions, reconciliation, network transport and external driver changes with the repository security owners. Follow semantic versioning.

## Repository and release setup

Protect `main` and require the **CI / required** check, pull-request review and no direct pushes. Replace the commented examples in CODEOWNERS with actual security owners and require their approval for owned paths. Enable Dependabot security alerts and updates, and configure auto-merge only with required checks and branch rules. The workflow opts in a narrow patch allowlist. Major updates require review. Restrict protected `v*` tags to release maintainers and use signed annotated tags where supported.

Create a protected GitHub environment named `pypi` with required reviewers and allowed release tags. Configure PyPI Trusted Publishing for the repository and the `release.yml` workflow. Release from a reviewed commit on `main` with a version-matched tag. The workflow validates the package, builds the wheel and source distribution, creates a CycloneDX SBOM, publishes using OIDC with PyPI attestations and generates GitHub release notes from merged changes. Record operating and compatibility changes in the changelog before tagging.
