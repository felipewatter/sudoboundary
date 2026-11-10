# SudoBoundary (English overview)

An **offline, deterministic, policy-as-code regression gate** for a deliberately scoped JSON model of Linux privileged-command grants.

- Explain who can run a command under a given declared rule, group, host and run-as identity.
- Detect broad root privileges, `NOPASSWD`, `SETENV`, weak logging, interpreters, and unconstrained argument lists.
- Compare baseline and candidate with explicit request matrices, blocking newly granted access and weakened security controls.
- Export structured JSON and SARIF 2.1.0, with content SHA-256 fingerprints and deterministic release ZIPs.
- Python 3.11+, no third-party runtime dependencies, no network or subprocess calls in the engine.

**This does not parse real sudoers files, query the OS, enforce sudo or prove Linux host security.** It intentionally models a small, well-defined subset of privileged access decisions. Actual changes must be reviewed and verified with `visudo`, `sudo -l` and authorized environment-specific tests.

## Quick start

```sh
python -m pip install --no-deps .
sudoboundary audit --policy examples/baseline.json --fail-on high
sudoboundary explain --policy examples/baseline.json --request examples/request.json
sudoboundary assert --policy examples/baseline.json --queries examples/queries.json
sudoboundary compare --baseline examples/baseline.json --candidate examples/candidate-risky.json --queries examples/queries.json --fail-on high
```

The last command intentionally fails with exit status `1`, demonstrating a policy gate. Exit `2` means input or execution failure. JSON outputs are the default; `--format text` is also supported.

**Detailed documentation in Brazilian Portuguese:** [README.md](README.md), [semantics](docs/SEMANTICS.md), [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md), [rules](docs/RULES.md), [validation](docs/VALIDATION.md) and [security policy](SECURITY.md). MIT license.
