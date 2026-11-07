# Access Hub Next (development only)

This repository contains a development copy of the user's Access Hub and a partial upgrade. It is **not a deployment package** and must not be installed on a production server yet. No OpenClaw gateway or Repo Lab bridge is implemented here.

## Local test

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

Tests use temporary SQLite databases; model responses are mocked. `baseline/app.py` is the supplied legacy app and exists for compatibility testing. `access_hub_next/app.py` is the development version.

## Not yet validated / unfinished

- The OpenClaw gateway, per-user isolation, model routing and a Repo Lab-only bridge are not implemented. Do not assume the local Ollama chat is OpenClaw.
- The integration has not been tested against real Ollama, Docker, a production SQLite database, service unit, or the Oracle installation. No production-ready installer or rollback command is provided.
- A limited headless Chromium smoke test covers desktop and mobile viewport sizes with a fake local Ollama service. It is not full browser/device coverage; role/group/user management remains incomplete.
- Full audit coverage, avatar lifecycle/storage quotas, security review, model resource controls and durable user-specific agent memory are incomplete.
- Secure cookies default to enabled, so production requires HTTPS. `ACCESS_HUB_INSECURE_DEV_COOKIE=1` is exclusively for local HTTP development; never enable it on a public deployment.
- Avatar processing requires Pillow. Dependencies must be installed in the interpreter used to run the application.

For multi-user OpenClaw integration, its HTTP gateway token is an operator-level credential, not a per-user authorization boundary. The upstream Docker documentation also advises a separate gateway for mutually untrusted users. A design must isolate users and prevent access to host execution, Docker sockets, and other users' sessions before any bridge is enabled.

## Packaging work in progress

`tools/preflight.py` collects compatibility markers, a database health/schema check, service state and a limited Docker configuration inventory; it does not install anything and cannot prove isolation. `tools/backup.py` creates a restricted-permission backup using SQLite's online backup API. It saves the application file, database and avatar files only: it excludes systemd/tunnel configuration and the workspace, and the avatar copy and database are not a single atomic snapshot. The backup contains private user data. These tools are locally tested prototypes, **not a validated production deployment or recovery procedure**.

## Rollback limitation

Successful legacy logins upgrade PBKDF2 hashes to scrypt. The original Access Hub does not understand scrypt hashes, so restoring only `app.py` after an upgrade can lock migrated accounts out. An actual rollback procedure must restore a matching pre-upgrade SQLite backup as well as the code and must explain that restoring the old database loses all changes since that backup. The current backup tool does **not** implement or validate such a rollback. Never deploy this development version until that procedure and the complete backup scope have been tested.

## Optional transitional credential compatibility

For staging and evaluation only, setting `ACCESS_HUB_LEGACY_CREDENTIAL_COMPAT=1` before starting the candidate preserves PBKDF2 credentials when users log in and uses that legacy format for newly created or reset credentials. This avoids forcing an authentication-incompatible scrypt conversion during a phased rollout, at the cost of retaining the old password hashing scheme. Existing scrypt hashes can still be verified by the candidate but not the old app. This flag does **not** by itself provide a complete rollback: schema, feature-specific data, file changes, configuration, and service recovery still require an independently tested procedure. The flag is not a deployment recommendation.

## UI test layers

`npm ci` installs test-only JavaScript dependencies. `PYTHON=.venv/bin/python npm run test:ui` runs a simulated DOM smoke test. `.venv/bin/python tests/browser_integration.py` runs headless Chromium against a temporary SQLite database and a **fake** local Ollama HTTP service (requires available loopback port 11434, compatible Chromium system libraries including NSS/NSPR, and the npm dev dependencies). Neither test contacts the Oracle server or proves real Docker/OpenClaw/Ollama isolation.

## Repo Lab boundary checks

Only authenticated users with both `tools.terminal` and `tools.repo.command` may run a Repo Lab command. Non-admin users can access this delegated terminal without acquiring access-management permissions. Before executing a command, the app inspects the named container and refuses to run if its expected non-root, capability, mount, resource or namespace configuration is missing. These checks are configuration checks, not proof of container isolation; they do not verify network isolation, Docker daemon security, kernel vulnerabilities, or prevent a privileged Docker operator from replacing a container between inspection and execution. The running service must itself use a non-root UID. Administrative management endpoints remain restricted to legacy admin accounts.

## Experimental deployment research

`tools/deploy_candidate.py` contains **non-CLI, experimental** deployment and source-only rollback building blocks, and `tools/systemd_adapter.py` has Linux/systemd safety checks. The code prepares a private release, validates the system interpreter and Pillow, stops through an injected service adapter, snapshots SQLite and the original app, tests migration on a copy, forces legacy-compatible credential writes, and attempts source-only recovery on failure. Tests use real local HTTP subprocesses with **simulated systemctl**; they do not prove that sudo, systemd, signals, service policies, filesystem permissions or recovery work on the Oracle instance. `tools/deploy_preflight.py` is a non-deploying preflight only. Do not invoke the deployment functions on production.

Source-only rollback retains the live SQLite database rather than restoring the old backup, and refuses unknown credential hashes. It does not restore old feature behavior or remove newer tables, avatars, model configuration or conversations, and later changes made while running the old app may not receive the new roles automatically. If the database itself must be restored from an old backup, changes since that snapshot will be lost. The private backups omit tunnel configuration and the workspace. Both recovery methods still require a production-specific procedure and validation.
