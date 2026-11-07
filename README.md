# Access Hub Next (development only)

## Deployment status and UI redesign

The operator reported applying revision `dfca9fd8e68878fdf7a1ec50811f692f8ea274b4` on Oracle and seeing `access-hub.service` active. The redesigned UI in this branch has **not** been applied to that server. Existing documentation below describes the earlier development and rehearsal process; those warnings and limitations remain relevant, but statements that nothing has been installed predate the operator's reported installation.

**Do not rerun `tools.deploy_cli --apply` as an update:** that installer expects the original baseline `app.py`, not the already-installed release wrapper. A separate, version-aware update and recovery procedure is required before deploying this redesign. OpenClaw and Telegram are not implemented; the existing chat uses local Ollama directly.

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

`tools/deploy_candidate.py` contains **experimental** deployment and source-only rollback building blocks, and `tools/systemd_adapter.py` has Linux/systemd safety checks. The code prepares a private release, validates the system interpreter and Pillow, stops through an injected service adapter, snapshots SQLite and the original app, tests migration on a copy, forces legacy-compatible credential writes, and attempts source-only recovery on failure. Local tests use real HTTP subprocesses with **simulated systemctl**. The operator reported a successful isolated systemd rehearsal on Oracle for an earlier revision; this does not verify the live service, current revision, all signals, policies or recovery conditions. `tools/deploy_preflight.py` is a non-deploying preflight only. `tools/deploy_cli.py` is an experimental operator interface and is not approved for production; do not use its apply or rollback actions on a live system.

Source-only rollback retains the live SQLite database rather than restoring the old backup, and refuses unknown credential hashes. It does not restore old feature behavior or remove newer tables, avatars, model configuration or conversations; accounts created while the old app is active are assigned a default role on the next migration, while deliberately removed roles on existing profiles remain removed. If the database itself must be restored from an old backup, changes since that snapshot will be lost. The private backups omit tunnel configuration and the workspace. Both recovery methods still require a production-specific procedure and validation.

`tools/rehearse_systemd.py` is an **isolated rehearsal**, not a live installation: it copies a verified private backup into a private directory, creates temporary test credentials only in that copy, and exercises deployment and source-only rollback through a uniquely named systemd service bound to loopback. It temporarily installs a test unit under `/run/systemd/system`, uses cached sudo, calls `daemon-reload`, and tries to stop/remove the test unit afterward. The normal Access Hub service and database are not touched. Failure or interruption may leave the temporary unit or private test copies behind; inspect and clean up only the named rehearsal unit. Its local automated tests use simulated systemctl; a prior revision was additionally rehearsed using a temporary real systemd unit on the target host. The temporary service does not reproduce every production unit restriction or test real Ollama/OpenClaw, and success does not itself establish production readiness.

The audit view is restricted to administrators with `system.logs`, paginates events, and never returns raw audit details. Successful logins/logouts, account and access changes, model policy changes, profile changes, and Repo Lab command requests are recorded; command text and chat contents are not. This is not complete security-event coverage: failed sign-ins, all authorization denials, command results and every infrastructure action are not comprehensively audited. Avatar replacement/deletion cleans unreferenced images on a best-effort basis, but storage quotas and a comprehensive security review are not complete.
