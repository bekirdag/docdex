# Docdex Dedicated Server

This folder contains non-secret operational assets for running the hosted Docdex
daemon. It is intentionally separate from the client/runtime source tree.

## Runtime Shape

- `docdexd daemon` runs as the `docdex` system user.
- The hosted daemon binds to `127.0.0.1:28492`; public traffic terminates at
  nginx. Port `28491` remains reserved for the machine-local Docdex daemon.
- Persistent state, indexes, audit logs, and managed repository data live under
  `/mnt/docdex`.
- Web discovery is enabled for the hosted daemon, including encrypted-repo
  search policy, and release activation attempts to install Docdex-managed
  Chromium under `/mnt/docdex/state` so link fetches work. Discovery defaults
  to local DuckDuckGo first, `https://se.overrid.com/search` second, and paid
  providers such as Brave only after those free paths fail.
- Repo memory, conversation memory, profile memory, personal preferences, and
  mind-clone context are enabled for hosted/company-wide chat clients. The
  shared personal-preferences store lives at `/mnt/docdex/personal_preferences`.
- Runtime secrets live only in `/etc/docdex/docdex.env`.
- CI deploys only the compiled `docdexd` binary; privileged installation is
  performed by the root-owned `/usr/local/sbin/docdex-apply-release` script.

## Server Directories

```text
/opt/docdex/bin/          active binary symlink
/opt/docdex/releases/     immutable release binaries
/etc/docdex/              runtime env, root-owned
/mnt/docdex/state/        Docdex state directory
/mnt/docdex/personal_preferences/
                          shared personal preferences and mind-clone store
/mnt/docdex/repos/        managed repository/index source storage
/mnt/docdex/logs/         audit/service logs
```

## Required GitHub Secrets

```text
DOCDEX_DEPLOY_HOST
DOCDEX_DEPLOY_PORT
DOCDEX_DEPLOY_USER
DOCDEX_DEPLOY_SSH_KEY
DOCDEX_DEPLOY_KNOWN_HOSTS
```

Populate `DOCDEX_DEPLOY_KNOWN_HOSTS` from host public keys obtained through an
already trusted administrative channel. Do not generate it with first-contact
`ssh-keyscan` during deployment.

Do not commit tokens, private keys, API keys, generated env files, or server
inventory that should stay private.

## One-Time Bootstrap

Run the bootstrap script as root from a checked-out repository copy:

```bash
sudo server/bin/bootstrap-ubuntu.sh
```

The script installs packages, creates service and root-anchored release-staging
directories, installs the systemd/nginx templates, creates
`/etc/docdex/docdex.env` if it does not exist, and installs the release-apply
helper plus a narrow sudoers rule for the deploy user.

After DNS points at the server, issue TLS certificates and switch nginx to the
TLS template:

```bash
sudo certbot certonly --webroot -w /var/www/html \
  -d api.docdex.org -d service.docdex.org -d auth.docdex.org
sudo install -m 0644 server/nginx/docdex-tls.conf /etc/nginx/sites-available/docdex.conf
sudo nginx -t
sudo systemctl reload nginx
```

## Health Checks

```bash
curl -fsS http://127.0.0.1:28492/healthz
curl -fsS http://127.0.0.1:28492/v1/personal-preferences/status
curl -fsS https://api.docdex.org/healthz
```

Release candidates must be uploaded as
`/var/lib/docdex-deploy/incoming/<40-character-commit-sha>/docdexd`. The
root-owned helper copies the candidate as the unprivileged deploy user and runs
its pre-activation `--version` check as the `docdex` service user only after the
root-owned copy matches the expected SHA-256 argument; it never executes a
deploy-controlled program as root. Rollbacks accept only existing, root-owned
immutable binaries under `/opt/docdex/releases` and must also match their
expected SHA-256.

`docdex-apply-release` performs the local health check plus the
`/v1/personal-preferences/status` smoke check after every activation.
