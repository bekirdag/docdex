# Docdex Dedicated Server

This folder contains non-secret operational assets for running the hosted Docdex
daemon. It is intentionally separate from the client/runtime source tree.

## Runtime Shape

- `docdexd daemon` runs as the `docdex` system user.
- The daemon binds to `127.0.0.1:28491`; public traffic terminates at nginx.
- Persistent state, indexes, audit logs, and managed repository data live under
  `/mnt/docdex`.
- Runtime secrets live only in `/etc/docdex/docdex.env`.
- CI deploys only the compiled `docdexd` binary; privileged installation is
  performed by the root-owned `/usr/local/sbin/docdex-apply-release` script.

## Server Directories

```text
/opt/docdex/bin/          active binary symlink
/opt/docdex/releases/     immutable release binaries
/etc/docdex/              runtime env, root-owned
/mnt/docdex/state/        Docdex state directory
/mnt/docdex/repos/        managed repository/index source storage
/mnt/docdex/logs/         audit/service logs
```

## Required GitHub Secrets

```text
DOCDEX_DEPLOY_HOST
DOCDEX_DEPLOY_PORT
DOCDEX_DEPLOY_USER
DOCDEX_DEPLOY_SSH_KEY
```

Do not commit tokens, private keys, API keys, generated env files, or server
inventory that should stay private.

## One-Time Bootstrap

Run the bootstrap script as root from a checked-out repository copy:

```bash
sudo server/bin/bootstrap-ubuntu.sh
```

The script installs packages, creates service directories, installs the
systemd/nginx templates, creates `/etc/docdex/docdex.env` if it does not exist,
and installs the release-apply helper plus a narrow sudoers rule for the deploy
user.

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
curl -fsS http://127.0.0.1:28491/healthz
curl -fsS https://api.docdex.org/healthz
```
