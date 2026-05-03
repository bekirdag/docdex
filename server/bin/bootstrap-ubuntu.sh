#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "bootstrap-ubuntu.sh must run as root" >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

DOCDEX_USER="${DOCDEX_USER:-docdex}"
DEPLOY_USER="${DEPLOY_USER:-deploy}"
DOCDEX_MOUNT="${DOCDEX_MOUNT:-/mnt/docdex}"
DOCDEX_ENV_DIR="${DOCDEX_ENV_DIR:-/etc/docdex}"
DOCDEX_ENV_FILE="${DOCDEX_ENV_FILE:-${DOCDEX_ENV_DIR}/docdex.env}"

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
  ca-certificates \
  certbot \
  curl \
  fail2ban \
  git \
  nginx \
  openssl \
  python3-certbot-nginx \
  rsync

if ! id -u "${DOCDEX_USER}" >/dev/null 2>&1; then
  useradd --system --home "${DOCDEX_MOUNT}" --shell /usr/sbin/nologin "${DOCDEX_USER}"
fi

if ! id -u "${DEPLOY_USER}" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "${DEPLOY_USER}"
fi

install -d -m 0755 -o root -g root /opt/docdex /opt/docdex/bin /opt/docdex/releases
install -d -m 0750 -o "${DOCDEX_USER}" -g "${DOCDEX_USER}" \
  "${DOCDEX_MOUNT}/.docdex" \
  "${DOCDEX_MOUNT}/state" \
  "${DOCDEX_MOUNT}/repos" \
  "${DOCDEX_MOUNT}/logs"
install -d -m 0750 -o root -g "${DOCDEX_USER}" "${DOCDEX_ENV_DIR}"
install -d -m 0755 -o root -g root /var/www/html
install -d -m 0700 -o "${DEPLOY_USER}" -g "${DEPLOY_USER}" "/home/${DEPLOY_USER}/docdex-releases"

if [[ ! -f "${DOCDEX_ENV_FILE}" ]]; then
  token="$(openssl rand -base64 48 | tr -d '\n')"
  umask 027
  cat > "${DOCDEX_ENV_FILE}" <<EOF
DOCDEX_STATE_DIR=${DOCDEX_MOUNT}/state
DOCDEX_AUTH_TOKEN=${token}
DOCDEX_ENABLE_MCP=true
DOCDEX_ENABLE_MEMORY=true
DOCDEX_ACCESS_LOG=true
DOCDEX_AUDIT_LOG_PATH=${DOCDEX_MOUNT}/logs/audit.log
DOCDEX_AUDIT_MAX_BYTES=20000000
DOCDEX_AUDIT_MAX_FILES=10
DOCDEX_MIN_NOFILE_SOFT=8192
DOCDEX_REPO_IDLE_SECONDS=7200
DOCDEX_REPO_HIBERNATE_SECONDS=86400
DOCDEX_REPO_CLEANUP_INTERVAL_SECONDS=600
EOF
  chown root:"${DOCDEX_USER}" "${DOCDEX_ENV_FILE}"
  chmod 0640 "${DOCDEX_ENV_FILE}"
fi

install -m 0755 -o root -g root "${REPO_ROOT}/server/bin/docdex-apply-release" /usr/local/sbin/docdex-apply-release
install -m 0644 -o root -g root "${REPO_ROOT}/server/systemd/docdex.service" /etc/systemd/system/docdex.service
install -m 0644 -o root -g root "${REPO_ROOT}/server/nginx/docdex-http.conf" /etc/nginx/sites-available/docdex.conf
ln -sfn /etc/nginx/sites-available/docdex.conf /etc/nginx/sites-enabled/docdex.conf
rm -f /etc/nginx/sites-enabled/default

cat > /etc/sudoers.d/docdex-deploy <<EOF
${DEPLOY_USER} ALL=(root) NOPASSWD: /usr/local/sbin/docdex-apply-release *
${DEPLOY_USER} ALL=(root) NOPASSWD: /bin/systemctl status docdex.service
${DEPLOY_USER} ALL=(root) NOPASSWD: /usr/bin/journalctl -u docdex.service *
EOF
chmod 0440 /etc/sudoers.d/docdex-deploy
visudo -cf /etc/sudoers.d/docdex-deploy

systemctl daemon-reload
systemctl enable nginx
nginx -t
systemctl reload nginx || systemctl restart nginx
systemctl enable fail2ban
systemctl restart fail2ban

echo "Docdex bootstrap completed. Install a docdexd binary with docdex-apply-release before starting docdex.service."
