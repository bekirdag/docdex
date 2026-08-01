# Overrid SearXNG

This Compose stack runs the SearXNG fallback used by Docdex at
`https://se.overrid.com/search`. The container port is bound to loopback so
only the host nginx proxy can expose it. JSON search is explicitly enabled.

## Deploy

Create a private `.env` beside `docker-compose.yml` and generate a unique
secret without printing it:

```bash
install -m 0600 searxng.env.example .env
sed -i "s|^SEARXNG_SECRET=.*|SEARXNG_SECRET=$(openssl rand -hex 32)|" .env
docker compose pull
docker compose up -d
```

Install `nginx-http.conf` as the dedicated site first and reload nginx only
after `nginx -t` succeeds. Obtain the Let's Encrypt certificate for
`se.overrid.com` with the `/var/www/html` webroot, then replace the site with
`nginx.conf`, validate again, and reload. The two-stage bootstrap prevents the
TLS vhost from referencing certificate files before Certbot creates them.
Those edge steps require root and are deliberately separate from the Docker
account.

## Validate

```bash
curl -fsS http://127.0.0.1:8888/healthz
curl --compressed -fsS \
  'http://127.0.0.1:8888/search?q=Docdex&format=json' |
  jq -e '.results | type == "array"'
curl -fsS https://se.overrid.com/healthz
```

Rollback with `docker compose down`; the named volumes remain available for a
subsequent restart. Keep `.env` private and never commit its secret.
