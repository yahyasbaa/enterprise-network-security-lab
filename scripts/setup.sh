#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v docker >/dev/null
command -v python3 >/dev/null
command -v openssl >/dev/null
command -v ssh-keygen >/dev/null
docker info >/dev/null
docker compose version
[[ -f .env ]] || cp .env.example .env
mkdir -p runtime/secrets runtime/logs/{firewall,suricata,web,ssh} reports
chmod 700 runtime runtime/secrets reports
umask 077
for secret in db_password ssh_password web_password; do
    [[ -s runtime/secrets/$secret ]] || openssl rand -hex 24 > "runtime/secrets/$secret"
done
if [[ ! -f runtime/secrets/admin_key ]]; then
    ssh-keygen -q -t ed25519 -N '' -f runtime/secrets/admin_key
fi
if [[ ! -f runtime/secrets/web_htpasswd ]]; then
    printf 'analyst:%s\n' "$(openssl passwd -apr1 -stdin < runtime/secrets/web_password)" > runtime/secrets/web_htpasswd
fi
# Nginx worker must read just its password hash, not the password/private key.
chmod 644 runtime/secrets/web_htpasswd runtime/secrets/admin_key.pub
umask 022
python3 -m venv .venv
.venv/bin/pip install -q -r requirements-dev.txt
docker compose config --quiet
docker compose build firewall
printf '\nSetup complete. Run make up.\n'
