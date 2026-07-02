#!/bin/bash
set -euo pipefail
PG_BIN=/usr/lib/postgresql/17/bin
mkdir -p /data/postgres
chown postgres:postgres /data/postgres
if [[ ! -f /data/postgres/PG_VERSION ]]; then
    runuser -u postgres -- "$PG_BIN/initdb" -D /data/postgres --auth-local=trust --auth-host=scram-sha-256
    cat >> /data/postgres/postgresql.conf <<'EOF'
listen_addresses = '*'
max_connections = 30
shared_buffers = 32MB
log_connections = on
log_disconnections = on
password_encryption = 'scram-sha-256'
EOF
    cat > /data/postgres/pg_hba.conf <<'EOF'
local all all trust
host lab labapp 10.77.50.10/32 scram-sha-256
host lab labapp 10.77.30.10/32 scram-sha-256
host lab labapp 10.77.40.20/32 scram-sha-256
EOF
    runuser -u postgres -- "$PG_BIN/pg_ctl" -D /data/postgres -w start
    runuser -u postgres -- psql -v ON_ERROR_STOP=1 --set=password="$(cat /run/secrets/db_password)" <<'EOF'
CREATE ROLE labapp LOGIN PASSWORD :'password';
CREATE DATABASE lab OWNER labapp;
EOF
    runuser -u postgres -- psql -v ON_ERROR_STOP=1 -d lab <<'EOF'
CREATE TABLE inventory (id integer PRIMARY KEY, name text NOT NULL);
INSERT INTO inventory VALUES (1, 'DMZ web server'), (2, 'Internal database');
GRANT SELECT ON inventory TO labapp;
EOF
    runuser -u postgres -- "$PG_BIN/pg_ctl" -D /data/postgres -m fast -w stop
fi
exec runuser -u postgres -- "$PG_BIN/postgres" -D /data/postgres
