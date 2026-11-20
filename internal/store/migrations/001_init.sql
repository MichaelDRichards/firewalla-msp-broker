-- 001_init: keys, secrets, audit log, box/group cache.
-- Timestamps are integer Unix milliseconds (UTC). JSON columns hold small documents.

CREATE TABLE keys (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL,
    kind                  TEXT NOT NULL CHECK (kind IN ('data', 'admin')),
    enabled               INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    expires_at            INTEGER,
    ip_allow              TEXT NOT NULL DEFAULT '[]',
    scope                 TEXT NOT NULL,
    permissions           TEXT NOT NULL,
    rate_limit_per_minute INTEGER,
    notes                 TEXT NOT NULL DEFAULT '',
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL,
    last_used_at          INTEGER,
    deleted_at            INTEGER
);

-- Names are unique among active (not soft-deleted) keys only.
CREATE UNIQUE INDEX keys_name_active ON keys (name) WHERE deleted_at IS NULL;

CREATE TABLE secrets (
    id         TEXT PRIMARY KEY,
    key_id     TEXT NOT NULL REFERENCES keys (id),
    prefix     TEXT NOT NULL,
    hash       BLOB NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked_at INTEGER
);

CREATE INDEX secrets_key_id ON secrets (key_id);

-- key_id is deliberately not a foreign key: blocked attempts with an unknown
-- secret have no key, and audit rows must outlive any key row.
CREATE TABLE audit (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                INTEGER NOT NULL,
    key_id            TEXT,
    key_name_at_time  TEXT,
    secret_prefix     TEXT,
    client_ip         TEXT,
    outcome           TEXT NOT NULL CHECK (outcome IN ('ok', 'upstream_error', 'blocked')),
    block_reason      TEXT,
    method            TEXT NOT NULL DEFAULT '',
    path              TEXT NOT NULL DEFAULT '',
    query             TEXT,
    resource          TEXT,
    action            TEXT,
    gid               TEXT,
    object_id         TEXT,
    upstream_status   INTEGER,
    before_json       TEXT,
    after_json        TEXT,
    revert_of         INTEGER REFERENCES audit (id),
    reverted_by       INTEGER REFERENCES audit (id),
    result_count      INTEGER
);

CREATE INDEX audit_ts ON audit (ts);
CREATE INDEX audit_key_id ON audit (key_id, id);
CREATE INDEX audit_gid ON audit (gid, id);
CREATE INDEX audit_resource ON audit (resource, id);

-- Box list as last fetched from upstream; group membership is each box's
-- group field. Replaced wholesale on refresh.
CREATE TABLE box_cache (
    gid      TEXT PRIMARY KEY,
    name     TEXT NOT NULL DEFAULT '',
    group_id TEXT NOT NULL DEFAULT ''
);

CREATE INDEX box_cache_group ON box_cache (group_id);

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
