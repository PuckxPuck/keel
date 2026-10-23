-- +goose Up
create table api_keys (
    id uuid primary key,
    name text not null check (char_length(name) between 1 and 100),
    hint text not null check (char_length(hint) between 1 and 64),
    secret_hash bytea not null check (octet_length(secret_hash) = 32),
    scopes text not null check (char_length(scopes) <= 4000),
    created_by uuid references users (id) on delete set null,
    created_at timestamptz not null,
    expires_at timestamptz,
    expiry_reminded_at timestamptz,
    last_used_at timestamptz,
    last_used_ip text check (char_length(last_used_ip) <= 45),
    allowed_cidrs text check (char_length(allowed_cidrs) <= 2000),
    revoked_at timestamptz,
    revoked_by uuid references users (id) on delete set null,
    rate_class text check (char_length(rate_class) between 1 and 32)
);
create index api_keys_created_at on api_keys (created_at, id);
create index api_keys_expires_at on api_keys (expires_at);
create index api_keys_created_by on api_keys (created_by);
create index api_keys_revoked_by on api_keys (revoked_by);

-- +goose Down
drop table api_keys;
