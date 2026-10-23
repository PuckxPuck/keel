-- +goose Up
create table devices (
    id uuid primary key,
    realm text not null check (char_length(realm) between 1 and 64),
    name text not null check (char_length(name) between 1 and 200),
    scope text not null check (char_length(scope) <= 200),
    secret_hash bytea not null check (octet_length(secret_hash) = 32),
    previous_secret_hash bytea check (octet_length(previous_secret_hash) = 32),
    previous_valid_until timestamptz,
    created_by uuid references users (id) on delete set null,
    created_at timestamptz not null,
    last_seen_at timestamptz,
    revoked_at timestamptz
);
create index devices_created_by on devices (created_by);

-- +goose Down
drop table devices;
