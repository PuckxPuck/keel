-- +goose Up
create table device_pairing_codes (
    code_hash bytea primary key check (octet_length(code_hash) = 32),
    realm text not null check (char_length(realm) between 1 and 64),
    name text not null check (char_length(name) between 1 and 200),
    scope text not null check (char_length(scope) <= 200),
    created_by uuid references users (id) on delete set null,
    created_at timestamptz not null,
    expires_at timestamptz not null,
    used_at timestamptz
);
create index device_pairing_codes_created_by on device_pairing_codes (created_by);
create index device_pairing_codes_expires_at on device_pairing_codes (expires_at);

-- +goose Down
drop table device_pairing_codes;
