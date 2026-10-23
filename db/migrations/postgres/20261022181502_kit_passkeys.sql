-- keel:global per user, bound to the realm they were registered on
-- +goose Up
create table passkeys (
    id uuid primary key,
    user_id uuid not null references users (id) on delete cascade,
    realm text not null check (char_length(realm) between 1 and 64),
    credential_id bytea not null check (octet_length(credential_id) between 16 and 1023),
    public_key bytea not null check (octet_length(public_key) between 1 and 4096),
    sign_count bigint not null default 0 check (sign_count >= 0),
    transports text not null default '' check (char_length(transports) <= 200),
    aaguid bytea check (octet_length(aaguid) = 16),
    flags smallint not null check (flags between 0 and 255),
    attestation_type text not null default '' check (char_length(attestation_type) <= 64),
    name text not null check (char_length(name) between 1 and 100),
    version integer not null default 1 check (version >= 1),
    created_at timestamptz not null,
    updated_at timestamptz not null,
    last_used_at timestamptz
);
create unique index passkeys_credential_id_key on passkeys (credential_id);
create index passkeys_user_id_realm on passkeys (user_id, realm);

-- +goose Down
drop table passkeys;
