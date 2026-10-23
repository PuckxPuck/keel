-- +goose Up
create table idempotency_keys (
    id uuid primary key,
    realm text not null check (char_length(realm) <= 64),
    principal text not null check (char_length(principal) between 1 and 128),
    idem_key text not null check (char_length(idem_key) between 1 and 255),
    request_hash bytea not null,
    status text not null check (status in ('in_progress', 'done', 'unknown')),
    response_status integer,
    response_headers jsonb,
    response_body bytea,
    body_stored boolean not null default false,
    created_at timestamptz not null,
    lease_until timestamptz not null,
    expires_at timestamptz not null,
    unique (realm, principal, idem_key)
);
create index idempotency_keys_expires_at on idempotency_keys (expires_at);

-- +goose Down
drop table idempotency_keys;
