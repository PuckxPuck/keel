-- keel:global per user, like users
-- +goose Up
create table auth_tokens (
    id uuid primary key,
    user_id uuid not null references users (id) on delete cascade,
    purpose text not null check (purpose in ('reset', 'verify_email', 'invite')),
    token_hash bytea not null check (octet_length(token_hash) = 32),
    expires_at timestamptz not null,
    used_at timestamptz,
    created_at timestamptz not null
);
create unique index auth_tokens_token_hash_key on auth_tokens (token_hash);
-- One live token per user and purpose: issuing replaces the row, so an earlier link stops working.
create unique index auth_tokens_user_purpose_key on auth_tokens (user_id, purpose);
create index auth_tokens_expires_at on auth_tokens (expires_at);

-- +goose Down
drop table auth_tokens;
