-- keel:global a session belongs to a user and records its current tenant
-- +goose Up
create table sessions (
    id uuid primary key,
    token_hash bytea not null check (octet_length(token_hash) = 32),
    realm text not null check (char_length(realm) between 1 and 64),
    user_id uuid not null references users (id) on delete cascade,
    kind text not null check (kind in ('browser', 'api', 'device')),
    mfa_state text not null check (mfa_state in ('none', 'pending', 'passed')),
    mfa_at timestamptz,
    created_at timestamptz not null,
    last_seen_at timestamptz not null,
    idle_expires_at timestamptz not null,
    absolute_expires_at timestamptz not null,
    ip text check (char_length(ip) <= 45),
    user_agent text check (char_length(user_agent) <= 256),
    revoked_at timestamptz,
    access_version bigint not null default 0 check (access_version >= 0)
);
create unique index sessions_token_hash_key on sessions (token_hash);
create index sessions_user_id on sessions (user_id);
create index sessions_absolute_expires_at on sessions (absolute_expires_at);

-- +goose Down
drop table sessions;
