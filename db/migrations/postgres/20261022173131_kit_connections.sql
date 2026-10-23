-- +goose Up
create table connections (
    id uuid primary key,
    provider text not null check (char_length(provider) between 1 and 64),
    external_account_id text not null check (char_length(external_account_id) between 1 and 255),
    scopes text not null default '' check (char_length(scopes) <= 2000),
    status text not null check (status in ('active', 'needs_reauth', 'disconnecting')),
    access_token bytea not null,
    refresh_token bytea,
    token_type text not null default '' check (char_length(token_type) <= 32),
    expires_at timestamptz,
    created_by uuid references users (id),
    created_at timestamptz not null,
    updated_at timestamptz not null,
    version integer not null default 1,
    refresh_owner text check (char_length(refresh_owner) between 1 and 64),
    refreshing_until timestamptz,
    unique (provider, external_account_id)
);
create index connections_created_by on connections (created_by);

-- +goose Down
drop table connections;
