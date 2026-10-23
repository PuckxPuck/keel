-- +goose Up
create table webhook_endpoints (
    id uuid primary key,
    url text not null check (char_length(url) between 1 and 2048),
    description text not null default '' check (char_length(description) <= 200),
    events jsonb not null,
    secret bytea not null,
    status text not null check (status in ('active', 'disabled')),
    failure_count integer not null default 0 check (failure_count >= 0),
    disabled_at timestamptz,
    disabled_reason text check (char_length(disabled_reason) <= 64),
    created_at timestamptz not null,
    updated_at timestamptz not null,
    version integer not null default 1
);
create index webhook_endpoints_status on webhook_endpoints (status);

-- +goose Down
drop table webhook_endpoints;
