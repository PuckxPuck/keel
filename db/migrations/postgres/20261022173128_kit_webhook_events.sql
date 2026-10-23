-- +goose Up
create table webhook_events (
    id uuid primary key,
    type text not null check (char_length(type) between 1 and 128),
    payload jsonb not null,
    created_at timestamptz not null
);
create index webhook_events_created_at on webhook_events (created_at);

-- +goose Down
drop table webhook_events;
