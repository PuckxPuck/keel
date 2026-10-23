-- +goose Up
create table webhook_out_deliveries (
    id uuid primary key,
    event_id uuid not null references webhook_events (id) on delete cascade,
    endpoint_id uuid not null references webhook_endpoints (id) on delete cascade,
    status text not null check (status in ('pending', 'succeeded', 'failed', 'skipped')),
    attempts integer not null default 0 check (attempts >= 0),
    generation integer not null default 0,
    last_status_code integer,
    last_error_code text check (char_length(last_error_code) <= 64),
    last_error text check (char_length(last_error) <= 1000),
    created_at timestamptz not null,
    updated_at timestamptz not null,
    delivered_at timestamptz
);
create index webhook_out_deliveries_event on webhook_out_deliveries (event_id);
create index webhook_out_deliveries_endpoint on webhook_out_deliveries (endpoint_id, created_at);

-- +goose Down
drop table webhook_out_deliveries;
