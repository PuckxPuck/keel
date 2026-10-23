-- keel:global inbound delivery ids, recorded before any tenant is known
-- +goose Up
create table webhook_deliveries (
    source text not null check (char_length(source) between 1 and 64),
    id text not null check (char_length(id) between 1 and 255),
    received_at timestamptz not null,
    primary key (source, id)
);
create index webhook_deliveries_received_at on webhook_deliveries (received_at);

-- +goose Down
drop table webhook_deliveries;
