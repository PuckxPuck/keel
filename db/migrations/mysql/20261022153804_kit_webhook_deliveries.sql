-- +goose Up
create table webhook_deliveries (
    source varchar(64) character set ascii collate ascii_bin not null check (char_length(source) >= 1),
    id varchar(255) character set ascii collate ascii_bin not null check (char_length(id) >= 1),
    received_at datetime(6) not null,
    primary key (source, id),
    key webhook_deliveries_received_at (received_at)
);

-- +goose Down
drop table webhook_deliveries;
