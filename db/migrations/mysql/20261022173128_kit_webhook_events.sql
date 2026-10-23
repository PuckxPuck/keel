-- +goose Up
create table webhook_events (
    id char(36) character set ascii collate ascii_bin not null primary key,
    type varchar(128) character set ascii collate ascii_bin not null check (char_length(type) >= 1),
    payload json not null,
    created_at datetime(6) not null,
    key webhook_events_created_at (created_at)
);

-- +goose Down
drop table webhook_events;
