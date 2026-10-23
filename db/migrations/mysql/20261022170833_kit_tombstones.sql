-- +goose Up
create table tombstones (
    entity varchar(64) character set ascii collate ascii_bin not null check (char_length(entity) >= 1),
    id char(36) character set ascii collate ascii_bin not null,
    changed_at datetime(6) not null default current_timestamp(6),
    deleted_at datetime(6) not null,
    primary key (entity, id),
    key tombstones_feed (entity, changed_at, id),
    key tombstones_deleted_at (deleted_at)
);

-- +goose Down
drop table tombstones;
