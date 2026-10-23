-- +goose Up
create table tombstones (
    entity text not null check (char_length(entity) between 1 and 64),
    id uuid not null,
    change_xid xid8 not null default pg_current_xact_id(),
    deleted_at timestamptz not null,
    primary key (entity, id)
);
create index tombstones_feed on tombstones (entity, change_xid, id);
create index tombstones_deleted_at on tombstones (deleted_at);

-- +goose Down
drop table tombstones;
