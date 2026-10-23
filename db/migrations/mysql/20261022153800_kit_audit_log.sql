-- +goose Up
create table audit_log (
    id char(36) character set ascii collate ascii_bin not null primary key,
    seq bigint not null auto_increment,
    occurred_at datetime(6) not null,
    realm varchar(64) null,
    actor_type varchar(32) not null check (actor_type in ('user', 'system', 'apikey', 'device')),
    actor_id char(36) character set ascii collate ascii_bin null,
    on_behalf_of char(36) character set ascii collate ascii_bin null,
    action varchar(64) not null check (char_length(action) >= 1),
    entity varchar(64) not null,
    entity_id varchar(128) not null,
    `before` json null,
    `after` json null,
    ip varchar(45) null,
    request_id varchar(64) null,
    prev_hash varbinary(32) null,
    hash varbinary(32) null,
    unique key audit_log_seq (seq),
    key audit_log_entity (entity, entity_id, occurred_at),
    key audit_log_actor (actor_id, occurred_at),
    key audit_log_occurred_at (occurred_at)
);

-- +goose Down
drop table audit_log;
