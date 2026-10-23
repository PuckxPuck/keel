-- +goose Up
create table devices (
    id char(36) character set ascii collate ascii_bin not null primary key,
    realm varchar(64) character set ascii collate ascii_bin not null check (char_length(realm) >= 1),
    name varchar(200) not null check (char_length(name) >= 1),
    scope varchar(200) not null,
    secret_hash varbinary(32) not null check (length(secret_hash) = 32),
    previous_secret_hash varbinary(32) null check (length(previous_secret_hash) = 32),
    previous_valid_until datetime(6) null,
    created_by char(36) character set ascii collate ascii_bin null,
    created_at datetime(6) not null,
    last_seen_at datetime(6) null,
    revoked_at datetime(6) null,
    key devices_created_by (created_by),
    constraint devices_created_by_fk foreign key (created_by) references users (id) on delete set null
);

-- +goose Down
drop table devices;
