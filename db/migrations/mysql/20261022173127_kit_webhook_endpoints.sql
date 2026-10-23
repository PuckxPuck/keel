-- +goose Up
create table webhook_endpoints (
    id char(36) character set ascii collate ascii_bin not null primary key,
    url varchar(2048) not null check (char_length(url) >= 1),
    description varchar(200) not null default '',
    events json not null,
    secret varbinary(255) not null,
    status varchar(32) not null check (status in ('active', 'disabled')),
    failure_count int not null default 0 check (failure_count >= 0),
    disabled_at datetime(6) null,
    disabled_reason varchar(64) null,
    created_at datetime(6) not null,
    updated_at datetime(6) not null,
    version int not null default 1,
    key webhook_endpoints_status (status)
);

-- +goose Down
drop table webhook_endpoints;
