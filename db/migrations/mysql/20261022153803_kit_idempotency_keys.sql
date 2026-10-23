-- +goose Up
create table idempotency_keys (
    id char(36) character set ascii collate ascii_bin not null primary key,
    realm varchar(64) character set ascii collate ascii_bin not null,
    principal varchar(128) character set ascii collate ascii_bin not null check (char_length(principal) >= 1),
    idem_key varchar(255) character set ascii collate ascii_bin not null check (char_length(idem_key) >= 1),
    request_hash varbinary(32) not null,
    status varchar(32) not null check (status in ('in_progress', 'done', 'unknown')),
    response_status int null,
    response_headers json null,
    response_body mediumblob null,
    body_stored boolean not null default false,
    created_at datetime(6) not null,
    lease_until datetime(6) not null,
    expires_at datetime(6) not null,
    unique key idempotency_keys_scope_key (realm, principal, idem_key),
    key idempotency_keys_expires_at (expires_at)
);

-- +goose Down
drop table idempotency_keys;
