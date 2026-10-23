-- +goose Up
create table api_keys (
    id char(36) character set ascii collate ascii_bin not null primary key,
    name varchar(100) not null check (char_length(name) >= 1),
    hint varchar(64) character set ascii collate ascii_bin not null check (char_length(hint) >= 1),
    secret_hash varbinary(32) not null check (length(secret_hash) = 32),
    scopes varchar(4000) character set ascii collate ascii_bin not null,
    created_by char(36) character set ascii collate ascii_bin null,
    created_at datetime(6) not null,
    expires_at datetime(6) null,
    expiry_reminded_at datetime(6) null,
    last_used_at datetime(6) null,
    last_used_ip varchar(45) character set ascii collate ascii_bin null,
    allowed_cidrs varchar(2000) character set ascii collate ascii_bin null,
    revoked_at datetime(6) null,
    revoked_by char(36) character set ascii collate ascii_bin null,
    rate_class varchar(32) character set ascii collate ascii_bin null check (char_length(rate_class) >= 1),
    key api_keys_created_at (created_at, id),
    key api_keys_expires_at (expires_at),
    key api_keys_created_by (created_by),
    key api_keys_revoked_by (revoked_by),
    constraint api_keys_created_by_fk foreign key (created_by) references users (id) on delete set null,
    constraint api_keys_revoked_by_fk foreign key (revoked_by) references users (id) on delete set null
);

-- +goose Down
drop table api_keys;
