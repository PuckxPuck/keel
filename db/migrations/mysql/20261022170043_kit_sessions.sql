-- +goose Up
create table sessions (
    id char(36) character set ascii collate ascii_bin not null primary key,
    token_hash varbinary(32) not null check (length(token_hash) = 32),
    realm varchar(64) character set ascii collate ascii_bin not null check (char_length(realm) >= 1),
    user_id char(36) character set ascii collate ascii_bin not null,
    kind varchar(32) not null check (kind in ('browser', 'api', 'device')),
    mfa_state varchar(32) not null check (mfa_state in ('none', 'pending', 'passed')),
    mfa_at datetime(6) null,
    created_at datetime(6) not null,
    last_seen_at datetime(6) not null,
    idle_expires_at datetime(6) not null,
    absolute_expires_at datetime(6) not null,
    ip varchar(45) null,
    user_agent varchar(256) null,
    revoked_at datetime(6) null,
    access_version bigint not null default 0 check (access_version >= 0),
    unique key sessions_token_hash_key (token_hash),
    key sessions_user_id (user_id),
    key sessions_absolute_expires_at (absolute_expires_at),
    constraint sessions_user_fk foreign key (user_id) references users (id) on delete cascade
);

-- +goose Down
drop table sessions;
