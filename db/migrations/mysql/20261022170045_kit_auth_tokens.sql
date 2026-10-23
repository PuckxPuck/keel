-- +goose Up
create table auth_tokens (
    id char(36) character set ascii collate ascii_bin not null primary key,
    user_id char(36) character set ascii collate ascii_bin not null,
    purpose varchar(32) not null check (purpose in ('reset', 'verify_email', 'invite')),
    token_hash varbinary(32) not null check (length(token_hash) = 32),
    expires_at datetime(6) not null,
    used_at datetime(6) null,
    created_at datetime(6) not null,
    unique key auth_tokens_token_hash_key (token_hash),
    unique key auth_tokens_user_purpose_key (user_id, purpose),
    key auth_tokens_expires_at (expires_at),
    constraint auth_tokens_user_fk foreign key (user_id) references users (id) on delete cascade
);

-- +goose Down
drop table auth_tokens;
