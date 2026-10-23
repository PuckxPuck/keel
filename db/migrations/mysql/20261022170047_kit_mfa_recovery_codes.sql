-- +goose Up
create table mfa_recovery_codes (
    id char(36) character set ascii collate ascii_bin not null primary key,
    user_id char(36) character set ascii collate ascii_bin not null,
    salt varbinary(16) not null check (length(salt) = 16),
    code_hash varbinary(32) not null check (length(code_hash) = 32),
    used_at datetime(6) null,
    created_at datetime(6) not null,
    key mfa_recovery_codes_user_id (user_id),
    constraint mfa_recovery_codes_user_fk foreign key (user_id) references users (id) on delete cascade
);

-- +goose Down
drop table mfa_recovery_codes;
