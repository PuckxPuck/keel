-- +goose Up
create table mfa_totp (
    user_id char(36) character set ascii collate ascii_bin not null primary key,
    secret_enc varbinary(256) not null check (length(secret_enc) >= 1),
    confirmed_at datetime(6) null,
    last_step bigint null check (last_step >= 0),
    created_at datetime(6) not null,
    updated_at datetime(6) not null,
    constraint mfa_totp_user_fk foreign key (user_id) references users (id) on delete cascade
);

-- +goose Down
drop table mfa_totp;
