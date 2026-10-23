-- keel:global per user, like users
-- +goose Up
create table mfa_totp (
    user_id uuid primary key references users (id) on delete cascade,
    secret_enc bytea not null check (octet_length(secret_enc) between 1 and 256),
    confirmed_at timestamptz,
    last_step bigint check (last_step >= 0),
    created_at timestamptz not null,
    updated_at timestamptz not null
);

-- +goose Down
drop table mfa_totp;
