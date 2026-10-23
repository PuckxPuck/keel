-- keel:global per user, like users
-- +goose Up
create table mfa_recovery_codes (
    id uuid primary key,
    user_id uuid not null references users (id) on delete cascade,
    salt bytea not null check (octet_length(salt) = 16),
    code_hash bytea not null check (octet_length(code_hash) = 32),
    used_at timestamptz,
    created_at timestamptz not null
);
create index mfa_recovery_codes_user_id on mfa_recovery_codes (user_id);

-- +goose Down
drop table mfa_recovery_codes;
