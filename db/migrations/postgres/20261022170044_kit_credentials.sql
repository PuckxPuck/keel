-- keel:global per user, like users
-- +goose Up
create table credentials (
    user_id uuid primary key references users (id) on delete cascade,
    password_hash text not null check (char_length(password_hash) between 1 and 256),
    created_at timestamptz not null,
    updated_at timestamptz not null
);

-- +goose Down
drop table credentials;
