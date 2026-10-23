-- keel:global sign-in challenges made before a tenant is known
-- +goose Up
create table auth_challenges (
    id uuid primary key,
    purpose text not null check (char_length(purpose) between 1 and 32),
    user_id uuid references users (id) on delete cascade,
    data text not null check (char_length(data) <= 16384),
    expires_at timestamptz not null,
    created_at timestamptz not null
);
create index auth_challenges_expires_at on auth_challenges (expires_at);
create index auth_challenges_user_id on auth_challenges (user_id);

-- +goose Down
drop table auth_challenges;
