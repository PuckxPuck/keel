-- keel:global sign-in state made before a tenant is known; Take checks the recorded tenant
-- +goose Up
create table oauth_states (
    id uuid primary key,
    state_hash bytea not null unique check (octet_length(state_hash) = 32),
    purpose text not null check (char_length(purpose) between 1 and 32),
    provider text not null check (char_length(provider) between 1 and 64),
    verifier text not null check (char_length(verifier) between 43 and 128),
    nonce text check (char_length(nonce) <= 128),
    return_to text check (char_length(return_to) <= 2048),
    user_id uuid references users (id) on delete cascade,
    expires_at timestamptz not null,
    created_at timestamptz not null
);
create index oauth_states_expires_at on oauth_states (expires_at);
create index oauth_states_user on oauth_states (user_id);

-- +goose Down
drop table oauth_states;
