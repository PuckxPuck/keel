-- +goose Up
create table oauth_states (
    id char(36) character set ascii collate ascii_bin not null primary key,
    state_hash varbinary(32) not null check (length(state_hash) = 32),
    purpose varchar(32) character set ascii collate ascii_bin not null check (char_length(purpose) >= 1),
    provider varchar(64) character set ascii collate ascii_bin not null check (char_length(provider) >= 1),
    verifier varchar(128) character set ascii collate ascii_bin not null check (char_length(verifier) >= 43),
    nonce varchar(128) character set ascii collate ascii_bin null,
    return_to varchar(2048) null,
    user_id char(36) character set ascii collate ascii_bin null,
    expires_at datetime(6) not null,
    created_at datetime(6) not null,
    unique key oauth_states_state_hash (state_hash),
    key oauth_states_expires_at (expires_at),
    key oauth_states_user (user_id),
    constraint oauth_states_user_fk foreign key (user_id) references users (id) on delete cascade
);

-- +goose Down
drop table oauth_states;
