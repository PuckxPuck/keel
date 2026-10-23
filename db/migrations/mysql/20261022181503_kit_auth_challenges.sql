-- +goose Up
create table auth_challenges (
    id char(36) character set ascii collate ascii_bin not null primary key,
    purpose varchar(32) character set ascii collate ascii_bin not null check (char_length(purpose) >= 1),
    user_id char(36) character set ascii collate ascii_bin null,
    data text not null,
    expires_at datetime(6) not null,
    created_at datetime(6) not null,
    key auth_challenges_expires_at (expires_at),
    key auth_challenges_user_id (user_id),
    constraint auth_challenges_user_fk foreign key (user_id) references users (id) on delete cascade
);

-- +goose Down
drop table auth_challenges;
