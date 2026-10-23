-- +goose Up
create table credentials (
    user_id char(36) character set ascii collate ascii_bin not null primary key,
    password_hash varchar(256) character set ascii collate ascii_bin not null check (char_length(password_hash) >= 1),
    created_at datetime(6) not null,
    updated_at datetime(6) not null,
    constraint credentials_user_fk foreign key (user_id) references users (id) on delete cascade
);

-- +goose Down
drop table credentials;
