-- +goose Up
create table users (
    id char(36) character set ascii collate ascii_bin not null primary key,
    email varchar(254) character set utf8mb4 collate utf8mb4_bin not null check (char_length(email) >= 3),
    name varchar(200) not null,
    status varchar(32) not null default 'active' check (status in ('active', 'disabled')),
    created_at datetime(6) not null,
    updated_at datetime(6) not null,
    updated_by char(36) character set ascii collate ascii_bin null,
    version int not null default 1 check (version >= 1),
    unique key users_email_key (email),
    key users_updated_by (updated_by),
    constraint users_updated_by_fk foreign key (updated_by) references users (id) on delete set null
);

-- +goose Down
drop table users;
