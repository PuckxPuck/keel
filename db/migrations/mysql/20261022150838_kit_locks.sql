-- +goose Up
create table locks (
    name varchar(191) character set utf8mb4 collate utf8mb4_bin not null primary key check (char_length(name) >= 1),
    created_at datetime(6) not null default current_timestamp(6)
);

-- +goose Down
drop table locks;
