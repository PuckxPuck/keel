-- +goose Up
create table roles (
    id char(36) character set ascii collate ascii_bin not null primary key,
    realm varchar(64) not null check (char_length(realm) >= 1),
    code varchar(64) not null check (char_length(code) >= 1),
    name varchar(100) not null check (char_length(name) >= 1),
    builtin boolean not null default false,
    version int not null default 1 check (version >= 1),
    created_at datetime(6) not null,
    updated_at datetime(6) not null,
    unique key roles_realm_code_key (realm, code)
);

-- +goose Down
drop table roles;
