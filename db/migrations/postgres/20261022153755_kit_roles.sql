-- +goose Up
create table roles (
    id uuid primary key,
    realm text not null check (char_length(realm) between 1 and 64),
    code text not null check (char_length(code) between 1 and 64),
    name text not null check (char_length(name) between 1 and 100),
    builtin boolean not null default false,
    version integer not null default 1 check (version >= 1),
    created_at timestamptz not null,
    updated_at timestamptz not null,
    unique (realm, code)
);

-- +goose Down
drop table roles;
