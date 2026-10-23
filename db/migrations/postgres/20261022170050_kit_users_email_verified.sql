-- +goose Up
alter table users
    add column email_verified_at timestamptz,
    add column access_version bigint not null default 0 check (access_version >= 0);

-- +goose Down
alter table users drop column email_verified_at, drop column access_version;
