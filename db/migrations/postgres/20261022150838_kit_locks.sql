-- keel:global advisory lock names; db.Lock prefixes them with the tenant
-- +goose Up
create table locks (
    name text primary key check (char_length(name) between 1 and 191),
    created_at timestamptz not null default now()
);

-- +goose Down
drop table locks;
