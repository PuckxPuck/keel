-- keel:global one identity across tenants; memberships grant entry
-- +goose Up
create table users (
    id uuid primary key,
    email text not null check (char_length(email) between 3 and 254),
    name text not null check (char_length(name) <= 200),
    status text not null default 'active' check (status in ('active', 'disabled')),
    created_at timestamptz not null,
    updated_at timestamptz not null,
    updated_by uuid references users (id) on delete set null,
    version integer not null default 1 check (version >= 1)
);
-- Go normalises emails (trim, lower case, NFC), so the index compares them exactly.
create unique index users_email_key on users (email);
create index users_updated_by on users (updated_by);

-- +goose Down
drop table users;
