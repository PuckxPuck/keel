-- +goose Up
create table user_roles (
    id uuid primary key,
    user_id uuid not null references users (id) on delete cascade,
    role_id uuid not null references roles (id) on delete cascade,
    scope_type text check (char_length(scope_type) between 1 and 64),
    scope_id uuid,
    granted_by uuid references users (id) on delete set null,
    created_at timestamptz not null,
    check ((scope_type is null) = (scope_id is null)),
    unique nulls not distinct (user_id, role_id, scope_type, scope_id)
);
create index user_roles_role_id on user_roles (role_id);
create index user_roles_granted_by on user_roles (granted_by);

-- +goose Down
drop table user_roles;
