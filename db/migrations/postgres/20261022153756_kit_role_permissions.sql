-- +goose Up
create table role_permissions (
    role_id uuid not null references roles (id) on delete cascade,
    permission text not null check (char_length(permission) between 1 and 128),
    primary key (role_id, permission)
);

-- +goose Down
drop table role_permissions;
