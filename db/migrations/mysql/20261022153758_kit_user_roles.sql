-- +goose Up
create table user_roles (
    id char(36) character set ascii collate ascii_bin not null primary key,
    user_id char(36) character set ascii collate ascii_bin not null,
    role_id char(36) character set ascii collate ascii_bin not null,
    scope_type varchar(64) null check (char_length(scope_type) >= 1),
    scope_id char(36) character set ascii collate ascii_bin null,
    granted_by char(36) character set ascii collate ascii_bin null,
    created_at datetime(6) not null,
    check ((scope_type is null) = (scope_id is null)),
    unique key user_roles_grant_key (user_id, role_id, (coalesce(scope_type, '')), (coalesce(scope_id, ''))),
    key user_roles_role_id (role_id),
    key user_roles_granted_by (granted_by),
    constraint user_roles_user_fk foreign key (user_id) references users (id) on delete cascade,
    constraint user_roles_role_fk foreign key (role_id) references roles (id) on delete cascade,
    constraint user_roles_granted_by_fk foreign key (granted_by) references users (id) on delete set null
);

-- +goose Down
drop table user_roles;
