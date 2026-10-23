-- +goose Up
create table role_permissions (
    role_id char(36) character set ascii collate ascii_bin not null,
    permission varchar(128) not null check (char_length(permission) >= 1),
    primary key (role_id, permission),
    constraint role_permissions_role_fk foreign key (role_id) references roles (id) on delete cascade
);

-- +goose Down
drop table role_permissions;
