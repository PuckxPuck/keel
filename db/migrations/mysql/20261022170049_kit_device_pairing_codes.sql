-- +goose Up
create table device_pairing_codes (
    code_hash varbinary(32) not null primary key check (length(code_hash) = 32),
    realm varchar(64) character set ascii collate ascii_bin not null check (char_length(realm) >= 1),
    name varchar(200) not null check (char_length(name) >= 1),
    scope varchar(200) not null,
    created_by char(36) character set ascii collate ascii_bin null,
    created_at datetime(6) not null,
    expires_at datetime(6) not null,
    used_at datetime(6) null,
    key device_pairing_codes_created_by (created_by),
    key device_pairing_codes_expires_at (expires_at),
    constraint device_pairing_codes_created_by_fk foreign key (created_by) references users (id) on delete set null
);

-- +goose Down
drop table device_pairing_codes;
