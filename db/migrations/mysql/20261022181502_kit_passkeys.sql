-- +goose Up
create table passkeys (
    id char(36) character set ascii collate ascii_bin not null primary key,
    user_id char(36) character set ascii collate ascii_bin not null,
    realm varchar(64) character set ascii collate ascii_bin not null check (char_length(realm) >= 1),
    credential_id varbinary(1023) not null check (length(credential_id) >= 16),
    public_key varbinary(4096) not null check (length(public_key) >= 1),
    sign_count bigint not null default 0 check (sign_count >= 0),
    transports varchar(200) character set ascii collate ascii_bin not null default '',
    aaguid varbinary(16) null check (length(aaguid) = 16),
    flags smallint not null check (flags between 0 and 255),
    attestation_type varchar(64) character set ascii collate ascii_bin not null default '',
    name varchar(100) not null check (char_length(name) >= 1),
    version int not null default 1 check (version >= 1),
    created_at datetime(6) not null,
    updated_at datetime(6) not null,
    last_used_at datetime(6) null,
    unique key passkeys_credential_id_key (credential_id),
    key passkeys_user_id_realm (user_id, realm),
    constraint passkeys_user_fk foreign key (user_id) references users (id) on delete cascade
);

-- +goose Down
drop table passkeys;
