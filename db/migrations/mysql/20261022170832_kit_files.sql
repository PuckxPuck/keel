-- +goose Up
create table files (
    id char(36) character set ascii collate ascii_bin not null primary key,
    kind varchar(64) character set ascii collate ascii_bin not null check (char_length(kind) >= 1),
    state varchar(16) character set ascii collate ascii_bin not null check (state in ('pending', 'staged', 'attached')),
    uploader_kind varchar(32) character set ascii collate ascii_bin not null check (char_length(uploader_kind) >= 1),
    uploader_id char(36) character set ascii collate ascii_bin null,
    owner_type varchar(64) character set ascii collate ascii_bin null check (char_length(owner_type) >= 1),
    owner_id char(36) character set ascii collate ascii_bin null,
    name varchar(255) not null check (char_length(name) >= 1),
    mime varchar(255) character set ascii collate ascii_bin not null check (char_length(mime) >= 1),
    size bigint not null check (size > 0),
    sha256 varbinary(32) not null check (length(sha256) = 32),
    storage_key varchar(512) character set ascii collate ascii_bin not null check (char_length(storage_key) >= 1),
    visibility varchar(32) not null check (visibility in ('private', 'public')),
    created_at datetime(6) not null,
    updated_at datetime(6) not null,
    check ((owner_type is null) = (owner_id is null)),
    check ((state = 'attached') = (owner_type is not null)),
    check ((uploader_kind = 'system') = (uploader_id is null)),
    unique key files_storage_key (storage_key),
    key files_owner (owner_type, owner_id),
    key files_unattached (state, updated_at)
);

-- +goose Down
drop table files;
