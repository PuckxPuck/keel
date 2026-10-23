-- +goose Up
create table files (
    id uuid primary key,
    kind text not null check (char_length(kind) between 1 and 64),
    state text not null check (state in ('pending', 'staged', 'attached')),
    uploader_kind text not null check (char_length(uploader_kind) between 1 and 32),
    uploader_id uuid,
    owner_type text check (char_length(owner_type) between 1 and 64),
    owner_id uuid,
    name text not null check (char_length(name) between 1 and 255),
    mime text not null check (char_length(mime) between 1 and 255),
    size bigint not null check (size > 0),
    sha256 bytea not null check (octet_length(sha256) = 32),
    storage_key text not null unique check (char_length(storage_key) between 1 and 512),
    visibility text not null check (visibility in ('private', 'public')),
    created_at timestamptz not null,
    updated_at timestamptz not null,
    check ((owner_type is null) = (owner_id is null)),
    check ((state = 'attached') = (owner_type is not null)),
    check ((uploader_kind = 'system') = (uploader_id is null))
);
create index files_owner on files (owner_type, owner_id);
create index files_unattached on files (updated_at) where state <> 'attached';

-- +goose Down
drop table files;
