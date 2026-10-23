-- attachment_id has no foreign key: kit/files owns that row and deletes it only through files.Remove,
-- which the notes service calls when it replaces or deletes the attachment.
-- +goose Up
create table notes (
    id uuid primary key,
    client_id uuid unique,
    title text not null check (char_length(title) between 1 and 200),
    body text not null default '' check (char_length(body) <= 20000),
    status text not null default 'active' check (status in ('active', 'archived')),
    archived_at timestamptz,
    archived_by uuid references users (id) on delete set null,
    word_count integer check (word_count >= 0),
    attachment_id uuid,
    attachment_name text check (char_length(attachment_name) between 1 and 255),
    attachment_mime text check (char_length(attachment_mime) between 1 and 255),
    attachment_size bigint check (attachment_size >= 0),
    version integer not null default 1 check (version >= 1),
    created_by uuid references users (id) on delete set null,
    updated_by uuid references users (id) on delete set null,
    created_at timestamptz not null,
    updated_at timestamptz not null,
    change_xid xid8 not null default pg_current_xact_id(),
    check ((attachment_id is null) = (attachment_name is null) and (attachment_id is null) = (attachment_mime is null)
        and (attachment_id is null) = (attachment_size is null))
);
create index notes_title on notes (title, id);
create index notes_created_at on notes (created_at, id);
create index notes_updated_at on notes (updated_at, id);
create index notes_change_xid on notes (change_xid, id);
create index notes_archived_by on notes (archived_by);
create index notes_created_by on notes (created_by);
create index notes_updated_by on notes (updated_by);

-- +goose Down
drop table notes;
