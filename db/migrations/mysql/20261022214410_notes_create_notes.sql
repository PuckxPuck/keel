-- attachment_id has no foreign key: kit/files owns that row and deletes it only through files.Remove,
-- which the notes service calls when it replaces or deletes the attachment.
-- +goose Up
create table notes (
    id char(36) character set ascii collate ascii_bin not null primary key,
    client_id char(36) character set ascii collate ascii_bin null,
    title varchar(200) not null check (char_length(title) >= 1),
    body text not null,
    status varchar(32) not null default 'active' check (status in ('active', 'archived')),
    archived_at datetime(6) null,
    archived_by char(36) character set ascii collate ascii_bin null,
    word_count int null check (word_count >= 0),
    attachment_id char(36) character set ascii collate ascii_bin null,
    attachment_name varchar(255) null check (char_length(attachment_name) >= 1),
    attachment_mime varchar(255) null check (char_length(attachment_mime) >= 1),
    attachment_size bigint null check (attachment_size >= 0),
    version int not null default 1 check (version >= 1),
    created_by char(36) character set ascii collate ascii_bin null,
    updated_by char(36) character set ascii collate ascii_bin null,
    created_at datetime(6) not null,
    updated_at datetime(6) not null,
    changed_at datetime(6) not null default current_timestamp(6) on update current_timestamp(6),
    check (char_length(body) <= 20000),
    check ((attachment_id is null) = (attachment_name is null) and (attachment_id is null) = (attachment_mime is null)
        and (attachment_id is null) = (attachment_size is null)),
    unique key notes_client_id (client_id),
    key notes_title (title, id),
    key notes_created_at (created_at, id),
    key notes_updated_at (updated_at, id),
    key notes_changed_at (changed_at, id),
    key notes_archived_by (archived_by),
    key notes_created_by (created_by),
    key notes_updated_by (updated_by),
    constraint notes_archived_by_fk foreign key (archived_by) references users (id) on delete set null,
    constraint notes_created_by_fk foreign key (created_by) references users (id) on delete set null,
    constraint notes_updated_by_fk foreign key (updated_by) references users (id) on delete set null
);

-- +goose Down
drop table notes;
