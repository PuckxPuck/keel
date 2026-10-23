-- +goose Up
create table mail_outbox (
    id char(36) character set ascii collate ascii_bin not null primary key,
    message_id varchar(255) character set ascii collate ascii_bin not null check (char_length(message_id) >= 1),
    seq int not null check (seq >= 1),
    job_id char(36) character set ascii collate ascii_bin null,
    status varchar(32) not null check (status in ('queued', 'sending', 'sent', 'failed', 'uncertain')),
    error_code varchar(64) null,
    error varchar(1000) null,
    created_at datetime(6) not null,
    unique key mail_outbox_message_seq (message_id, seq),
    key mail_outbox_created_at (created_at)
);

-- +goose Down
drop table mail_outbox;
