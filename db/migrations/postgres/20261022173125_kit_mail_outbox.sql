-- +goose Up
create table mail_outbox (
    id uuid primary key,
    message_id text not null check (char_length(message_id) between 1 and 255),
    seq integer not null check (seq >= 1),
    job_id uuid,
    status text not null check (status in ('queued', 'sending', 'sent', 'failed', 'uncertain')),
    error_code text check (char_length(error_code) <= 64),
    error text check (char_length(error) <= 1000),
    created_at timestamptz not null,
    unique (message_id, seq)
);
create index mail_outbox_created_at on mail_outbox (created_at);

-- +goose Down
drop table mail_outbox;
