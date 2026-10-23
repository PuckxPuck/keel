-- +goose Up
create table jobs (
    id uuid primary key,
    kind text not null check (char_length(kind) between 1 and 128),
    lane text not null check (char_length(lane) between 1 and 32),
    priority integer not null default 0 check (priority between -1000 and 1000),
    payload jsonb not null,
    unique_key text check (char_length(unique_key) between 1 and 255),
    status text not null check (status in ('queued', 'running', 'done', 'failed', 'cancelled')),
    attempts integer not null default 0 check (attempts >= 0),
    max_attempts integer not null check (max_attempts between 1 and 1000),
    run_at timestamptz not null,
    locked_by text check (char_length(locked_by) between 1 and 128),
    locked_until timestamptz,
    last_error_code text check (char_length(last_error_code) <= 64),
    last_error text check (char_length(last_error) <= 1000),
    created_at timestamptz not null,
    updated_at timestamptz not null,
    finished_at timestamptz,
    check ((status = 'running') = (locked_by is not null and locked_until is not null))
);
create index jobs_ready on jobs (lane, priority desc, run_at) where status = 'queued';
create index jobs_leased on jobs (locked_until) where status = 'running';
create index jobs_finished on jobs (finished_at) where status in ('done', 'failed', 'cancelled');
create unique index jobs_open_unique on jobs (unique_key) where status in ('queued', 'running');

-- +goose Down
drop table jobs;
