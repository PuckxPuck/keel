-- +goose Up
create table jobs (
    id char(36) character set ascii collate ascii_bin not null primary key,
    kind varchar(128) character set ascii collate ascii_bin not null check (char_length(kind) >= 1),
    lane varchar(32) character set ascii collate ascii_bin not null check (char_length(lane) >= 1),
    priority int not null default 0 check (priority between -1000 and 1000),
    payload json not null,
    unique_key varchar(255) collate utf8mb4_bin null check (char_length(unique_key) >= 1),
    status varchar(32) not null check (status in ('queued', 'running', 'done', 'failed', 'cancelled')),
    attempts int not null default 0 check (attempts >= 0),
    max_attempts int not null check (max_attempts between 1 and 1000),
    run_at datetime(6) not null,
    locked_by varchar(128) character set ascii collate ascii_bin null check (char_length(locked_by) >= 1),
    locked_until datetime(6) null,
    last_error_code varchar(64) null,
    last_error varchar(1000) null,
    created_at datetime(6) not null,
    updated_at datetime(6) not null,
    finished_at datetime(6) null,
    check ((status = 'running') = (locked_by is not null and locked_until is not null)),
    key jobs_ready (lane, status, priority desc, run_at),
    key jobs_leased (status, locked_until),
    key jobs_finished (status, finished_at),
    unique key jobs_open_unique ((case when status in ('queued', 'running') then unique_key end))
);

-- +goose Down
drop table jobs;
