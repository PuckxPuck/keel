-- +goose Up
create table job_schedules (
    name varchar(128) character set ascii collate ascii_bin not null primary key check (char_length(name) >= 1),
    kind varchar(128) character set ascii collate ascii_bin not null check (char_length(kind) >= 1),
    spec varchar(128) character set ascii collate ascii_bin not null check (char_length(spec) >= 1),
    location varchar(64) character set ascii collate ascii_bin not null check (char_length(location) >= 1),
    next_run_at datetime(6) not null,
    last_run_at datetime(6) null,
    last_job_id char(36) character set ascii collate ascii_bin null,
    created_at datetime(6) not null,
    updated_at datetime(6) not null
);

-- +goose Down
drop table job_schedules;
