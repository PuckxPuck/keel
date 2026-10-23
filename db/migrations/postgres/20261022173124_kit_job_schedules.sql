-- keel:global schedules of global maintenance kinds
-- +goose Up
create table job_schedules (
    name text primary key check (char_length(name) between 1 and 128),
    kind text not null check (char_length(kind) between 1 and 128),
    spec text not null check (char_length(spec) between 1 and 128),
    location text not null check (char_length(location) between 1 and 64),
    next_run_at timestamptz not null,
    last_run_at timestamptz,
    last_job_id uuid,
    created_at timestamptz not null,
    updated_at timestamptz not null
);

-- +goose Down
drop table job_schedules;
