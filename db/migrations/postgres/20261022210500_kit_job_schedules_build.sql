-- +goose Up
alter table job_schedules add column build text check (char_length(build) <= 64);

-- +goose Down
alter table job_schedules drop column build;
