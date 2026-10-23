-- +goose Up
alter table job_schedules add column build varchar(64) character set ascii collate ascii_bin null;

-- +goose Down
alter table job_schedules drop column build;
