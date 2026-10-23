-- +goose Up
alter table webhook_endpoints add column previous_secret bytea, add column previous_secret_until timestamptz;

-- +goose Down
alter table webhook_endpoints drop column previous_secret, drop column previous_secret_until;
