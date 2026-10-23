-- +goose Up
alter table webhook_endpoints add column previous_secret varbinary(255) null, add column previous_secret_until datetime(6) null;

-- +goose Down
alter table webhook_endpoints drop column previous_secret, drop column previous_secret_until;
