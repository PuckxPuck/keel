-- +goose Up
create table rate_counters (
    bucket varchar(191) not null check (char_length(bucket) >= 1),
    window_start datetime(6) not null,
    hits bigint not null check (hits >= 0),
    expires_at datetime(6) not null,
    primary key (bucket, window_start),
    key rate_counters_expires_at (expires_at)
);

-- +goose Down
drop table rate_counters;
