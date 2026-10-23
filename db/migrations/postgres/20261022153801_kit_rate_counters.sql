-- keel:global counters keyed by caller; ratelimit.ByTenant puts the tenant in the key
-- +goose Up
create table rate_counters (
    bucket text not null check (char_length(bucket) between 1 and 191),
    window_start timestamptz not null,
    hits bigint not null check (hits >= 0),
    expires_at timestamptz not null,
    primary key (bucket, window_start)
);
create index rate_counters_expires_at on rate_counters (expires_at);

-- +goose Down
drop table rate_counters;
