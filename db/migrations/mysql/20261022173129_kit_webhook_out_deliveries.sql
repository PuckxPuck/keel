-- +goose Up
create table webhook_out_deliveries (
    id char(36) character set ascii collate ascii_bin not null primary key,
    event_id char(36) character set ascii collate ascii_bin not null,
    endpoint_id char(36) character set ascii collate ascii_bin not null,
    status varchar(32) not null check (status in ('pending', 'succeeded', 'failed', 'skipped')),
    attempts int not null default 0 check (attempts >= 0),
    generation int not null default 0,
    last_status_code int null,
    last_error_code varchar(64) null,
    last_error varchar(1000) null,
    created_at datetime(6) not null,
    updated_at datetime(6) not null,
    delivered_at datetime(6) null,
    key webhook_out_deliveries_event (event_id),
    key webhook_out_deliveries_endpoint (endpoint_id, created_at),
    constraint webhook_out_deliveries_event_fk foreign key (event_id) references webhook_events (id) on delete cascade,
    constraint webhook_out_deliveries_endpoint_fk foreign key (endpoint_id) references webhook_endpoints (id) on delete cascade
);

-- +goose Down
drop table webhook_out_deliveries;
