-- +goose Up
create table connections (
    id char(36) character set ascii collate ascii_bin not null primary key,
    provider varchar(64) character set ascii collate ascii_bin not null check (char_length(provider) >= 1),
    external_account_id varchar(255) collate utf8mb4_bin not null check (char_length(external_account_id) >= 1),
    scopes varchar(2000) not null default '',
    status varchar(32) not null check (status in ('active', 'needs_reauth', 'disconnecting')),
    access_token varbinary(8192) not null,
    refresh_token varbinary(8192) null,
    token_type varchar(32) not null default '',
    expires_at datetime(6) null,
    created_by char(36) character set ascii collate ascii_bin null,
    created_at datetime(6) not null,
    updated_at datetime(6) not null,
    version int not null default 1,
    refresh_owner varchar(64) character set ascii collate ascii_bin null,
    refreshing_until datetime(6) null,
    unique key connections_provider_account (provider, external_account_id),
    key connections_created_by (created_by),
    constraint connections_created_by_fk foreign key (created_by) references users (id)
);

-- +goose Down
drop table connections;
