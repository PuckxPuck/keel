-- +goose Up
create table audit_chain (
    chain_key varchar(64) character set ascii collate ascii_bin not null primary key check (char_length(chain_key) >= 1),
    last_id char(36) character set ascii collate ascii_bin null,
    hash varbinary(32) null,
    check ((last_id is null) = (hash is null))
);

-- +goose Down
drop table audit_chain;
