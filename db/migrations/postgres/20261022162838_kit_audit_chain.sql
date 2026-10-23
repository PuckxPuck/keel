-- One head per chain ("global" now, one per tenant with tenancy); recording locks it, so the chain cannot fork.
-- +goose Up
create table audit_chain (
    chain_key text primary key check (char_length(chain_key) between 1 and 64),
    last_id uuid,
    hash bytea,
    check ((last_id is null) = (hash is null))
);

-- +goose Down
drop table audit_chain;
