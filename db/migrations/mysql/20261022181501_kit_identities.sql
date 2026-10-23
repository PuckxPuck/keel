-- +goose Up
create table identities (
    id char(36) character set ascii collate ascii_bin not null primary key,
    user_id char(36) character set ascii collate ascii_bin not null,
    realm varchar(64) character set ascii collate ascii_bin not null check (char_length(realm) >= 1),
    provider varchar(255) character set ascii collate ascii_bin not null check (char_length(provider) >= 1),
    subject varchar(255) character set ascii collate ascii_bin not null check (char_length(subject) >= 1),
    email_at_link varchar(254) null,
    created_at datetime(6) not null,
    unique key identities_realm_provider_subject_key (realm, provider, subject),
    key identities_user_id_provider (user_id, provider),
    constraint identities_user_fk foreign key (user_id) references users (id) on delete cascade
);

-- +goose Down
drop table identities;
