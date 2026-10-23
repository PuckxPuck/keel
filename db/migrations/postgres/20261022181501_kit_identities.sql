-- keel:global per user, bound to the realm they were linked on
-- +goose Up
create table identities (
    id uuid primary key,
    user_id uuid not null references users (id) on delete cascade,
    realm text not null check (char_length(realm) between 1 and 64),
    provider text not null check (char_length(provider) between 1 and 255),
    subject text not null check (char_length(subject) between 1 and 255),
    email_at_link text check (char_length(email_at_link) <= 254),
    created_at timestamptz not null
);
create unique index identities_realm_provider_subject_key on identities (realm, provider, subject);
create index identities_user_id_provider on identities (user_id, provider);

-- +goose Down
drop table identities;
