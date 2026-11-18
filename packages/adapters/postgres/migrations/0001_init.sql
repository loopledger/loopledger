-- The hosted pilot ledger's schema (issue #78, 01-passport-custody technical spec, "Postgres").
-- Every table is append-only for the application: the grants at the end give the app role SELECT and
-- INSERT and never UPDATE or DELETE (SPEC-data-model §5). `row`/`doc`/`record` hold the port objects
-- as jsonb; `seq` fixes the append order that readAll() and signatures() return.
create table event (
  seq        bigserial primary key,
  event_id   text not null unique,
  tenant_id  text not null,
  event_type text not null,
  row        jsonb not null
);

create table signature (
  seq      bigserial primary key,
  sig_id   text not null unique,
  event_id text not null references event (event_id),
  row      jsonb not null
);

create table evidence (
  hash  text primary key,
  bytes bytea not null
);

create table key (
  seq      bigserial primary key,
  key_id   text not null unique,
  party_id text not null,
  record   jsonb not null
);

create table passport (
  seq       bigserial primary key,
  asset_id  text not null unique,
  tenant_id text not null,
  doc       jsonb not null
);

create table party (
  seq       bigserial primary key,
  party_id  text not null unique,
  tenant_id text not null,
  name      text not null
);

-- The two seeded pilot parties (01-passport-custody, decided items; migration-seeded, keys are not:
-- devices register their own). The seeded site is site-northside-01 and travels on each passport's
-- origin.site_id; the spec's table list has no site table.
insert into party (party_id, tenant_id, name) values
  ('pty_01JDPC0000000000000000SND1', 'pilot-northside', 'Northside Fit-out'),
  ('pty_01JDPC0000000000000000RCV1', 'pilot-northside', 'Lakeside Recovery');

-- Append-only hardening (SPEC-data-model §5). The application role is created without LOGIN; the
-- deployment grants it login out of band if the service connects as it. Migrating as the owner works
-- either way, and the membership grant below lets a verifier session `set role loopledger_app` and
-- prove the refusal for real.
do $$ begin
  if not exists (select from pg_roles where rolname = 'loopledger_app') then
    create role loopledger_app nologin;
  end if;
end $$;

grant usage on schema public to loopledger_app;
grant select, insert on event, signature, evidence, key, passport, party to loopledger_app;
grant usage, select on all sequences in schema public to loopledger_app;
revoke update, delete, truncate on event, signature, evidence, key, passport, party from loopledger_app;
revoke update, delete, truncate on event, signature, evidence, key, passport, party from public;
grant loopledger_app to current_user;
