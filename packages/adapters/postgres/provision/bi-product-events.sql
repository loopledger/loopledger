-- The shared product-events read contract (factory-ops docs/product-events.md): one view, bi_product_events, read
-- by loopledger_bi_login for the factory's daily counts. Only aggregates leave the database. Applied by
-- src/provision-bi.ts on a staging deployment only, never as a migration, so production never gets the view or roles.
-- __ENV__ is the deployment's environment label, substituted and validated by provision-bi.ts.
-- Idempotent: every boot re-applies it.
-- The subject is a keyed hash of tenant_id, so for loopledger `subjects` is a tenant_count. The key is generated here
-- and readable only by the owner; the view runs with the owner's rights, so the BI role needs SELECT on the view alone.
create table if not exists bi_pseudonym_key (
  id  boolean primary key default true check (id),
  key bytea   not null check (length(key) >= 30)
);
revoke all on bi_pseudonym_key from public;
insert into bi_pseudonym_key (key)
  values (decode(replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''), 'hex'))
  on conflict (id) do nothing;

-- recorded_at is ledger time (business time can be backdated). NULL unless it is an ISO-8601 UTC or offset
-- timestamp that Postgres accepts, so one malformed row cannot break the view.
create or replace function bi_iso_timestamp(value text) returns timestamptz
language plpgsql immutable set search_path = pg_catalog
as $fn$
begin
  if value !~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$' then
    return null;
  end if;
  return value::timestamptz;
exception when others then
  return null;
end
$fn$;
-- EXECUTE is PUBLIC's: a view runs its functions with the reader's rights, and this one only parses text. Granted
-- explicitly because CREATE OR REPLACE keeps an earlier ACL.
grant execute on function bi_iso_timestamp(text) to public;

create or replace view bi_product_events as
  select e.event_type                                                      as kind,
         bi_iso_timestamp(e.row ->> 'recorded_at')                         as occurred_at,
         e.event_id                                                        as dedupe_key,
         encode(sha256(k.key || convert_to(e.tenant_id, 'UTF8')), 'hex')  as subject,
         true                                                              as test_account,
         '{}'::text[]                                                      as settings_on,
         '__ENV__'::text                                                   as env,
         '{}'::jsonb                                                       as payload
    from event e cross join bi_pseudonym_key k;

-- The login is created without a password; it is set out of band into the staging vault (loopledger-bi).
-- The membership grant lets a verifier session `set role loopledger_bi`, as for loopledger_app.
do $$ begin
  if not exists (select from pg_roles where rolname = 'loopledger_bi') then
    create role loopledger_bi nologin;
  end if;
  if not exists (select from pg_roles where rolname = 'loopledger_bi_login') then
    create role loopledger_bi_login login in role loopledger_bi;
  end if;
end $$;

grant usage on schema public to loopledger_bi;
grant select on bi_product_events to loopledger_bi;
grant loopledger_bi to current_user;

-- Anything either role holds beyond SELECT on the view, or the login's membership in the BI role, fails the boot.
do $$
declare
  bi constant regrole := 'loopledger_bi'::regrole;
  bi_login constant regrole := 'loopledger_bi_login'::regrole;
  extra text;
begin
  select string_agg(item, ', ' order by item) into extra from (
    select format('%s on %I.%I to %s', a.privilege_type, n.nspname, c.relname, a.grantee::regrole) as item
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
      cross join lateral aclexplode(c.relacl) a
     where a.grantee in (bi, bi_login)
       and not (n.nspname = 'public' and c.relname = 'bi_product_events' and a.privilege_type = 'SELECT' and a.grantee = bi)
    union all
    select format('%s on %I.%I(%I) to %s', a.privilege_type, n.nspname, c.relname, att.attname, a.grantee::regrole)
      from pg_attribute att
      join pg_class c on c.oid = att.attrelid
      join pg_namespace n on n.oid = c.relnamespace
      cross join lateral aclexplode(att.attacl) a
     where a.grantee in (bi, bi_login)
    union all
    select format('%s on function %s to %s', a.privilege_type, p.oid::regprocedure, a.grantee::regrole)
      from pg_proc p
      cross join lateral aclexplode(p.proacl) a
     where a.grantee in (bi, bi_login)
    union all
    select format('%s is a member of %s', m.member::regrole, m.roleid::regrole)
      from pg_auth_members m
     where m.member in (bi, bi_login)
       and not (m.member = bi_login and m.roleid = bi)
  ) x;
  if extra is not null then
    raise exception 'BI roles hold grants beyond bi_product_events: %', extra;
  end if;
end $$;
