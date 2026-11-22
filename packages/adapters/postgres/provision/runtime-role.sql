-- Staging runtime login, loopledger_app_login. Neon makes every role it creates through its API or Terraform (the owner
-- included) a neon_superuser member, so the staging server's DATABASE_URL logs in as this role instead, and only the
-- migrations and the provisioning run as the owner (MIGRATION_DATABASE_URL). Applied by src/runtime-role.ts after the
-- migrations and the BI provisioning, only when LOOPLEDGER_RUNTIME_ROLE is staging, never as a migration, so production
-- never gets the role. Idempotent: every staging boot re-applies it.
-- No password statement: the password is set out of band and kept at op://staging/loopledger-db-app/password.
-- CREATE ROLE may spell the NO- attributes on a CREATEROLE non-superuser connection; ALTER ROLE may not. So an existing
-- role is verified, never re-pinned: a drifted role fails the boot.
DO $role$
DECLARE
  login_role pg_roles%ROWTYPE;
BEGIN
  SELECT * INTO login_role FROM pg_roles WHERE rolname = 'loopledger_app_login';
  IF NOT FOUND THEN
    CREATE ROLE loopledger_app_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
  ELSIF login_role.rolsuper OR login_role.rolcreatedb OR login_role.rolcreaterole
     OR login_role.rolbypassrls OR login_role.rolreplication OR NOT login_role.rolcanlogin THEN
    RAISE EXCEPTION 'role loopledger_app_login exists with unsafe attributes (rolsuper=%, rolcreatedb=%, rolcreaterole=%, rolbypassrls=%, rolreplication=%, rolcanlogin=%)',
      login_role.rolsuper, login_role.rolcreatedb, login_role.rolcreaterole,
      login_role.rolbypassrls, login_role.rolreplication, login_role.rolcanlogin;
  END IF;
  IF EXISTS (SELECT FROM pg_roles g
              WHERE g.rolname IN ('neon_superuser', 'pg_read_all_data', 'pg_write_all_data')
                AND pg_has_role('loopledger_app_login', g.oid, 'MEMBER')) THEN
    RAISE EXCEPTION 'role loopledger_app_login is a member of an elevated group (neon_superuser, pg_read_all_data, pg_write_all_data)';
  END IF;
END
$role$;

-- Converge, then grant exactly what apps/server's routes reach through src/index.ts: appends and reads on the log, its
-- signatures, keys and passports (bigserial ids, so USAGE on their sequences; ON CONFLICT DO NOTHING and RETURNING read
-- columns, covered by SELECT), reads of the migration-seeded parties, and reads of evidence (Ledger.append checks each
-- event's evidence refs are stored). No route stores evidence, and nothing updates or deletes (REQ-PG-004).
REVOKE ALL ON TABLE event, signature, evidence, key, passport, party, schema_migration FROM loopledger_app_login;
REVOKE ALL ON SEQUENCE event_seq_seq, signature_seq_seq, key_seq_seq, passport_seq_seq, party_seq_seq
  FROM loopledger_app_login;
DO $converge$
DECLARE
  rel regclass;
BEGIN
  FOREACH rel IN ARRAY ARRAY[to_regclass('public.bi_product_events'), to_regclass('public.bi_pseudonym_key')] LOOP
    IF rel IS NOT NULL THEN
      EXECUTE format('REVOKE ALL ON TABLE %s FROM loopledger_app_login', rel);
    END IF;
  END LOOP;
END
$converge$;

GRANT USAGE ON SCHEMA public TO loopledger_app_login;
GRANT SELECT, INSERT ON TABLE event, signature, key, passport TO loopledger_app_login;
GRANT SELECT ON TABLE party, evidence TO loopledger_app_login;
GRANT USAGE ON SEQUENCE event_seq_seq, signature_seq_seq, key_seq_seq, passport_seq_seq TO loopledger_app_login;

-- Any privilege beyond the grants above fails the boot: on relations (direct, or to PUBLIC in any user schema),
-- columns (direct, or to PUBLIC in any user schema), functions (PUBLIC EXECUTE on a SECURITY DEFINER function in any
-- user schema included: a NULL proacl is the default ACL, which grants it), schemas (PUBLIC CREATE on any, PUBLIC
-- anything outside public), the database; anything held WITH GRANT OPTION; any role membership; owning a relation,
-- schema, type, function or large object; large-object grants; default privileges for the login or PUBLIC. Objects an
-- extension owns are exempt from the PUBLIC checks only.
-- Not checked: PUBLIC's defaults (CONNECT and TEMP on the database, USAGE on schema public and on types, EXECUTE on
-- functions that are not SECURITY DEFINER, and PUBLIC's built-in EXECUTE and USAGE in a global default-privilege
-- entry for functions or types), and PUBLIC's grants in the system schemas.
DO $check$
DECLARE
  login constant oid := 'loopledger_app_login'::regrole;
  extra text;
BEGIN
  WITH allowed(relname, privilege_type) AS (VALUES
    ('event', 'SELECT'), ('event', 'INSERT'), ('event_seq_seq', 'USAGE'),
    ('signature', 'SELECT'), ('signature', 'INSERT'), ('signature_seq_seq', 'USAGE'),
    ('key', 'SELECT'), ('key', 'INSERT'), ('key_seq_seq', 'USAGE'),
    ('passport', 'SELECT'), ('passport', 'INSERT'), ('passport_seq_seq', 'USAGE'),
    ('party', 'SELECT'),
    ('evidence', 'SELECT')
  ),
  extension_member AS (
    SELECT classid, objid FROM pg_depend WHERE deptype = 'e'
  ),
  user_schema AS (
    SELECT oid, nspname FROM pg_namespace
     WHERE nspname NOT IN ('pg_catalog', 'information_schema')
       AND nspname NOT LIKE 'pg\_toast%' AND nspname NOT LIKE 'pg\_temp%'
  )
  SELECT string_agg(offence, ', ' ORDER BY offence) INTO extra FROM (
    SELECT format('%s%s on %I.%I to %s', a.privilege_type, CASE WHEN a.is_grantable THEN ' (grantable)' ELSE '' END,
                  n.nspname, c.relname, CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END) AS offence
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      CROSS JOIN LATERAL aclexplode(c.relacl) a
     WHERE (a.grantee = login
            OR (a.grantee = 0 AND c.relnamespace IN (SELECT oid FROM user_schema)
                AND NOT EXISTS (SELECT FROM extension_member e WHERE e.classid = 'pg_class'::regclass AND e.objid = c.oid)))
       AND NOT (a.grantee = login AND NOT a.is_grantable AND n.nspname = 'public'
                AND (c.relname::text, a.privilege_type) IN (SELECT relname, privilege_type FROM allowed))
    UNION ALL
    SELECT format('%s%s on column %I.%I(%I) to %s', a.privilege_type, CASE WHEN a.is_grantable THEN ' (grantable)' ELSE '' END,
                  n.nspname, c.relname, att.attname, CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END)
      FROM pg_attribute att
      JOIN pg_class c ON c.oid = att.attrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
      CROSS JOIN LATERAL aclexplode(att.attacl) a
     WHERE a.grantee = login
        OR (a.grantee = 0 AND c.relnamespace IN (SELECT oid FROM user_schema)
            AND NOT EXISTS (SELECT FROM extension_member e WHERE e.classid = 'pg_class'::regclass AND e.objid = c.oid))
    UNION ALL
    SELECT format('EXECUTE%s on function %s to %s', CASE WHEN a.is_grantable THEN ' (grantable)' ELSE '' END,
                  p.oid::regprocedure, CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END)
      FROM pg_proc p
      CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
     WHERE a.grantee = login
        OR (a.grantee = 0 AND p.prosecdef AND p.pronamespace IN (SELECT oid FROM user_schema)
            AND NOT EXISTS (SELECT FROM extension_member e WHERE e.classid = 'pg_proc'::regclass AND e.objid = p.oid))
    UNION ALL
    SELECT format('%s%s on schema %I to %s', a.privilege_type, CASE WHEN a.is_grantable THEN ' (grantable)' ELSE '' END,
                  n.nspname, CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END)
      FROM pg_namespace n
      CROSS JOIN LATERAL aclexplode(n.nspacl) a
     WHERE (a.grantee = login
            OR (a.grantee = 0 AND (a.privilege_type = 'CREATE'
                                   OR (n.nspname <> 'public' AND n.oid IN (SELECT oid FROM user_schema)
                                       AND NOT EXISTS (SELECT FROM extension_member e
                                                        WHERE e.classid = 'pg_namespace'::regclass AND e.objid = n.oid)))))
       AND NOT (a.grantee = login AND NOT a.is_grantable AND n.nspname = 'public' AND a.privilege_type = 'USAGE')
    UNION ALL
    SELECT format('%s on database %I to %s', a.privilege_type, d.datname, a.grantee::regrole::text)
      FROM pg_database d
      CROSS JOIN LATERAL aclexplode(d.datacl) a
     WHERE a.grantee = login
    UNION ALL
    SELECT format('loopledger_app_login is a member of %s%s', m.roleid::regrole::text,
                  CASE WHEN m.admin_option THEN ' (admin)' ELSE '' END)
      FROM pg_auth_members m
     WHERE m.member = login
    UNION ALL
    SELECT format('owns relation %I.%I', n.nspname, c.relname)
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE pg_has_role(login, c.relowner, 'MEMBER')
    UNION ALL
    SELECT format('owns schema %I', n.nspname)
      FROM pg_namespace n
     WHERE pg_has_role(login, n.nspowner, 'MEMBER')
    UNION ALL
    SELECT format('owns type %s', t.oid::regtype)
      FROM pg_type t
     WHERE pg_has_role(login, t.typowner, 'MEMBER')
    UNION ALL
    SELECT format('owns function %s', p.oid::regprocedure)
      FROM pg_proc p
     WHERE pg_has_role(login, p.proowner, 'MEMBER')
    UNION ALL
    SELECT format('owns large object %s', l.oid)
      FROM pg_largeobject_metadata l
     WHERE pg_has_role(login, l.lomowner, 'MEMBER')
    UNION ALL
    SELECT format('%s on large object %s to %s', a.privilege_type, l.oid,
                  CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END)
      FROM pg_largeobject_metadata l
      CROSS JOIN LATERAL aclexplode(l.lomacl) a
     WHERE a.grantee IN (login, 0)
    UNION ALL
    SELECT format('default %s on %s%s for %s to %s', a.privilege_type,
                  CASE d.defaclobjtype WHEN 'r' THEN 'tables' WHEN 'S' THEN 'sequences' WHEN 'f' THEN 'functions'
                       WHEN 'T' THEN 'types' WHEN 'n' THEN 'schemas' ELSE d.defaclobjtype::text END,
                  CASE WHEN d.defaclnamespace = 0 THEN '' ELSE format(' in schema %I', d.defaclnamespace::regnamespace) END,
                  d.defaclrole::regrole::text, CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END)
      FROM pg_default_acl d
      CROSS JOIN LATERAL aclexplode(d.defaclacl) a
     WHERE a.grantee IN (login, 0)
       -- A global entry (no IN SCHEMA) stores the whole ACL, PUBLIC's built-in EXECUTE on functions and USAGE on
       -- types included; only a PUBLIC privilege beyond that default is an offence there.
       AND NOT (a.grantee = 0 AND d.defaclnamespace = 0 AND d.defaclobjtype IN ('f', 'T')
                AND (a.privilege_type, a.is_grantable) IN (
                      SELECT x.privilege_type, x.is_grantable
                        FROM aclexplode(acldefault(d.defaclobjtype, d.defaclrole)) x
                       WHERE x.grantee = 0))
  ) offences;
  IF extra IS NOT NULL THEN
    RAISE EXCEPTION 'role loopledger_app_login holds privileges beyond its runtime grants: %', extra;
  END IF;
END
$check$;
