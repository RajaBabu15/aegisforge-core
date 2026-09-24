-- Applied once by the migrator as a superuser. aegis_app is the API login.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'aegis_migrator') THEN
    CREATE ROLE aegis_migrator LOGIN PASSWORD 'migrator' SUPERUSER;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'aegis_app') THEN
    CREATE ROLE aegis_app LOGIN PASSWORD 'app' NOSUPERUSER NOBYPASSRLS NOCREATEDB;
  END IF;
  -- Dedicated, narrowly-scoped role for the one agent tool that mutates data
  -- (execute_sql_write). It gets its own connection, its own statement timeout, and
  -- privileges on exactly one table -- never the app's full aegis_app grant set.
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'aegis_tool_sql') THEN
    CREATE ROLE aegis_tool_sql LOGIN PASSWORD 'tool' NOSUPERUSER NOBYPASSRLS NOCREATEDB;
    ALTER ROLE aegis_tool_sql SET statement_timeout = '5s';
  END IF;
END $$;

DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS pgcrypto;
EXCEPTION
  WHEN OTHERS THEN
    NULL;
END $$;

GRANT USAGE ON SCHEMA public TO aegis_app;
GRANT CREATE ON SCHEMA public TO aegis_migrator;

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    domain_lock VARCHAR(100) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255),
    system_role VARCHAR(50) NOT NULL
        CHECK (system_role IN ('org_admin', 'workspace_developer', 'viewer')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    groups JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_tenant_email UNIQUE (tenant_id, email)
);

CREATE TABLE application_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    key_hash CHAR(64) NOT NULL UNIQUE,
    key_prefix VARCHAR(16) NOT NULL,
    allowed_scopes VARCHAR(50)[] NOT NULL,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE refresh_token_families (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    revoked_at TIMESTAMPTZ,
    revoke_reason VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    family_id UUID NOT NULL REFERENCES refresh_token_families (id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash CHAR(64) NOT NULL UNIQUE,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    scopes VARCHAR(50)[] NOT NULL,
    used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (family_id, generation)
);

CREATE TABLE authorization_codes (
    code_hash CHAR(64) PRIMARY KEY,
    client_id VARCHAR(64) NOT NULL,
    tenant_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method VARCHAR(10) NOT NULL,
    scopes VARCHAR(50)[] NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE TABLE oauth_clients (
    client_id VARCHAR(64) PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    redirect_uris TEXT[] NOT NULL,
    is_public BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE scim_tokens (
    token_hash CHAR(64) PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE system_audit_ledger (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    tenant_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id UUID REFERENCES users (id) ON DELETE SET NULL,
    auth_scope_used VARCHAR(50)[],
    action_type VARCHAR(100) NOT NULL,
    resource_identifier VARCHAR(255) NOT NULL,
    execution_decision VARCHAR(20) NOT NULL
        CHECK (execution_decision IN ('ALLOW', 'DENY', 'REVOKED')),
    rejection_reason_code VARCHAR(100),
    client_ip_network INET
);

CREATE TABLE agent_workflow_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    trace_id VARCHAR(128) NOT NULL,
    workflow_definition_version VARCHAR(50) NOT NULL,
    current_phase VARCHAR(50) NOT NULL
        CHECK (current_phase IN (
            'START', 'PLAN', 'EXECUTE', 'VERIFY', 'SUSPEND',
            'RESPOND', 'CRITICAL_SECURITY_DENIAL', 'CANCELLED'
        )),
    execution_payload_state JSONB NOT NULL,
    is_suspended_for_approval BOOLEAN NOT NULL DEFAULT FALSE,
    accumulated_token_cost NUMERIC(12, 6) NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Everything the sandboxed execute_sql_write tool is allowed to write. aegis_tool_sql
-- has INSERT/SELECT on this table only -- it has no grants at all on any other table.
CREATE TABLE agent_tool_writes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    tool_name VARCHAR(100) NOT NULL,
    statement TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,
    sha256 CHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id, sha256)
);

CREATE TABLE document_chunks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    document_id UUID NOT NULL REFERENCES documents (id) ON DELETE CASCADE,
    page INTEGER NOT NULL CHECK (page >= 1),
    line_start INTEGER NOT NULL CHECK (line_start >= 1),
    line_end INTEGER NOT NULL CHECK (line_end >= line_start),
    sha256 CHAR(64) NOT NULL,
    content TEXT NOT NULL,
    qdrant_point_id UUID NOT NULL UNIQUE
);

CREATE INDEX idx_audit_tenant_timestamp
    ON system_audit_ledger (tenant_id, timestamp DESC);
CREATE INDEX idx_workflow_tenant_status
    ON agent_workflow_state (tenant_id, current_phase);
CREATE INDEX idx_workflow_trace
    ON agent_workflow_state (trace_id);
CREATE INDEX idx_refresh_family
    ON refresh_tokens (family_id);

-- Credential lookups happen before the tenant GUC is known. These functions
-- run as the table owner (superuser migrator) and are the only cross-tenant reads.

CREATE OR REPLACE FUNCTION auth_find_user_by_email(p_email text)
RETURNS TABLE (
    id uuid,
    tenant_id uuid,
    password_hash varchar,
    is_active boolean,
    system_role varchar
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT u.id, u.tenant_id, u.password_hash, u.is_active, u.system_role
    FROM users u
    WHERE lower(u.email) = lower(p_email);
$$;

CREATE OR REPLACE FUNCTION auth_save_code(
    p_code_hash text,
    p_client_id text,
    p_tenant_id uuid,
    p_user_id uuid,
    p_redirect_uri text,
    p_code_challenge text,
    p_method text,
    p_scopes text[],
    p_expires timestamptz
) RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    INSERT INTO authorization_codes (
        code_hash, client_id, tenant_id, user_id, redirect_uri,
        code_challenge, code_challenge_method, scopes, expires_at
    ) VALUES (
        p_code_hash, p_client_id, p_tenant_id, p_user_id, p_redirect_uri,
        p_code_challenge, p_method, p_scopes, p_expires
    );
$$;

CREATE OR REPLACE FUNCTION auth_consume_code(
    p_code_hash text,
    p_client_id text,
    p_redirect text,
    p_challenge text
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    row authorization_codes%ROWTYPE;
BEGIN
    SELECT * INTO row FROM authorization_codes WHERE code_hash = p_code_hash FOR UPDATE;
    IF NOT FOUND OR row.used_at IS NOT NULL OR row.expires_at <= now() THEN
        RETURN jsonb_build_object('status', 'invalid');
    END IF;
    IF row.client_id <> p_client_id
       OR row.redirect_uri <> p_redirect
       OR row.code_challenge_method <> 'S256'
       OR row.code_challenge <> p_challenge THEN
        RETURN jsonb_build_object('status', 'invalid');
    END IF;
    UPDATE authorization_codes SET used_at = now() WHERE code_hash = p_code_hash;
    RETURN jsonb_build_object(
        'status', 'ok',
        'client_id', row.client_id,
        'tenant_id', row.tenant_id,
        'user_id', row.user_id,
        'redirect_uri', row.redirect_uri,
        'code_challenge', row.code_challenge,
        'code_challenge_method', row.code_challenge_method,
        'scopes', to_jsonb(row.scopes)
    );
END;
$$;

CREATE OR REPLACE FUNCTION auth_issue_family(
    p_tenant_id uuid,
    p_user_id uuid,
    p_token_hash text,
    p_expires timestamptz,
    p_scopes text[]
) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    fam uuid;
BEGIN
    INSERT INTO refresh_token_families (tenant_id, user_id)
    VALUES (p_tenant_id, p_user_id)
    RETURNING id INTO fam;
    INSERT INTO refresh_tokens (
        family_id, tenant_id, user_id, token_hash, generation, scopes, expires_at
    ) VALUES (
        fam, p_tenant_id, p_user_id, p_token_hash, 0, p_scopes, p_expires
    );
    RETURN fam;
END;
$$;

CREATE OR REPLACE FUNCTION auth_present_refresh(
    p_presented_hash text,
    p_new_hash text,
    p_new_expires timestamptz,
    p_client_ip inet
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    tok refresh_tokens%ROWTYPE;
    fam refresh_token_families%ROWTYPE;
BEGIN
    SELECT * INTO tok FROM refresh_tokens WHERE token_hash = p_presented_hash FOR UPDATE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('status', 'invalid');
    END IF;
    SELECT * INTO fam FROM refresh_token_families WHERE id = tok.family_id FOR UPDATE;
    IF tok.expires_at <= now() AND tok.used_at IS NULL AND fam.revoked_at IS NULL THEN
        RETURN jsonb_build_object('status', 'invalid');
    END IF;
    IF fam.revoked_at IS NOT NULL OR tok.used_at IS NOT NULL THEN
        UPDATE refresh_token_families
           SET revoked_at = COALESCE(revoked_at, now()),
               revoke_reason = COALESCE(revoke_reason, 'REFRESH_TOKEN_REUSE_DETECTED')
         WHERE id = fam.id;
        UPDATE refresh_tokens
           SET used_at = COALESCE(used_at, now())
         WHERE family_id = fam.id;
        INSERT INTO system_audit_ledger (
            tenant_id, user_id, auth_scope_used, action_type, resource_identifier,
            execution_decision, rejection_reason_code, client_ip_network
        ) VALUES (
            tok.tenant_id, tok.user_id, tok.scopes, 'refresh_token', fam.id::text,
            'DENY', 'REFRESH_TOKEN_REUSE_DETECTED', p_client_ip
        );
        RETURN jsonb_build_object(
            'status', 'replay',
            'family_id', fam.id,
            'user_id', tok.user_id,
            'tenant_id', tok.tenant_id
        );
    END IF;
    UPDATE refresh_tokens SET used_at = now() WHERE id = tok.id;
    INSERT INTO refresh_tokens (
        family_id, tenant_id, user_id, token_hash, generation, scopes, expires_at
    ) VALUES (
        tok.family_id, tok.tenant_id, tok.user_id, p_new_hash,
        tok.generation + 1, tok.scopes, p_new_expires
    );
    RETURN jsonb_build_object(
        'status', 'ok',
        'family_id', fam.id,
        'user_id', tok.user_id,
        'tenant_id', tok.tenant_id,
        'scopes', to_jsonb(tok.scopes),
        'generation', tok.generation + 1
    );
END;
$$;

CREATE OR REPLACE FUNCTION auth_revoke_user(
    p_user_id uuid,
    p_reason text,
    p_client_ip inet
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    fam_ids uuid[];
    tid uuid;
    sc text[];
BEGIN
    SELECT tenant_id INTO tid FROM users WHERE id = p_user_id;
    IF tid IS NULL THEN
        RETURN jsonb_build_object('status', 'missing');
    END IF;
    SELECT array_agg(id) INTO fam_ids
      FROM refresh_token_families
     WHERE user_id = p_user_id AND revoked_at IS NULL;
    UPDATE refresh_token_families
       SET revoked_at = now(), revoke_reason = p_reason
     WHERE user_id = p_user_id AND revoked_at IS NULL;
    UPDATE refresh_tokens
       SET used_at = COALESCE(used_at, now())
     WHERE user_id = p_user_id;
    UPDATE users SET is_active = false WHERE id = p_user_id AND p_reason = 'SCIM_DEACTIVATED';
    UPDATE agent_workflow_state
       SET current_phase = 'CANCELLED',
           is_suspended_for_approval = false,
           updated_at = now()
     WHERE user_id = p_user_id
       AND current_phase NOT IN ('RESPOND', 'CRITICAL_SECURITY_DENIAL', 'CANCELLED');
    sc := ARRAY[p_reason];
    IF fam_ids IS NOT NULL THEN
        INSERT INTO system_audit_ledger (
            tenant_id, user_id, auth_scope_used, action_type, resource_identifier,
            execution_decision, rejection_reason_code, client_ip_network
        )
        SELECT tid, p_user_id, sc, 'user_revoke', id::text, 'REVOKED', p_reason, p_client_ip
          FROM unnest(fam_ids) AS id;
    END IF;
    RETURN jsonb_build_object(
        'status', 'ok',
        'tenant_id', tid,
        'family_ids', COALESCE(to_jsonb(fam_ids), '[]'::jsonb)
    );
END;
$$;

CREATE OR REPLACE FUNCTION auth_resolve_scim(p_hash text)
RETURNS uuid
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT tenant_id FROM scim_tokens WHERE token_hash = p_hash;
$$;

CREATE OR REPLACE FUNCTION auth_resolve_api_key(p_hash text)
RETURNS TABLE (
    id uuid,
    tenant_id uuid,
    user_id uuid,
    allowed_scopes varchar[],
    expires_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT k.id, k.tenant_id, k.user_id, k.allowed_scopes, k.expires_at
    FROM application_keys k
    JOIN users u ON u.id = k.user_id AND u.is_active
    WHERE k.key_hash = p_hash
      AND (k.expires_at IS NULL OR k.expires_at > now());
$$;

CREATE OR REPLACE FUNCTION auth_client_redirect_ok(p_client_id text, p_redirect text)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT EXISTS (
        SELECT 1 FROM oauth_clients
        WHERE client_id = p_client_id AND p_redirect = ANY (redirect_uris)
    );
$$;

DO $$
DECLARE
    tbl text;
BEGIN
    FOREACH tbl IN ARRAY ARRAY[
        'users', 'application_keys', 'refresh_token_families', 'refresh_tokens',
        'system_audit_ledger', 'agent_workflow_state', 'documents', 'document_chunks',
        'authorization_codes', 'oauth_clients', 'scim_tokens', 'agent_tool_writes'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tbl);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation_policy ON %I', tbl);
        EXECUTE format(
            'CREATE POLICY tenant_isolation_policy ON %I FOR ALL '
            'USING (tenant_id = NULLIF(current_setting(''app.current_tenant_id'', true), '''')::uuid) '
            'WITH CHECK (tenant_id = NULLIF(current_setting(''app.current_tenant_id'', true), '''')::uuid)',
            tbl
        );
    END LOOP;
END $$;

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS org_self_policy ON organizations;
CREATE POLICY org_self_policy ON organizations
    FOR ALL
    USING (id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON
    organizations, users, application_keys, refresh_token_families, refresh_tokens,
    agent_workflow_state, documents, document_chunks, agent_tool_writes
TO aegis_app;

-- aegis_tool_sql gets exactly this and nothing else -- no access to users,
-- refresh_tokens, system_audit_ledger, or any other table.
GRANT USAGE ON SCHEMA public TO aegis_tool_sql;
GRANT SELECT, INSERT ON agent_tool_writes TO aegis_tool_sql;

GRANT SELECT, INSERT ON system_audit_ledger TO aegis_app;
REVOKE UPDATE, DELETE ON system_audit_ledger FROM aegis_app;
GRANT USAGE, SELECT ON SEQUENCE system_audit_ledger_id_seq TO aegis_app;

-- NOTE on ledger immutability: schema.sql is applied via MIGRATOR_DATABASE_URL, which in
-- every environment here (docker/local.env, CI, the pgserver test fixture) authenticates as
-- the platform's actual Postgres superuser, not as the aegis_migrator role below -- and
-- aegis_migrator is itself created SUPERUSER too. REVOKE is a no-op against a superuser:
-- verified empirically (REVOKE UPDATE/DELETE FROM a superuser role, then UPDATE/DELETE as
-- that role, both still succeed -- Postgres skips ACL checks entirely for superusers), so
-- there is deliberately no REVOKE-from-migrator statement here pretending to restrict it.
-- Real audit-ledger tamper-proofing against the deploy-time credential would require that
-- credential to not be a superuser at all (a separate bootstrap-vs-steady-state credential
-- split) -- a larger, deliberately deferred change.

GRANT EXECUTE ON FUNCTION
    auth_find_user_by_email(text),
    auth_save_code(text, text, uuid, uuid, text, text, text, text[], timestamptz),
    auth_consume_code(text, text, text, text),
    auth_issue_family(uuid, uuid, text, timestamptz, text[]),
    auth_present_refresh(text, text, timestamptz, inet),
    auth_revoke_user(uuid, text, inet),
    auth_resolve_scim(text),
    auth_resolve_api_key(text),
    auth_client_redirect_ok(text, text)
TO aegis_app;
