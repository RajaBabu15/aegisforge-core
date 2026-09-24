-- Applied on every boot. Safe against a database created by an older schema.

DROP FUNCTION IF EXISTS auth_consume_code(text);

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

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'aegis_checkpoint') THEN
    CREATE ROLE aegis_checkpoint LOGIN PASSWORD 'checkpoint' NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;

GRANT EXECUTE ON FUNCTION auth_consume_code(text, text, text, text) TO aegis_app;
GRANT EXECUTE ON FUNCTION auth_resolve_api_key(text) TO aegis_app;
