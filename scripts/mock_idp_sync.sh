#!/bin/sh
# Deactivate a user through the SCIM-lite route.
# Requires AEGIS_SCIM_TOKEN, AEGIS_USER_ID, and optional AEGIS_BASE_URL.
set -eu
BASE="${AEGIS_BASE_URL:-http://localhost:8000}"
curl -sS -X PUT "$BASE/scim/v2/Users/${AEGIS_USER_ID}" \
  -H "Authorization: Bearer ${AEGIS_SCIM_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"userName\":\"${AEGIS_USER_EMAIL:-dev@demo.aegisforge.local}\",\"active\":false}"
echo
