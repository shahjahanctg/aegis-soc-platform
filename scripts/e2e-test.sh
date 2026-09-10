#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# AegisSOC end-to-end API test suite.
# Requires a running stack:  docker compose up -d --build
# Usage: BASE_URL=http://localhost INGEST_API_KEY=... ./scripts/e2e-test.sh
# Exits non-zero on any failed check.
# ---------------------------------------------------------------------------
set -u

BASE_URL="${BASE_URL:-http://localhost}"
INGEST_KEY="${INGEST_KEY:-${INGEST_API_KEY:-}}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0

say()  { echo -e "$@"; }
ok()   { PASS=$((PASS + 1)); say "  \e[32m✔\e[0m $1"; }
bad()  { FAIL=$((FAIL + 1)); say "  \e[31m✘\e[0m $1"; }

# extract <file> <node-expression>  -> value of expression, or __ERR__ on failure
extract() {
  node -e '
    const j = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    try { console.log(eval(process.argv[2])); } catch { console.log("__ERR__"); }
  ' "$1" "$2" 2>/dev/null || echo "__ERR__"
}

http() { # method path [body-file] [token] -> writes body to $TMP/body, echoes status
  local method="$1" path="$2" body="${3:-}" token="${4:-}"
  local args=(-s -o "$TMP/body" -w "%{http_code}" -X "$method" "$BASE_URL$path")
  [ -n "$token" ] && args+=(-H "Authorization: Bearer $token")
  if [ -n "$body" ]; then
    args+=(-H "Content-Type: application/json" --data-binary "@$body")
  fi
  curl "${args[@]}"
}

login() { # username password -> token
  echo "{\"username\":\"$1\",\"password\":\"$2\"}" > "$TMP/login.json"
  local code
  code=$(http POST /api/auth/login "$TMP/login.json")
  if [ "$code" != "200" ]; then
    say "  \e[31m✘\e[0m login as $1 failed (HTTP $code)"
    return 1
  fi
  extract "$TMP/body" 'j.accessToken'
}

# ---------------------------------------------------------------------------
say "\n\e[1mAegisSOC E2E suite\e[0m  (base: $BASE_URL)"

# 0. Wait for readiness -----------------------------------------------------
say "\n[0] Readiness"
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/health") && [ "$code" = "200" ] && break
  sleep 2
done
if [ "$code" = "200" ]; then ok "server healthy"; else bad "server not healthy (HTTP $code)"; exit 1; fi
curl -s "$BASE_URL/api/health" > "$TMP/health.json"
[ "$(extract "$TMP/health.json" 'j.storage')" = "postgres" ] && ok "postgres storage active" || bad "expected postgres storage, got $(extract "$TMP/health.json" 'j.storage')"

# 1. Unauthenticated access rejected ----------------------------------------
say "\n[1] Authentication boundary"
code=$(http GET /api/alerts)
[ "$code" = "401" ] && ok "unauthenticated /api/alerts -> 401" || bad "unauthenticated /api/alerts -> $code (want 401)"
code=$(http POST /api/telemetry/ingest)
[ "$code" = "401" ] && ok "unauthenticated ingest -> 401" || bad "unauthenticated ingest -> $code (want 401)"

# 2. Login + session ---------------------------------------------------------
say "\n[2] Auth & session"
ANA=$(login analyst "${SEED_ANALYST_PASSWORD:-ChangeMe_Analyst_2026!}") || exit 1
ok "analyst login"
ADMIN=$(login admin "${SEED_ADMIN_PASSWORD:-ChangeMe_Admin_2026!}") || exit 1
ok "admin login"
TRA=$(login trainer "${SEED_TRAINER_PASSWORD:-ChangeMe_Trainer_2026!}") || exit 1
ok "trainer login"
VIEW=$(login viewer "${SEED_VIEWER_PASSWORD:-ChangeMe_Viewer_2026!}") || exit 1
ok "viewer login"
code=$(http POST /api/auth/login "$TMP/login.json" "") # reuse wrong-ish body? use explicit bad creds
code=$(echo '{"username":"analyst","password":"wrong-password-xyz"}' > "$TMP/bad.json"; http POST /api/auth/login "$TMP/bad.json")
[ "$code" = "401" ] && ok "bad credentials -> 401" || bad "bad credentials -> $code (want 401)"
code=$(http GET /api/auth/me "" "$ANA")
[ "$code" = "200" ] && [ "$(extract "$TMP/body" 'j.user.score')" != "__ERR__" ] && ok "session includes score" || bad "session missing score"

# 3. Alerts ------------------------------------------------------------------
say "\n[3] Alerts"
code=$(http GET "/api/alerts" "" "$ANA")
[ "$code" = "200" ] && ok "list alerts" || bad "list alerts -> $code"
TOTAL=$(extract "$TMP/body" 'j.total')
[ "$TOTAL" -ge 5 ] 2>/dev/null && ok "seeded alerts present ($TOTAL)" || bad "expected >=5 alerts, got $TOTAL"
code=$(http GET "/api/alerts/ALT-1092" "" "$ANA")
[ "$code" = "200" ] && ok "get alert by id" || bad "get alert by id -> $code"

# 4. Triage + persistence ----------------------------------------------------
say "\n[4] Triage"
echo '{"status":"investigating","triage_notes":"e2e check"}' > "$TMP/triage.json"
code=$(http PATCH /api/alerts/ALT-1092/triage "$TMP/triage.json" "$ANA")
[ "$code" = "200" ] && ok "triage accepted" || bad "triage -> $code"
code=$(http GET "/api/alerts/ALT-1092" "" "$ANA")
[ "$(extract "$TMP/body" 'j.triage_notes')" = "e2e check" ] && ok "triage persisted" || bad "triage not persisted"

# 5. CTF integrity + per-user solves ------------------------------------------
say "\n[5] CTF (flags server-side, per-user state)"
code=$(http GET "/api/ctf/challenges" "" "$ANA")
[ "$code" = "200" ] && ok "list challenges" || bad "list challenges -> $code"
if grep -q "FLAG{" "$TMP/body"; then bad "flags leaked in /api/ctf/challenges"; else ok "no flags in challenge list"; fi

echo '{"flag":"FLAG{un10n_s3l3ct_byp4ss_2026}"}' > "$TMP/flag.json"
code=$(http POST /api/ctf/challenges/CTF-WEB-01/submit "$TMP/flag.json" "$ANA")
[ "$code" = "200" ] && ok "correct flag accepted (+$(extract "$TMP/body" 'j.pointsAwarded') pts)" || bad "correct flag -> $code"
code=$(http POST /api/ctf/challenges/CTF-WEB-01/submit "$TMP/flag.json" "$ANA")
MSG=$(extract "$TMP/body" 'j.message')
[ "$code" = "200" ] && echo "$MSG" | grep -qi "already" && ok "duplicate submission not double-awarded" || bad "duplicate submission: $MSG"

code=$(http GET "/api/ctf/challenges" "" "$TRA")
SOLVED=$(extract "$TMP/body" 'j.find(function(c){return c.id==="CTF-WEB-01"}).solved')
[ "$SOLVED" = "false" ] && ok "per-user isolation: trainer still sees unsolved" || bad "trainer sees solved=$SOLVED"

code=$(http GET "/api/ctf/leaderboard" "" "$ANA")
if echo "$(extract "$TMP/body" 'JSON.stringify(j)')" | grep -q "Lead SOC Analyst"; then
  ok "leaderboard shows real user"
else
  bad "leaderboard missing real user"
fi

# 6. Hints (per-user) ----------------------------------------------------------
say "\n[6] CTF hints"
code=$(http POST /api/ctf/challenges/CTF-FOR-02/unlock-hint "" "$ANA")
[ "$code" = "200" ] && ok "analyst unlocked hint" || bad "unlock hint -> $code"
code=$(http GET "/api/ctf/challenges" "" "$TRA")
UNLOCKED=$(extract "$TMP/body" 'j.find(function(c){return c.id==="CTF-FOR-02"}).hintUnlocked')
[ "$UNLOCKED" = "false" ] && ok "trainer hint state isolated" || bad "trainer hintUnlocked=$UNLOCKED"

# 7. Training (per-user completion) --------------------------------------------
say "\n[7] Training"
echo '{}' > "$TMP/empty.json"
code=$(http POST /api/training/courses/CRS-01/lessons/CRS-01-L2/complete "$TMP/empty.json" "$TRA")
PROG=$(extract "$TMP/body" 'j.courseProgress')
[ "$code" = "200" ] && [ "$PROG" = "33" ] && ok "trainer lesson completed (33%)" || bad "complete lesson -> $code progress=$PROG"
code=$(http GET "/api/training/courses" "" "$ANA")
DONE=$(extract "$TMP/body" 'j.find(function(c){return c.id==="CRS-01"}).lessons.filter(function(l){return l.completed}).length')
[ "$DONE" = "0" ] && ok "analyst progress unaffected" || bad "analyst completed=$DONE lessons"

# 8. AI module ------------------------------------------------------------------
say "\n[8] AI (zero-training-data)"
code=$(http POST /api/ai/anomaly "$TMP/empty.json" "$ANA")
[ "$code" = "200" ] && [ "$(extract "$TMP/body" 'j.riskLevel')" != "__ERR__" ] && ok "anomaly detection" || bad "anomaly -> $code"
code=$(http POST /api/ai/correlate "$TMP/empty.json" "$ANA")
[ "$code" = "200" ] && [ "$(extract "$TMP/body" 'j.clusters.length')" != "__ERR__" ] && ok "alert correlation" || bad "correlate -> $code"
echo '{"rawEmail":"Received-SPF: fail (evil.example) client-ip=198.51.100.44\nSubject: URGENT password reset\nAuthentication-Results: spf=fail; dmarc=fail"}' > "$TMP/phish.json"
code=$(http POST /api/ai/phishing-analyze "$TMP/phish.json" "$ANA")
[ "$code" = "200" ] && [ "$(extract "$TMP/body" 'j.spfCheck')" = "FAIL" ] && ok "phishing analysis (SPF=FAIL)" || bad "phishing -> $code"
echo '{"challengeId":"CTF-WEB-01"}' > "$TMP/hint.json"
code=$(http POST /api/ai/ctf-hint "$TMP/hint.json" "$ANA")
[ "$code" = "200" ] && ! grep -q "FLAG{" "$TMP/body" && ok "AI ctf hint (no flag leak)" || bad "ctf-hint -> $code"

# 9. RBAC ------------------------------------------------------------------------
say "\n[9] RBAC"
code=$(http POST /api/simulation/inject "$TMP/empty.json" "$VIEW")
[ "$code" = "403" ] && ok "viewer denied mutation (403)" || bad "viewer mutation -> $code (want 403)"
code=$(http GET "/api/audit" "" "$ANA")
[ "$code" = "403" ] && ok "analyst denied audit (403)" || bad "analyst audit -> $code (want 403)"
code=$(http GET "/api/audit" "" "$ADMIN")
[ "$code" = "200" ] && ok "admin can read audit" || bad "admin audit -> $code"

# 10. Ingest ---------------------------------------------------------------------
say "\n[10] Telemetry ingest"
if [ -n "$INGEST_KEY" ]; then
  echo '{"events":[{"isAlert":true,"severity":"high","title":"E2E Ingest","source":"e2e","sourceIp":"203.0.113.77"}]}' > "$TMP/ingest.json"
  code=$(curl -s -o "$TMP/body" -w "%{http_code}" -X POST "$BASE_URL/api/telemetry/ingest" \
    -H "Content-Type: application/json" -H "x-api-key: $INGEST_KEY" --data-binary "@$TMP/ingest.json")
  [ "$code" = "200" ] && ok "ingest with API key accepted" || bad "ingest with key -> $code"
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/api/telemetry/ingest" \
    -H "Content-Type: application/json" -H "x-api-key: wrong-key" --data-binary "@$TMP/ingest.json")
  [ "$code" = "401" ] && ok "ingest with wrong key -> 401" || bad "ingest wrong key -> $code (want 401)"
else
  say "  (skipped — set INGEST_API_KEY to test machine-key ingest)"
fi

# ---------------------------------------------------------------------------
say ""
say "\e[1mResults: $PASS passed, $FAIL failed\e[0m"
[ "$FAIL" -eq 0 ] || exit 1