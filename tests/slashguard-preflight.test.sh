#!/usr/bin/env bash
# Behaviour tests for templates/slashguard-preflight.sh.tftpl.
#
# The template is rendered with `terraform console`, then run against a stub
# curl that serves canned beacon API responses and a stub slashguard that
# records its arguments. Nothing here opens a socket.
#
# The property under test: the wrapper either hands slashguard the head epoch
# or exits 2. It never runs slashguard without one.
#
#   bash tests/slashguard-preflight.test.sh
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/bin" "$tmp/empty"

# curl stub: answers by path from $FIXTURES/<name>.json. A missing file makes
# it behave like an unreachable host (exit 7); a file named <name>.exit makes
# it exit with that code instead, the way --fail does on an HTTP error.
cat >"$tmp/bin/curl" <<'EOF'
#!/usr/bin/env bash
url=${!#}
case "$url" in
  */eth/v1/node/syncing) name=syncing ;;
  */eth/v1/beacon/headers/head) name=header ;;
  *) echo "curl stub: unexpected URL $url" >&2; exit 3 ;;
esac
if [ -f "$FIXTURES/$name.exit" ]; then exit "$(cat "$FIXTURES/$name.exit")"; fi
if [ -f "$FIXTURES/$name.json" ]; then cat "$FIXTURES/$name.json"; exit 0; fi
echo "curl: (7) Failed to connect" >&2
exit 7
EOF

cat >"$tmp/bin/slashguard" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$FIXTURES/slashguard.args"
exit "${SLASHGUARD_RC:-0}"
EOF
chmod 0755 "$tmp/bin/curl" "$tmp/bin/slashguard"

# terraform console reads one expression per line, so the call is one line.
vars='{ beacon_endpoint = "http://10.20.1.10:5052", slots_per_epoch = 32'
vars+=", slashguard_bin = \"$tmp/bin/slashguard\""
vars+=', keys_dir = "/var/lib/eth/validator/keys"'
vars+=', protection_file = "/var/lib/eth/validator/slashing-protection.json"'
vars+=', genesis_validators_root = "0x415f7d28a5d66b012547d7991089127689f11afa0b6792a080a000a15bbd0352"'
vars+=', max_epoch_lag = 4, fail_on = "high" }'
rendered=$(echo "base64encode(templatefile(\"$repo/templates/slashguard-preflight.sh.tftpl\", $vars))" |
  terraform -chdir="$tmp/empty" console)
rendered=${rendered//\"/}
printf '%s' "$rendered" | base64 -d >"$tmp/slashguard-preflight"
chmod 0755 "$tmp/slashguard-preflight"

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck "$tmp/slashguard-preflight"
fi

synced='{"data":{"head_slot":"3840130","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}'
syncing='{"data":{"head_slot":"3840130","sync_distance":"120","is_syncing":true,"is_optimistic":false,"el_offline":false}}'
# Shape from the beacon-APIs spec, getBlockHeader: data is an object.
header() {
  cat <<EOF
{
  "execution_optimistic": false,
  "finalized": false,
  "data": {
    "root": "0x$(printf '%064d' 1)",
    "canonical": true,
    "header": {
      "message": {
        "slot": "$1",
        "proposer_index": "1",
        "parent_root": "0x$(printf '%064d' 2)",
        "state_root": "0x$(printf '%064d' 3)",
        "body_root": "0x$(printf '%064d' 4)"
      },
      "signature": "0x$(printf '%0192d' 5)"
    }
  }
}
EOF
}

failures=0
case_dir=

# setup NAME: fresh fixture dir for one case.
setup() {
  case_dir="$tmp/case-$1"
  mkdir -p "$case_dir"
}

# expect NAME RC [SLASHGUARD_RC]: run the wrapper and check its exit code.
expect() {
  local name=$1 want=$2 rc=0
  FIXTURES=$case_dir PATH="$tmp/bin:$PATH" SLASHGUARD_RC=${3:-0} \
    "$tmp/slashguard-preflight" >"$case_dir/stdout" 2>"$case_dir/stderr" || rc=$?
  if [ "$rc" != "$want" ]; then
    echo "FAIL $name: exit $rc, want $want" >&2
    sed 's/^/  stderr: /' "$case_dir/stderr" >&2
    failures=$((failures + 1))
    return 1
  fi
  echo "ok   $name"
}

# no_slashguard NAME: the wrapper must not have run slashguard.
no_slashguard() {
  if [ -e "$case_dir/slashguard.args" ]; then
    echo "FAIL $1: slashguard ran without a head epoch" >&2
    failures=$((failures + 1))
  fi
}

setup healthy
echo "$synced" >"$case_dir/syncing.json"
header 3840130 >"$case_dir/header.json"
if expect "synced node: slashguard gets the head epoch" 0; then
  want=$(printf '%s\n' \
    --interchange /var/lib/eth/validator/slashing-protection.json \
    --keystores /var/lib/eth/validator/keys \
    --genesis-validators-root 0x415f7d28a5d66b012547d7991089127689f11afa0b6792a080a000a15bbd0352 \
    --current-epoch 120004 \
    --max-epoch-lag 4 \
    --fail-on high)
  if [ "$(cat "$case_dir/slashguard.args")" != "$want" ]; then
    echo "FAIL synced node: slashguard arguments" >&2
    diff <(echo "$want") "$case_dir/slashguard.args" >&2 || true
    failures=$((failures + 1))
  fi
fi

setup blocked
echo "$synced" >"$case_dir/syncing.json"
header 3840130 >"$case_dir/header.json"
expect "slashguard's exit 1 reaches systemd" 1 1 || true

setup unreachable
expect "beacon node unreachable" 2 || true
no_slashguard "beacon node unreachable"

setup header-unreachable
echo "$synced" >"$case_dir/syncing.json"
expect "headers endpoint unreachable" 2 || true
no_slashguard "headers endpoint unreachable"

setup header-http-error
echo "$synced" >"$case_dir/syncing.json"
echo 22 >"$case_dir/header.exit"
expect "headers endpoint returns an HTTP error" 2 || true
no_slashguard "headers endpoint returns an HTTP error"

setup syncing
echo "$syncing" >"$case_dir/syncing.json"
header 3840130 >"$case_dir/header.json"
expect "node still syncing" 2 || true
no_slashguard "node still syncing"

setup no-is-syncing
echo '{"data":{"head_slot":"3840130"}}' >"$case_dir/syncing.json"
header 3840130 >"$case_dir/header.json"
expect "syncing response without is_syncing" 2 || true
no_slashguard "syncing response without is_syncing"

setup garbage-header
echo "$synced" >"$case_dir/syncing.json"
echo '<html>502 Bad Gateway</html>' >"$case_dir/header.json"
expect "header response is not the expected JSON" 2 || true
no_slashguard "header response is not the expected JSON"

setup numeric-slot
echo "$synced" >"$case_dir/syncing.json"
header 3840130 | sed 's/"slot": "3840130"/"slot": 3840130/' >"$case_dir/header.json"
expect "slot encoded as a JSON number, not a Uint64 string" 2 || true
no_slashguard "slot encoded as a JSON number, not a Uint64 string"

setup two-slots
echo "$synced" >"$case_dir/syncing.json"
echo '{"data":[{"header":{"message":{"slot":"10"}}},{"header":{"message":{"slot":"3840130"}}}]}' >"$case_dir/header.json"
expect "two slots in one response" 2 || true
no_slashguard "two slots in one response"

setup huge-slot
echo "$synced" >"$case_dir/syncing.json"
header 18446744073709551615 >"$case_dir/header.json"
expect "slot beyond what shell arithmetic holds" 2 || true
no_slashguard "slot beyond what shell arithmetic holds"

if [ "$failures" -gt 0 ]; then
  echo "$failures failure(s)" >&2
  exit 1
fi
echo "all slashguard-preflight cases passed"
