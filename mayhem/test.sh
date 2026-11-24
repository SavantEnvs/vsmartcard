#!/usr/bin/env bash
#
# mayhem/test.sh — run the known-answer self-test built by mayhem/build.sh
# (mayhem/tests/vsc_selftest.c: OpenPICC C-APDU decoding/R-APDU encoding and the
# ifd-vpcd/vpcd exchange with a scripted virtual ICC, asserting exact bytes).
# Emits a CTRF report; exit non-zero iff a check failed.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

EXPECTED=17   # number of checks in vsc_selftest.c
runner="$SRC/mayhem/out/vsc_selftest"
if [ ! -x "$runner" ]; then
  echo "test.sh: $runner missing — run mayhem/build.sh first" >&2
  emit_ctrf "vsc-selftest" 0 1
  exit 1
fi

out=$("$runner" 2>&1); rc=$?
echo "$out"
passed=$(grep -c '^PASS ' <<<"$out" || true)
failed=$(grep -c '^FAIL ' <<<"$out" || true)
# a check that never ran (crash, early exit, no-op binary) is a failure
missing=$(( EXPECTED - passed - failed ))
[ "$missing" -gt 0 ] && failed=$(( failed + missing ))
[ "$rc" -ne 0 ] && [ "$failed" -eq 0 ] && failed=1
emit_ctrf "vsc-selftest" "$passed" "$failed"
