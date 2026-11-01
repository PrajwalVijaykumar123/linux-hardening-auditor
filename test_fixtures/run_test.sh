#!/bin/sh
# Builds two real on-disk fixture trees (compliant/ and noncompliant/)
# and runs the real scanner.py against each with every --*-file flag
# pointed at the fixture - every check reads real files and real file
# permissions, nothing mocked.
set -e
cd "$(dirname "$0")/.."

FIXTURES=/tmp/lha_fixtures_$$
python3 test_fixtures/make_fixtures.py "$FIXTURES"

flags() {
  dir="$1"
  echo "--shadow-file $dir/shadow --passwd-file $dir/passwd --sshd-config $dir/sshd_config \
--login-defs $dir/login_defs --sudoers-file $dir/sudoers --sudoers-d-dir $dir/sudoers.d \
--fstab-file $dir/fstab --sysctl-file $dir/sysctl.conf"
}

COMPLIANT="$FIXTURES/compliant"
NONCOMPLIANT="$FIXTURES/noncompliant"

echo "== Compliant fixture: expect zero failed checks, exit 0 even at --fail-on any =="
set +e
# shellcheck disable=SC2046
python3 scanner.py $(flags "$COMPLIANT") --json /tmp/lha_compliant.json --fail-on any > /tmp/lha_1.txt 2>&1
EXIT1=$?
set -e
cat /tmp/lha_1.txt
grep -q "No failed checks" /tmp/lha_1.txt && echo "PASS: compliant fixture produces zero failed checks" || { echo "FAIL"; rm -rf "$FIXTURES"; exit 1; }
[ "$EXIT1" = "0" ] && echo "PASS: exit code 0 on fully compliant fixture" || { echo "FAIL: expected exit 0, got $EXIT1"; rm -rf "$FIXTURES"; exit 1; }

echo
echo "== Noncompliant fixture: expect specific checks to fail =="
set +e
# shellcheck disable=SC2046
python3 scanner.py $(flags "$NONCOMPLIANT") --json /tmp/lha_noncompliant.json --fail-on any > /tmp/lha_2.txt 2>&1
EXIT2=$?
set -e
cat /tmp/lha_2.txt
[ "$EXIT2" = "1" ] && echo "PASS: exit code 1 on noncompliant fixture" || { echo "FAIL: expected exit 1, got $EXIT2"; rm -rf "$FIXTURES"; exit 1; }

assert_fail() {
  check_id="$1"
  python3 -c "
import json, sys
results = json.load(open('/tmp/lha_noncompliant.json'))
r = next((x for x in results if x['check_id'] == '$check_id'), None)
sys.exit(0 if r and r['status'] == 'fail' else 1)
" && echo "PASS: $check_id correctly FAILS on noncompliant fixture" || { echo "FAIL: $check_id did not fail as expected"; rm -rf "$FIXTURES"; exit 1; }
}

for cid in FS-1 FS-2 FS-3 SSH-1 SSH-2 SSH-3 SSH-4 SSH-5 ACCT-1 ACCT-2 ACCT-3 ACCT-4 SUDO-1 SUDO-2 SYSCTL-1 SYSCTL-2 SYSCTL-3 SYSCTL-4; do
  assert_fail "$cid"
done

echo
echo "== Cross-check: every one of those 18 checks PASSES on the compliant fixture =="
python3 -c "
import json, sys
results = json.load(open('/tmp/lha_compliant.json'))
failed = [r['check_id'] for r in results if r['status'] == 'fail']
if failed:
    print('Unexpectedly failed on compliant fixture:', failed)
    sys.exit(1)
print('PASS: all 18 checks pass on the compliant fixture')
"

rm -rf "$FIXTURES" /tmp/lha_1.txt /tmp/lha_2.txt /tmp/lha_compliant.json /tmp/lha_noncompliant.json
echo
echo "All tests passed."
