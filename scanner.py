#!/usr/bin/env python3
"""
linux-hardening-auditor

Audits a Linux host's configuration against 18 checks drawn from the CIS
Distribution Independent Linux Benchmark, each also mapped to a real
ISO/IEC 27001:2022 Annex A control - so a report from this tool doubles
as audit evidence, not just a checklist.

Run with no arguments to audit the REAL machine it's running on. Use the
--*-file overrides to point individual checks at a different root (a
chroot, a mounted disk image, or - as the test suite does - a deliberately
misconfigured fixture) without needing root on a live system you don't
want to touch.

Only audit systems you own or are authorized to assess.
"""
import argparse
import json
import sys

from checks import AuditContext, run_all

SEVERITY_ORDER = ["low", "medium", "high"]


def print_report(results):
    failed = [r for r in results if r.status == "fail"]
    passed = [r for r in results if r.status == "pass"]
    errored = [r for r in results if r.status == "error"]

    print(f"\nLinux hardening audit: {len(results)} checks "
          f"({len(passed)} pass, {len(failed)} fail, {len(errored)} skipped/error)\n")

    if failed:
        failed.sort(key=lambda r: SEVERITY_ORDER.index(r.severity), reverse=True)
        for r in failed:
            print(f"  [FAIL - {r.severity.upper()}] {r.check_id}: {r.title}")
            print(f"      {r.cis_ref} | {r.iso27001_ref}")
            print(f"      {r.detail}")
            if r.remediation:
                print(f"      Fix: {r.remediation}")
            print()

    if errored:
        print("  Skipped (file/path not found or unreadable):")
        for r in errored:
            print(f"    [SKIP] {r.check_id}: {r.title} - {r.detail}")
        print()

    if not failed:
        print("  No failed checks.\n")


def main():
    ap = argparse.ArgumentParser(description="Audit Linux system-hardening configuration.")
    ap.add_argument("--shadow-file", default="/etc/shadow")
    ap.add_argument("--passwd-file", default="/etc/passwd")
    ap.add_argument("--sshd-config", default="/etc/ssh/sshd_config")
    ap.add_argument("--login-defs", default="/etc/login.defs")
    ap.add_argument("--sudoers-file", default="/etc/sudoers")
    ap.add_argument("--sudoers-d-dir", default="/etc/sudoers.d")
    ap.add_argument("--fstab-file", default="/etc/fstab")
    ap.add_argument("--sysctl-file", default=None,
                     help="Read sysctl values from this file instead of live /proc/sys "
                          "(file format: 'key = value' per line, as in /etc/sysctl.conf)")
    ap.add_argument("--json", metavar="FILE", help="Write JSON report to FILE")
    ap.add_argument("--fail-on", default="medium",
                     choices=["low", "medium", "high", "any", "none"],
                     help="Exit 1 if a failed check at/above this severity exists. Default: medium")
    args = ap.parse_args()

    ctx = AuditContext(
        shadow_file=args.shadow_file,
        passwd_file=args.passwd_file,
        sshd_config=args.sshd_config,
        login_defs=args.login_defs,
        sudoers_file=args.sudoers_file,
        sudoers_d_dir=args.sudoers_d_dir,
        fstab_file=args.fstab_file,
        sysctl_file=args.sysctl_file,
    )

    results = run_all(ctx)
    print_report(results)

    if args.json:
        with open(args.json, "w") as fh:
            json.dump([r.to_dict() for r in results], fh, indent=2)
        print(f"JSON report written to {args.json}\n")

    failed = [r for r in results if r.status == "fail"]
    if args.fail_on == "none" or not failed:
        sys.exit(0)
    if args.fail_on == "any":
        sys.exit(1)
    threshold = SEVERITY_ORDER.index(args.fail_on)
    worst = max(SEVERITY_ORDER.index(r.severity) for r in failed)
    sys.exit(1 if worst >= threshold else 0)


if __name__ == "__main__":
    main()
