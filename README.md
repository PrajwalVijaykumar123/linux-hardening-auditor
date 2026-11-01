# Linux Hardening Auditor

Audits a Linux host's configuration against 18 checks drawn from the **CIS Distribution Independent Linux Benchmark**, each also mapped to a real **ISO/IEC 27001:2022 Annex A** control — so a report from this tool is usable as actual audit evidence, not just a checklist someone has to manually translate into compliance language afterward.

**Only audit systems you own or are authorized to assess.**

## What This Project Does

18 checks across five areas:

- **Filesystem (3)** — `/etc/shadow` and `/etc/passwd` permissions, `/tmp` mounted `noexec,nosuid`
- **SSH hardening (5)** — root login disabled, password auth disabled (key-only), empty passwords rejected, X11 forwarding disabled, `MaxAuthTries` capped
- **Account & password policy (4)** — no duplicate UID 0 accounts, no empty password hashes, password max-age and minimum-length policy
- **Sudo (2)** — `sudoers` file permissions, no unrestricted `NOPASSWD:ALL` entries
- **Kernel/network hardening via sysctl (4)** — IP forwarding, source-routed packet acceptance, SYN cookies, full ASLR

Each check reports **pass/fail/skip**, its **CIS control ID**, its **ISO 27001 Annex A reference**, severity, the actual value found, and a concrete remediation command.

## Why the Compliance Mapping Isn't Cosmetic

A hardening checklist with no control mapping is something an engineer can use but an auditor can't — "we checked 18 things" doesn't answer "which Annex A controls does this evidence support" without someone manually doing that mapping after the fact, every time, for every audit cycle. Attaching the real CIS and ISO 27001 references to each check at the point the check is *defined* means a report from this tool drops directly into audit evidence with no translation step, and the mapping can't silently drift out of sync with the check it describes the way a separate spreadsheet would.

## Real Output — Audited Against the Actual Machine This Was Built On

Running with no arguments audits the **real host it's run on** — not a fixture. This is the real output from running it against the sandbox environment this tool was developed in, unedited:

```
Linux hardening audit: 18 checks (9 pass, 4 fail, 5 skipped/error)

  [FAIL - HIGH] SUDO-2: No sudoers entry grants NOPASSWD:ALL
      CIS 5.1.2 (custom) | ISO 27001 A.8.2
      1 unrestricted NOPASSWD:ALL entry found (['/etc/sudoers: claude ALL=(ALL) NOPASSWD: ALL'])
      Fix: Scope NOPASSWD entries to specific commands, never ALL, or require a password

  [FAIL - MEDIUM] ACCT-3: Password max age (PASS_MAX_DAYS) is 90 or fewer
      CIS 5.4.1.1 | ISO 27001 A.5.17
      PASS_MAX_DAYS is 99999
      Fix: Set 'PASS_MAX_DAYS 90' in /etc/login.defs
  ...
```

That's a real, currently-true finding about the container this README was written in — not a cherry-picked demo.

## Tech Stack

- Python 3.11, standard library only (no third-party dependencies to install for the auditor itself)

## Setup

```bash
python3 scanner.py                              # audit the real local machine
python3 scanner.py --json report.json           # also write a JSON report
python3 scanner.py --fail-on high                # only fail the exit code on HIGH severity findings
```

Every file path has an override flag (`--shadow-file`, `--sshd-config`, `--sysctl-file`, etc.) for auditing a mounted disk image, a chroot, or a config bundle pulled from a remote host, without needing to run the tool as root on a live system.

## Testing

`test_fixtures/make_fixtures.py` builds two complete, real on-disk configuration trees — `compliant/` (passes every check) and `noncompliant/` (deliberately fails every check, including a duplicate UID-0 account, an empty password hash, and an unrestricted `NOPASSWD:ALL` sudoers entry) — with real file permissions set via `os.chmod`. `run_test.sh` runs the real scanner against both:

```bash
sh test_fixtures/run_test.sh
```

This verifies the compliant fixture produces **zero** failed checks (exit 0, even under `--fail-on any`), and that **every single one of the 18 checks** fails on its specific condition in the noncompliant fixture and passes on the compliant one — not just that the tool runs without crashing.

## Architecture

```
scanner.py (CLI: arg parsing, report formatting, --fail-on exit codes)
        |
        v
checks.py: AuditContext (file paths, default to the live system)
        |
        v
18 check functions, each:
  - reads one real config file or live /proc/sys value
  - compares against its CIS Benchmark expected value
  - returns a CheckResult tagged with CIS ref + ISO 27001 ref + severity
        |
        v
Console report (grouped by severity) + optional JSON; exit code reflects --fail-on
```

## Project Structure

```
linux-hardening-auditor/
├── scanner.py                      # CLI
├── checks.py                        # AuditContext + all 18 checks
└── test_fixtures/
    ├── make_fixtures.py            # Builds real compliant/ and noncompliant/ config trees
    └── run_test.sh                    # Runs scanner.py against both, verifies all 18 checks both ways
```

## What I Learned

- A compliance control mapping is only trustworthy if it's attached directly to the code that implements the check, not maintained as a separate document - the two drift apart the moment someone updates one without the other, and nothing forces that update to happen together unless they're literally the same line of code.
- Running the tool against the real sandbox it was built in immediately surfaced a genuine, previously-unnoticed finding (an unrestricted `NOPASSWD:ALL` sudoers entry) - a good reminder that "audit your own environment with your own tool" is a cheap and often-skipped validation step that mock data can't replicate, since mock data is never surprising.
- `PASS_MIN_LEN` in `/etc/login.defs` is a legacy mechanism that most modern distributions have effectively superseded with `pam_pwquality` - the check still has value (an unset value with no PAM enforcement either means literally no minimum), but the remediation text needed to say that honestly instead of implying `login.defs` alone is the modern way to enforce this.
- Sysctl values needed two different read paths (a provided file for deterministic testing, live `/proc/sys` for real auditing) designed in from the start, rather than bolted on - this is the same "configurable target, real default" pattern used throughout this portfolio, applied to kernel parameters instead of network services this time.

## Next Steps

- Extend coverage toward CIS Level 2 controls (auditd rule specifics, AIDE/file-integrity baselining, firewall default-deny posture) for a deeper audit tier.
- A Windows counterpart auditing the equivalent CIS Microsoft Windows Benchmark controls (registry-based policy checks instead of config-file checks).
- A `--remediate` mode that, with explicit confirmation per change, applies the fix commands directly rather than only printing them.
- Direct integration with `detection-as-code`'s GitHub Actions pattern: a scheduled workflow that re-runs this against a fleet of hosts (via SSH) and opens an issue per new failed check, turning this from a point-in-time audit into continuous configuration drift detection.
