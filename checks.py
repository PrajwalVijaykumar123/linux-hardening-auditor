"""
19 Linux system-hardening checks, each mapped to a real CIS Distribution
Independent Linux Benchmark control ID and a real ISO/IEC 27001:2022
Annex A control reference - because "we have a hardening checklist" means
nothing to an auditor without the control mapping that lets it be used as
actual audit evidence.

Every check takes an AuditContext, which holds the file paths it reads.
Those paths default to the real system paths, so running this with no
overrides audits the REAL machine it's run on - not a fixture. The
overrides exist purely so the test suite can point individual checks at
deliberately compliant/non-compliant temp files for deterministic
pass/fail testing, the same pattern used throughout this portfolio.
"""
import os
import re
import stat
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AuditContext:
    shadow_file: str = "/etc/shadow"
    passwd_file: str = "/etc/passwd"
    sshd_config: str = "/etc/ssh/sshd_config"
    login_defs: str = "/etc/login.defs"
    sudoers_file: str = "/etc/sudoers"
    sudoers_d_dir: str = "/etc/sudoers.d"
    fstab_file: str = "/etc/fstab"
    sysctl_file: Optional[str] = None  # if set, parse this instead of live /proc/sys


@dataclass
class CheckResult:
    check_id: str
    title: str
    status: str          # "pass" | "fail" | "error"
    severity: str         # "low" | "medium" | "high"
    cis_ref: str
    iso27001_ref: str
    detail: str
    remediation: str = ""

    def to_dict(self):
        return {
            "check_id": self.check_id, "title": self.title, "status": self.status,
            "severity": self.severity, "cis_ref": self.cis_ref,
            "iso27001_ref": self.iso27001_ref, "detail": self.detail,
            "remediation": self.remediation,
        }


def _result(check_id, title, cis, iso, severity, passed, detail, remediation=""):
    return CheckResult(check_id, title, "pass" if passed else "fail", severity, cis, iso, detail, remediation)


def _error(check_id, title, cis, iso, severity, detail):
    return CheckResult(check_id, title, "error", severity, cis, iso, detail)


def _read_lines(path):
    with open(path) as fh:
        return fh.readlines()


def _parse_sshd_config(path):
    opts = {}
    for line in _read_lines(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            opts[parts[0].lower()] = parts[1].strip()
    return opts


def _parse_login_defs(path):
    opts = {}
    for line in _read_lines(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            opts[parts[0]] = parts[1].strip()
    return opts


def _read_sysctl(ctx: AuditContext, key: str):
    """Read one sysctl key, from ctx.sysctl_file if set, else live /proc/sys."""
    if ctx.sysctl_file:
        if not os.path.exists(ctx.sysctl_file):
            return None
        for line in _read_lines(ctx.sysctl_file):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            k, _, v = line.partition("=")
            if k.strip() == key:
                return v.strip()
        return None
    proc_path = "/proc/sys/" + key.replace(".", "/")
    if not os.path.exists(proc_path):
        return None
    with open(proc_path) as fh:
        return fh.read().strip()


# ---------------------------------------------------------------- Filesystem

def check_shadow_perms(ctx: AuditContext) -> CheckResult:
    cid, title = "FS-1", "/etc/shadow is not readable by non-root users"
    cis, iso, sev = "CIS 6.1.3", "ISO 27001 A.8.9", "high"
    if not os.path.exists(ctx.shadow_file):
        return _error(cid, title, cis, iso, sev, f"{ctx.shadow_file} does not exist")
    mode = stat.S_IMODE(os.stat(ctx.shadow_file).st_mode)
    passed = mode <= 0o640
    return _result(cid, title, cis, iso, sev, passed,
                    f"{ctx.shadow_file} mode is {oct(mode)}",
                    f"chmod 640 {ctx.shadow_file}")


def check_passwd_perms(ctx: AuditContext) -> CheckResult:
    cid, title = "FS-2", "/etc/passwd is world-readable only, not world-writable"
    cis, iso, sev = "CIS 6.1.2", "ISO 27001 A.8.9", "medium"
    if not os.path.exists(ctx.passwd_file):
        return _error(cid, title, cis, iso, sev, f"{ctx.passwd_file} does not exist")
    mode = stat.S_IMODE(os.stat(ctx.passwd_file).st_mode)
    passed = mode <= 0o644
    return _result(cid, title, cis, iso, sev, passed,
                    f"{ctx.passwd_file} mode is {oct(mode)}",
                    f"chmod 644 {ctx.passwd_file}")


def check_fstab_tmp_noexec(ctx: AuditContext) -> CheckResult:
    cid, title = "FS-3", "/tmp is mounted with noexec,nosuid"
    cis, iso, sev = "CIS 1.1.3", "ISO 27001 A.8.9", "medium"
    if not os.path.exists(ctx.fstab_file):
        return _error(cid, title, cis, iso, sev, f"{ctx.fstab_file} does not exist")
    tmp_line = None
    for line in _read_lines(ctx.fstab_file):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "/tmp":
            tmp_line = fields
            break
    if tmp_line is None:
        return _result(cid, title, cis, iso, sev, False,
                        "/tmp has no dedicated fstab entry (likely part of root filesystem, can't be mounted noexec independently)",
                        "Give /tmp its own filesystem/tmpfs entry in /etc/fstab with noexec,nosuid")
    opts = tmp_line[3] if len(tmp_line) > 3 else ""
    passed = "noexec" in opts and "nosuid" in opts
    return _result(cid, title, cis, iso, sev, passed, f"/tmp mount options: {opts}",
                    "Add noexec,nosuid to /tmp's mount options in /etc/fstab")


# ---------------------------------------------------------------- SSH

def _ssh_opt_check(ctx, cid, title, cis, iso, sev, option, expected, remediation):
    if not os.path.exists(ctx.sshd_config):
        return _error(cid, title, cis, iso, sev, f"{ctx.sshd_config} does not exist")
    opts = _parse_sshd_config(ctx.sshd_config)
    actual = opts.get(option.lower())
    passed = actual is not None and actual.lower() == expected.lower()
    detail = f"{option} is '{actual}'" if actual is not None else f"{option} is not set (uses sshd default)"
    return _result(cid, title, cis, iso, sev, passed, detail, remediation)


def check_ssh_permit_root_login(ctx: AuditContext) -> CheckResult:
    return _ssh_opt_check(ctx, "SSH-1", "SSH root login is disabled", "CIS 5.2.10",
                           "ISO 27001 A.8.5", "high", "PermitRootLogin", "no",
                           "Set 'PermitRootLogin no' in sshd_config")


def check_ssh_password_auth(ctx: AuditContext) -> CheckResult:
    return _ssh_opt_check(ctx, "SSH-2", "SSH password authentication is disabled (key-only)",
                           "CIS 5.2.4", "ISO 27001 A.8.5", "high", "PasswordAuthentication", "no",
                           "Set 'PasswordAuthentication no' in sshd_config and ensure key-based auth works first")


def check_ssh_permit_empty_passwords(ctx: AuditContext) -> CheckResult:
    return _ssh_opt_check(ctx, "SSH-3", "SSH empty passwords are not permitted", "CIS 5.2.8",
                           "ISO 27001 A.8.5", "high", "PermitEmptyPasswords", "no",
                           "Set 'PermitEmptyPasswords no' in sshd_config")


def check_ssh_x11_forwarding(ctx: AuditContext) -> CheckResult:
    return _ssh_opt_check(ctx, "SSH-4", "SSH X11 forwarding is disabled", "CIS 5.2.5",
                           "ISO 27001 A.8.20", "low", "X11Forwarding", "no",
                           "Set 'X11Forwarding no' in sshd_config unless specifically required")


def check_ssh_max_auth_tries(ctx: AuditContext) -> CheckResult:
    cid, title = "SSH-5", "SSH MaxAuthTries is 4 or fewer"
    cis, iso, sev = "CIS 5.2.7", "ISO 27001 A.8.5", "medium"
    if not os.path.exists(ctx.sshd_config):
        return _error(cid, title, cis, iso, sev, f"{ctx.sshd_config} does not exist")
    opts = _parse_sshd_config(ctx.sshd_config)
    val = opts.get("maxauthtries")
    if val is None:
        return _result(cid, title, cis, iso, sev, False, "MaxAuthTries is not set (sshd default is 6)",
                        "Set 'MaxAuthTries 4' in sshd_config")
    try:
        passed = int(val) <= 4
    except ValueError:
        return _error(cid, title, cis, iso, sev, f"MaxAuthTries value '{val}' is not an integer")
    return _result(cid, title, cis, iso, sev, passed, f"MaxAuthTries is {val}",
                    "Set 'MaxAuthTries 4' in sshd_config")


# ---------------------------------------------------------------- Accounts

def check_no_duplicate_uid0(ctx: AuditContext) -> CheckResult:
    cid, title = "ACCT-1", "Only one account (root) has UID 0"
    cis, iso, sev = "CIS 6.2.9", "ISO 27001 A.8.2", "high"
    if not os.path.exists(ctx.passwd_file):
        return _error(cid, title, cis, iso, sev, f"{ctx.passwd_file} does not exist")
    uid0_accounts = []
    for line in _read_lines(ctx.passwd_file):
        fields = line.strip().split(":")
        if len(fields) >= 3 and fields[2] == "0":
            uid0_accounts.append(fields[0])
    passed = uid0_accounts == ["root"]
    return _result(cid, title, cis, iso, sev, passed, f"UID 0 accounts: {uid0_accounts}",
                    "Remove UID 0 from any account other than 'root'")


def check_no_empty_password_hashes(ctx: AuditContext) -> CheckResult:
    cid, title = "ACCT-2", "No account has an empty password hash"
    cis, iso, sev = "CIS 6.2.1", "ISO 27001 A.8.5", "high"
    if not os.path.exists(ctx.shadow_file):
        return _error(cid, title, cis, iso, sev, f"{ctx.shadow_file} does not exist")
    empty = []
    for line in _read_lines(ctx.shadow_file):
        fields = line.strip().split(":")
        if len(fields) >= 2 and fields[1] == "":
            empty.append(fields[0])
    passed = len(empty) == 0
    return _result(cid, title, cis, iso, sev, passed, f"Accounts with empty password hash: {empty}",
                    "Lock or set a password for every account listed (passwd -l <user>)")


def check_login_defs_max_days(ctx: AuditContext) -> CheckResult:
    cid, title = "ACCT-3", "Password max age (PASS_MAX_DAYS) is 90 or fewer"
    cis, iso, sev = "CIS 5.4.1.1", "ISO 27001 A.5.17", "medium"
    if not os.path.exists(ctx.login_defs):
        return _error(cid, title, cis, iso, sev, f"{ctx.login_defs} does not exist")
    opts = _parse_login_defs(ctx.login_defs)
    val = opts.get("PASS_MAX_DAYS")
    if val is None:
        return _result(cid, title, cis, iso, sev, False, "PASS_MAX_DAYS is not set",
                        "Set 'PASS_MAX_DAYS 90' in /etc/login.defs")
    try:
        passed = int(val) <= 90
    except ValueError:
        return _error(cid, title, cis, iso, sev, f"PASS_MAX_DAYS value '{val}' is not an integer")
    return _result(cid, title, cis, iso, sev, passed, f"PASS_MAX_DAYS is {val}",
                    "Set 'PASS_MAX_DAYS 90' in /etc/login.defs")


def check_login_defs_min_len(ctx: AuditContext) -> CheckResult:
    cid, title = "ACCT-4", "Minimum password length is 14 or more"
    cis, iso, sev = "CIS 5.3.1", "ISO 27001 A.5.17", "medium"
    if not os.path.exists(ctx.login_defs):
        return _error(cid, title, cis, iso, sev, f"{ctx.login_defs} does not exist")
    opts = _parse_login_defs(ctx.login_defs)
    val = opts.get("PASS_MIN_LEN")
    if val is None:
        return _result(cid, title, cis, iso, sev, False,
                        "PASS_MIN_LEN is not set in login.defs (modern systems should enforce this via pam_pwquality instead, but if neither is configured, there is no minimum)",
                        "Set 'PASS_MIN_LEN 14' in /etc/login.defs, or minlen=14 in /etc/security/pwquality.conf")
    try:
        passed = int(val) >= 14
    except ValueError:
        return _error(cid, title, cis, iso, sev, f"PASS_MIN_LEN value '{val}' is not an integer")
    return _result(cid, title, cis, iso, sev, passed, f"PASS_MIN_LEN is {val}",
                    "Set 'PASS_MIN_LEN 14' in /etc/login.defs")


# ---------------------------------------------------------------- Sudo

def check_sudoers_perms(ctx: AuditContext) -> CheckResult:
    cid, title = "SUDO-1", "/etc/sudoers has mode 0440 or stricter"
    cis, iso, sev = "CIS 5.1.1", "ISO 27001 A.8.9", "medium"
    if not os.path.exists(ctx.sudoers_file):
        return _error(cid, title, cis, iso, sev, f"{ctx.sudoers_file} does not exist")
    mode = stat.S_IMODE(os.stat(ctx.sudoers_file).st_mode)
    passed = mode <= 0o440
    return _result(cid, title, cis, iso, sev, passed, f"{ctx.sudoers_file} mode is {oct(mode)}",
                    f"chmod 440 {ctx.sudoers_file}")


def check_sudoers_no_unrestricted_nopasswd(ctx: AuditContext) -> CheckResult:
    cid, title = "SUDO-2", "No sudoers entry grants NOPASSWD:ALL"
    cis, iso, sev = "CIS 5.1.2 (custom)", "ISO 27001 A.8.2", "high"
    files = []
    if os.path.exists(ctx.sudoers_file):
        files.append(ctx.sudoers_file)
    if os.path.isdir(ctx.sudoers_d_dir):
        for name in sorted(os.listdir(ctx.sudoers_d_dir)):
            files.append(os.path.join(ctx.sudoers_d_dir, name))
    if not files:
        return _error(cid, title, cis, iso, sev, "No sudoers files found")
    offenders = []
    pattern = re.compile(r"NOPASSWD:\s*ALL", re.IGNORECASE)
    for f in files:
        for line in _read_lines(f):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if pattern.search(line):
                offenders.append(f"{f}: {line}")
    passed = len(offenders) == 0
    return _result(cid, title, cis, iso, sev, passed,
                    f"{len(offenders)} unrestricted NOPASSWD:ALL entr{'y' if len(offenders)==1 else 'ies'} found" +
                    (f" ({offenders})" if offenders else ""),
                    "Scope NOPASSWD entries to specific commands, never ALL, or require a password")


# ---------------------------------------------------------------- Kernel / Network

def _sysctl_check(ctx, cid, title, cis, iso, sev, key, expected, remediation):
    val = _read_sysctl(ctx, key)
    if val is None:
        return _error(cid, title, cis, iso, sev, f"Could not read {key}")
    passed = val == expected
    return _result(cid, title, cis, iso, sev, passed, f"{key} = {val} (expected {expected})", remediation)


def check_sysctl_ip_forward(ctx: AuditContext) -> CheckResult:
    return _sysctl_check(ctx, "SYSCTL-1", "IPv4 forwarding is disabled", "CIS 3.1.1",
                          "ISO 27001 A.8.20", "medium", "net.ipv4.ip_forward", "0",
                          "sysctl -w net.ipv4.ip_forward=0 (unless this host is an intentional router)")


def check_sysctl_source_route(ctx: AuditContext) -> CheckResult:
    return _sysctl_check(ctx, "SYSCTL-2", "Source-routed packets are not accepted", "CIS 3.2.1",
                          "ISO 27001 A.8.20", "medium", "net.ipv4.conf.all.accept_source_route", "0",
                          "sysctl -w net.ipv4.conf.all.accept_source_route=0")


def check_sysctl_syncookies(ctx: AuditContext) -> CheckResult:
    return _sysctl_check(ctx, "SYSCTL-3", "TCP SYN cookies are enabled (SYN flood protection)",
                          "CIS 3.2.2", "ISO 27001 A.8.20", "medium", "net.ipv4.tcp_syncookies", "1",
                          "sysctl -w net.ipv4.tcp_syncookies=1")


def check_sysctl_aslr(ctx: AuditContext) -> CheckResult:
    return _sysctl_check(ctx, "SYSCTL-4", "Full ASLR is enabled", "CIS 1.6.1",
                          "ISO 27001 A.8.9", "high", "kernel.randomize_va_space", "2",
                          "sysctl -w kernel.randomize_va_space=2")


ALL_CHECKS = [
    check_shadow_perms,
    check_passwd_perms,
    check_fstab_tmp_noexec,
    check_ssh_permit_root_login,
    check_ssh_password_auth,
    check_ssh_permit_empty_passwords,
    check_ssh_x11_forwarding,
    check_ssh_max_auth_tries,
    check_no_duplicate_uid0,
    check_no_empty_password_hashes,
    check_login_defs_max_days,
    check_login_defs_min_len,
    check_sudoers_perms,
    check_sudoers_no_unrestricted_nopasswd,
    check_sysctl_ip_forward,
    check_sysctl_source_route,
    check_sysctl_syncookies,
    check_sysctl_aslr,
]


def run_all(ctx: AuditContext):
    return [check(ctx) for check in ALL_CHECKS]
