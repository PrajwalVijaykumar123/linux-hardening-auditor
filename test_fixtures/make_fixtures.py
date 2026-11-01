"""
Builds two real, on-disk fixture trees - compliant/ and noncompliant/ -
each containing real shadow/passwd/sshd_config/login.defs/sudoers/fstab/
sysctl files with real file permissions set via os.chmod. The test suite
points scanner.py's --*-file flags at these instead of the live system,
so every check runs its real file-reading and permission-checking logic
against real files - nothing about the checks themselves is mocked, only
which files they're told to look at.
"""
import os
import stat


def _write(path, content, mode=None):
    with open(path, "w") as fh:
        fh.write(content)
    if mode is not None:
        os.chmod(path, mode)


def build(base_dir: str):
    compliant = os.path.join(base_dir, "compliant")
    noncompliant = os.path.join(base_dir, "noncompliant")
    for d in (compliant, noncompliant):
        os.makedirs(os.path.join(d, "sudoers.d"), exist_ok=True)

    # ---------------------------------------------------------- compliant
    _write(os.path.join(compliant, "shadow"),
           "root:$6$rounds=100000$abc$longhashvalue:19700:0:99999:7:::\n"
           "deploy:$6$rounds=100000$xyz$longhashvalue:19700:0:99999:7:::\n",
           mode=0o640)
    _write(os.path.join(compliant, "passwd"),
           "root:x:0:0:root:/root:/bin/bash\n"
           "deploy:x:1000:1000::/home/deploy:/bin/bash\n",
           mode=0o644)
    _write(os.path.join(compliant, "sshd_config"),
           "PermitRootLogin no\n"
           "PasswordAuthentication no\n"
           "PermitEmptyPasswords no\n"
           "X11Forwarding no\n"
           "MaxAuthTries 3\n")
    _write(os.path.join(compliant, "login_defs"),
           "PASS_MAX_DAYS\t90\n"
           "PASS_MIN_LEN\t14\n")
    _write(os.path.join(compliant, "sudoers"),
           "root ALL=(ALL) ALL\n"
           "%sudo ALL=(ALL) ALL\n",
           mode=0o440)
    _write(os.path.join(compliant, "sudoers.d", "deploy"),
           "deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart app\n")
    _write(os.path.join(compliant, "fstab"),
           "UUID=1111 /               ext4    defaults        0 1\n"
           "tmpfs     /tmp            tmpfs   defaults,noexec,nosuid 0 0\n")
    _write(os.path.join(compliant, "sysctl.conf"),
           "net.ipv4.ip_forward = 0\n"
           "net.ipv4.conf.all.accept_source_route = 0\n"
           "net.ipv4.tcp_syncookies = 1\n"
           "kernel.randomize_va_space = 2\n")

    # ------------------------------------------------------- noncompliant
    _write(os.path.join(noncompliant, "shadow"),
           "root:$6$rounds=100000$abc$longhashvalue:19700:0:99999:7:::\n"
           "backdoor::19700:0:99999:7:::\n",  # empty password hash
           mode=0o644)
    _write(os.path.join(noncompliant, "passwd"),
           "root:x:0:0:root:/root:/bin/bash\n"
           "toor:x:0:0:backdoor admin:/root:/bin/bash\n"   # duplicate UID 0
           "deploy:x:1000:1000::/home/deploy:/bin/bash\n",
           mode=0o666)
    _write(os.path.join(noncompliant, "sshd_config"),
           "PermitRootLogin yes\n"
           "PasswordAuthentication yes\n"
           "PermitEmptyPasswords yes\n"
           "X11Forwarding yes\n"
           "MaxAuthTries 10\n")
    _write(os.path.join(noncompliant, "login_defs"),
           "PASS_MAX_DAYS\t99999\n")  # PASS_MIN_LEN deliberately absent
    _write(os.path.join(noncompliant, "sudoers"),
           "root ALL=(ALL) ALL\n"
           "admin ALL=(ALL) NOPASSWD: ALL\n",
           mode=0o644)
    _write(os.path.join(noncompliant, "fstab"),
           "UUID=1111 /               ext4    defaults        0 1\n")  # no /tmp entry at all
    _write(os.path.join(noncompliant, "sysctl.conf"),
           "net.ipv4.ip_forward = 1\n"
           "net.ipv4.conf.all.accept_source_route = 1\n"
           "net.ipv4.tcp_syncookies = 0\n"
           "kernel.randomize_va_space = 0\n")

    return compliant, noncompliant


if __name__ == "__main__":
    import sys
    base = sys.argv[1] if len(sys.argv) > 1 else "/tmp/lha_fixtures"
    c, n = build(base)
    print(f"Built fixtures:\n  compliant:    {c}\n  noncompliant: {n}")
