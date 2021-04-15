# Comparing the DISA STIG and CIS Benchmark values

This is a document comparing DISA STIG and CIS benchmark recommended values
when configuring a [Ubuntu Server](https://ubuntu.com/download/server)
server.

This document compare `sshd` timeouts, password lengths and so on. It does
not, for example, compare file permissions, `auditd` rules, packages to be
removed or which specific filesystem should be disabled.

## Ubuntu 18.04

### Documents

[Canonical Ubuntu 18.04 LTS Security Technical Implementation Guide Version: 2 Release: 1](https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cunix-linux)

[CIS Ubuntu Linux 18.04 LTS Benchmark v2.0.1](https://www.cisecurity.org/cis-benchmarks/#ubuntu_linux)

### Comparison Table

_Rule_ is the configuration file and configuration option.\
_CIS_ is the CIS Benchmark value.\
_DISA_ is the DISA STIG value.\
_CIS RN_ is the the CIS Recommendation Number.\
_STIG-ID_ is the STIG-ID value.

A value of `-` means that the setting wasn't metioned in the
document.

| Rule | CIS | DISA | CIS RN | STIG-ID |
| :--- | :-: | :--: | :----: | :-----: |
| `/etc/audit/auditd.conf`: `space_left` | - | 25% | - | UBTU-18-010006 |
| `/etc/chrony/chrony.conf`: `makestep` | - | 1 -1 | - | UBTU-18-010502 |
| `/etc/chrony/chrony.conf`: `maxpoll` | - | 17 | - | UBTU-18-010501 |
| `/etc/default/grub`: `audit_backlog_limit` | 8192 | - | 4.1.1.4 | - |
| `/etc/default/useradd`: `INACTIVE` | 30 | 35 | 5.4.1.4 | UBTU-18-010445 |
| `/etc/login.defs`: `ENCRYPT_METHOD` | - | SHA512 | - | UBTU-18-010110 |
| `/etc/login.defs`: `PASS_MAX_DAYS` | 365 | 60 | 5.4.1.1 | UBTU-18-010107 |
| `/etc/login.defs`: `PASS_MIN_DAYS` | 1 | 1 | 5.4.1.2 | UBTU-18-010106 |
| `/etc/login.defs`: `PASS_WARN_AGE` | 7 | -| 5.4.1.3 | - |
| `/etc/login.defs`: `UMASK` | - | 077 | - | UBTU-18-010448 |
| `/etc/pam.d/common-auth`: `pam_faildelay.so delay` | - | 4000000 | - | UBTU-18-010031 |
| `/etc/pam.d/common-auth`: `pam_tally2.so deny` | 5 | 3 | 5.3.2 | UBTU-18-010033 |
| `/etc/pam.d/common-password`: `pam_unix.so password` | sha512 | sha512 | 5.3.4 | UBTU-18-010110 |
| `/etc/pam.d/common-password`: `pam_unix.so, pam_pwhistory.so remember` | 5 | 5 | 5.3.3 | UBTU-18-010108 |
| `/etc/profile*`: `TMOUT` | 900 | 900 | 5.4.5 | UBTU-18-010402 |
| `/etc/profile*`: `umask` | 027 | - | 5.4.4 | - |
| `/etc/security/limits*`: `hard core` | 0 | - | 1.6.4 | - |
| `/etc/security/limits*`: `hard maxlogins` | - | 10 | - | UBTU-18-010400 |
| `/etc/security/pwquality.conf`: `dcredit` | -1 | -1 | 5.3.1 | UBTU-18-010102 |
| `/etc/security/pwquality.conf`: `dictcheck` | - | 1 | - | UBTU-18-010113 |
| `/etc/security/pwquality.conf`: `difok` | - | 8 | - | UBTU-18-010103 |
| `/etc/security/pwquality.conf`: `enforcing` | - | 1 | - | UBTU-18-010116 |
| `/etc/security/pwquality.conf`: `lcredit` | -1 | -1 | 5.3.1 | UBTU-18-010101 |
| `/etc/security/pwquality.conf`: `minlen` | 14 | 15 | 5.3.1 | UBTU-18-010109 |
| `/etc/security/pwquality.conf`: `ocredit` | -1 | -1 | 5.3.1 | UBTU-18-010145 |
| `/etc/security/pwquality.conf`: `ucredit` | -1 | -1 | 5.3.1 | UBTU-18-010100 |
| `/etc/ssh/sshd_config`: `Ciphers` | chacha20-poly1305\@openssh.com,aes256-gcm\@openssh.com,aes128-gcm\@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr | aes128-ctr,aes192-ctr,aes256-ctr | 5.2.13 | UBTU-18-010411 |
| `/etc/ssh/sshd_config`: `ClientAliveCountMax` | 0 | 1 | 5.2.16 | UBTU-18-010415 |
| `/etc/ssh/sshd_config`: `ClientAliveInterval` | 300 | 600 | 5.2.16 | UBTU-18-010415 |
| `/etc/ssh/sshd_config`: `KexAlgorithms` | curve25519-sha256,curve25519-sha256\@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256 | - | 5.2.15 | - |
| `/etc/ssh/sshd_config`: `LoginGraceTime` | 60 | - | 5.2.17 | - |
| `/etc/ssh/sshd_config`: `MACs` | hmac-sha2-512-etm\@openssh.com,hmac-sha2-256-etm\@openssh.com,hmac-sha2-512,hmac-sha2-256 | hmac-sha2-256,hmac-sha2-512 | 5.2.14 | UBTU-18-010417 |
| `/etc/ssh/sshd_config`: `MaxAuthTries` | 4 | - | 5.2.7 | - |
| `/etc/ssh/sshd_config`: `MaxSessions` | 4 | - | 5.2.23 | - |
| `/etc/ssh/sshd_config`: `MaxStartups` | 10:30:60 | - | 5.2.22 | - |
| `/etc/sssd/conf.d/*.conf`: `offline_credentials_expiration` | - | 1 | - | UBTU-18-010030 |
| `/etc/sysctl*`: `fs.suid_dumpable` | 0 | - | 1.6.4 | - |
| `/etc/sysctl*`: `kernel.randomize_va_space` | 2 | 2 | 1.6.2 | UBTU-18-010514 |
| `/etc/sysctl*`: `net.ipv4.conf.all.accept_redirects` | 0 | - | 3.2.2 | - |
| `/etc/sysctl*`: `net.ipv4.conf.all.accept_source_route` | 0 | - | 3.2.1 | - |
| `/etc/sysctl*`: `net.ipv4.conf.all.log_martians` | 1 | - | 3.2.4 | - |
| `/etc/sysctl*`: `net.ipv4.conf.all.rp_filter` | 1 | - | 3.2.7 | - |
| `/etc/sysctl*`: `net.ipv4.conf.all.secure_redirects` | 0 | - | 3.2.3 | - |
| `/etc/sysctl*`: `net.ipv4.conf.all.secure_redirects` | 0 | - | 3.2.3 | - |
| `/etc/sysctl*`: `net.ipv4.conf.all.send_redirects` | 0 | - | 3.1.1 | - |
| `/etc/sysctl*`: `net.ipv4.conf.default.accept_redirects` | 0 | - | 3.2.2 | - |
| `/etc/sysctl*`: `net.ipv4.conf.default.accept_source_route` | 0 | - | 3.2.1 | - |
| `/etc/sysctl*`: `net.ipv4.conf.default.log_martians` | 1 | - | 3.2.4 | - |
| `/etc/sysctl*`: `net.ipv4.conf.default.rp_filter` | 1 | - | 3.2.7 | - |
| `/etc/sysctl*`: `net.ipv4.conf.default.secure_redirects` | 0 | - | 3.2.3 | - |
| `/etc/sysctl*`: `net.ipv4.conf.default.secure_redirects` | 0 | - | 3.2.3 | - |
| `/etc/sysctl*`: `net.ipv4.conf.default.send_redirects` | 0 | - | 3.1.1 | - |
| `/etc/sysctl*`: `net.ipv4.icmp_echo_ignore_broadcasts` | 1 | - | 3.2.5 | - |
| `/etc/sysctl*`: `net.ipv4.icmp_ignore_bogus_error_responses` | 1 | - | 3.2.6 | - |
| `/etc/sysctl*`: `net.ipv4.ip_forward` | 0 | - | 3.1.2 | - |
| `/etc/sysctl*`: `net.ipv4.tcp_syncookies` | 1 | 1 | 3.2.8 | UBTU-18-010500 |
| `/etc/sysctl*`: `net.ipv6.conf.all.accept_ra` | 0 | - | 3.2.9 | - |
| `/etc/sysctl*`: `net.ipv6.conf.all.accept_redirects` | 0 | - | 3.2.2 | - |
| `/etc/sysctl*`: `net.ipv6.conf.all.accept_source_route` | 0 | - | 3.2.1 | - |
| `/etc/sysctl*`: `net.ipv6.conf.all.forwarding` | 0 | - | 3.1.2 | - |
| `/etc/sysctl*`: `net.ipv6.conf.default.accept_ra` | 0 | - | 3.2.9 | - |
| `/etc/sysctl*`: `net.ipv6.conf.default.accept_redirects` | 0 | - | 3.2.2 | - |
| `/etc/sysctl*`: `net.ipv6.conf.default.accept_source_route` | 0 | - | 3.2.1 | - |
| `/etc/systemd/coredump.conf`: `ProcessSizeMax` | 0 | - | 1.6.4 | - |
| `/etc/systemd/coredump.conf`: `Storage` | none | - | 1.6.4 | - |
| `/etc/systemd/timesyncd.conf`: `RootDistanceMaxSec` | 1 | - | 2.2.1.2 | - |

## Ubuntu 20.04

### Documents

[Canonical Ubuntu 20.04 LTS Security Technical Implementation Guide Version: 1 Release: 1](https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cunix-linux)

[CIS Ubuntu Linux 20.04 LTS Benchmark v1.1.0](https://www.cisecurity.org/cis-benchmarks/#ubuntu_linux)

### Comparison Table

_Rule_ is the configuration file and configuration option.\
_CIS_ is the CIS Benchmark value.\
_DISA_ is the DISA STIG value.\
_CIS RN_ is the the CIS Recommendation Number.\
_STIG-ID_ is the STIG-ID value.

A value of `-` means that the setting wasn't metioned in the
document.

| Rule | CIS | DISA | CIS RN | STIG-ID |
| :--- | :-: | :--: | :----: | :-----: |
