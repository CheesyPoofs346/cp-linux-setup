# What CyberPatriot actually scores (and where this repo handles it)

Source: the CP-18 Round 2 answer sheet (Mint 21 image) plus community checklists and backdoor slides.
Mint 21 round 2 category counts: User Auditing 7, OS Updates 4, Unwanted Software 3, App Updates 2,
Forensics 2, and 1 each of Account Policy, App Security, Defensive Countermeasures, Local Policy,
Prohibited Files, Service Auditing, Uncategorized OS Settings.

| Scored item (CP-18 R2, Mint 21) | Handled by |
|---|---|
| Guest account disabled | `user_auditing.sh` `disable_guest_account`, `account_policy.sh` greeter |
| Unauthorized users removed | `user_auditing.sh` `remove_unauthorized_users`, `sentinel.py` (review) |
| User X is not an administrator | `user_auditing.sh` `manage_admin_privileges`, `sentinel.py` `extra-admin` |
| Insecure password changed | `user_auditing.sh` `fix_insecure_passwords` + `rotate_authorized_passwords` |
| New admin account created, must change password at next login | `user_auditing.sh` `create_missing_users` (`passwd -e`); rotation keeps the expiry |
| Minimum password length | `account_policy.sh` pwquality + PAM |
| IPv4 TCP SYN cookies | `extra_hardening.sh` `extra_sysctl_extra`, `os_settings.sh` |
| UFW enabled | `defensive_countermeasures.sh` |
| Insecure FTP root permissions | `extra_hardening.sh` `extra_ftp_root` |
| OpenSSH disabled or removed (README never mentions SSH) | `sentinel.py` `ssh-not-needed` (auto) |
| Update list refreshed automatically / update manager installs automatically / security updates | `os_updates.sh` Mint update-manager config |
| systemd / Chromium / vsftpd updated | `os_updates.sh` full upgrade |
| Prohibited MP3 files | `prohibited_files.sh` |
| Prohibited software (aMule, Wireshark, Zangband) | `sentinel.py` `BAD_PACKAGES` |
| FTP users may log in with SSL | `ftp_hardening.sh` `ssl_enable=YES` |

Backdoor slides (Linux): `ss -antpl` listeners, `/proc/<pid>/exe`, cron dirs, `/etc/pam.d` rules that skip
authentication, planted SSH keys, odd `sshd_config` policy. Sentinel covers each: listener kill
(`backdoor-listener`), cron lines (`cron-line`), PAM (`pam-backdoor` auto, `pam-suspect` review), keys
(`ssh-key`), plus autostart entries, web shells, root-equivalent groups and sudo grants.

Penalties to avoid (README critical services, your own account, `PasswordAuthentication no` without keys,
purging a package that drags out the desktop) are enforced by README protection, the protected-account
guard, SSH password-auth preservation when no key exists, and `_purge_collateral` (simulates `apt-get -s purge`).
