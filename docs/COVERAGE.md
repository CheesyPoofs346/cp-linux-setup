# Public training research and Linux coverage

Reviewed 2026-10-23. This is a coverage inventory, not a complete CyberPatriot rubric or a promise of full score. Public released practice material and original simulator/scorer documentation informed the family list. Active-round answers and gated coach/dashboard material were not accessed.

**Implemented** means a bounded policy exists with focused tests; **partial** means selected cases exist; **review** needs an image-specific decision; **missing** has no complete implementation; **outside-linux** requires other tooling. No label means universal safe remediation. Sources describe task families; implementation assessments come from this repository, not those sources.

Coverage totals: partial: 44, review: 4, implemented: 3, missing: 4, outside-linux: 3. Total: 58 families.

| Vulnerability/task family | Coverage | Implementation | Boundary / next action |
|---|---|---|---|
| README accounts, roles and hires | partial | [lib/readme_extract.py](../lib/readme_extract.py) | Explicit supported headings/lists; arbitrary narrative remains ambiguous. |
| Unauthorized users and administrator membership | partial | [modules/user_auditing.sh](../modules/user_auditing.sh) | Operator account protected; system/service accounts and unusual identity providers need review. |
| Extra UID 0 accounts and account anomalies | partial | [lib/sentinel.py](../lib/sentinel.py) | Local account checks; domain/LDAP identity is not covered. |
| Supplementary groups and role changes | partial | [modules/user_auditing.sh](../modules/user_auditing.sh) | README-derived local policy; custom groups may need review. |
| Password changes, empty passwords and aging | partial | [modules/account_policy.sh](../modules/account_policy.sh) | Broad local policy; authentication must be checked on the target image. |
| PAM quality and password history | partial | [modules/account_policy.sh](../modules/account_policy.sh) | Module availability and PAM order differ by distribution and release. |
| PAM bypass and authentication tampering | partial | [lib/sentinel.py](../lib/sentinel.py) | Known patterns; arbitrary malicious modules and control-flow changes are not fully detected. |
| Login lockout and failure counters | partial | [modules/local_policy.sh](../modules/local_policy.sh) | Legacy tally2 versus faillock differences need image-specific validation. |
| Guest login, autologin and desktop locking | partial | [modules/os_settings.sh](../modules/os_settings.sh) | Display managers and desktops differ; only SH7 desktop has live evidence. |
| Sudoers privilege and NOPASSWD policy | partial | [modules/security_policy.sh](../modules/security_policy.sh) | Custom delegation needs requirements review and syntax validation. |
| SSH daemon configuration | partial | [modules/ssh_hardening.sh](../modules/ssh_hardening.sh) | Includes operator safeguards; settings, Match blocks and authentication must be validated live. |
| SSH authorized keys | review | [lib/sentinel.py](../lib/sentinel.py) | Unknown keys require an ownership/authorization decision; no blind deletion. |
| SSH ports and remote operator preservation | partial | [lib/firewall_policy.py](../lib/firewall_policy.py) | Preserves declared connection port when SSH_CONNECTION is supplied; sudo may strip it. Use VM console. |
| FTP security and passive data ports | partial | [modules/ftp_hardening.sh](../modules/ftp_hardening.sh) | Control port known; passive ranges and TLS/application behavior need explicit configuration. |
| Apache web-server settings | partial | [modules/apache_hardening.sh](../modules/apache_hardening.sh) | Generic directives do not validate applications, virtual hosts or certificates. |
| nginx settings | partial | [modules/nginx_hardening.sh](../modules/nginx_hardening.sh) | Absent service skipped; complex site configurations require review. |
| PHP settings | partial | [modules/php_hardening.sh](../modules/php_hardening.sh) | Absent PHP skipped; version and application compatibility remain image-specific. |
| PostgreSQL authentication and permissions | partial | [modules/postgres_hardening.sh](../modules/postgres_hardening.sh) | Generic hardening can affect extensions/apps; no universal database application test. |
| MySQL/MariaDB security | partial | [modules/mysql_hardening.sh](../modules/mysql_hardening.sh) | Actual credentials, grants and application connectivity need verification. |
| Samba share security | partial | [modules/samba_hardening.sh](../modules/samba_hardening.sh) | Custom share ACLs, domain roles and client access need review. |
| DNS and mail-server settings | partial | [modules/extra_hardening.sh](../modules/extra_hardening.sh) | Selected directives and standard firewall ports; not complete DNS/mail deployment validation. |
| NFS/RPC server roles | review | [lib/firewall_policy.py](../lib/firewall_policy.py) | Dynamic/unknown service requirements stop firewall planning; exports and RPC roles require manual review. |
| SNMP communities and access control | review | [lib/firewall_policy.py](../lib/firewall_policy.py) | Standard port mapping is not SNMP authentication or community hardening. |
| Required-service preservation | partial | [lib/utils.sh](../lib/utils.sh) | Aliases/dependencies guarded; running service does not prove end-to-end reachability. |
| Prohibited packages and services | partial | [modules/unwanted_software.sh](../modules/unwanted_software.sh) | Known lists and README exceptions; custom binaries and disguised packages can remain. |
| OS and security package updates | partial | [modules/os_updates.sh](../modules/os_updates.sh) | SH7 update/reboot evidence exists for an earlier revision; repositories and failures vary. |
| APT sources and trust | partial | [modules/extra_hardening.sh](../modules/extra_hardening.sh) | Selected source/security checks; not complete repository-signature provenance verification. |
| UFW defaults, required ports and conflicting rules | partial | [lib/firewall_policy.py](../lib/firewall_policy.py) | Unknown services/global conflicting denies stop for review. Source-specific ACLs and live connectivity are not certified. |
| IPv6, forwarding and router/server roles | review | [lib/kernel_policy.py](../lib/kernel_policy.py) | Preserved for compatibility; role-specific values must come from image requirements. |
| Conservative kernel protections | implemented | [lib/kernel_policy.py](../lib/kernel_policy.py) | Ten supported keys, write/readback verification and backups; not a complete sysctl policy. |
| Account/system file ownership and modes | partial | [modules/os_settings.sh](../modules/os_settings.sh) | Selected paths; custom ownership and mount semantics can differ. |
| Log directory permissions | implemented | [modules/os_settings.sh](../modules/os_settings.sh) | Corrects /var/log root directory to root:root 0755; does not certify every log file ACL. |
| SUID/SGID executables | partial | [lib/sentinel.py](../lib/sentinel.py) | Selected findings; unusual legitimate executables and arbitrary binaries need review. |
| World-writable files/directories | partial | [modules/os_settings.sh](../modules/os_settings.sh) | Broad checks are not a safe universal permission policy for application data. |
| POSIX ACL abuse | missing | — | No complete ACL inventory/remediation policy; inspect getfacl and legitimate access requirements. |
| File capability abuse | missing | — | No complete getcap inventory or application-aware setcap remediation. |
| Immutable attributes | partial | [modules/malware.sh](../modules/malware.sh) | Selected handling; legitimate immutable settings and unusual files need review. |
| Hosts mappings and local name resolution | implemented | [modules/os_settings.sh](../modules/os_settings.sh) | Preserves custom mappings and adds missing localhost/hostname entries; malicious mappings still require review. |
| Cron persistence | partial | [lib/sentinel.py](../lib/sentinel.py) | Known suspicious command patterns; arbitrary benign-looking jobs need investigation. |
| systemd units, timers and user autostart | partial | [lib/anomaly_audit.py](../lib/anomaly_audit.py) | Bounded evidence inventory; arbitrary persistence is not automatically classified. |
| LD preload and injected libraries | partial | [modules/malware.sh](../modules/malware.sh) | Known/missing suspicious entries; not a complete rootkit detector. |
| Shell aliases and startup hijacks | partial | [lib/sentinel.py](../lib/sentinel.py) | Known alias/startup patterns; obfuscation and application launchers can evade rules. |
| Unexpected listeners and processes | partial | [lib/anomaly_audit.py](../lib/anomaly_audit.py) | Inventory is evidence, not proof of maliciousness; no automatic universal kill policy. |
| Web shells and malicious scripts | partial | [modules/malware.sh](../modules/malware.sh) | Pattern-based detection; arbitrary obfuscated application code requires analysis. |
| Package integrity and altered binaries | partial | [modules/malware.sh](../modules/malware.sh) | Selected checks; no comprehensive trusted reinstallation of every modified executable. |
| Prohibited media/files | partial | [modules/prohibited_files.sh](../modules/prohibited_files.sh) | Requirements and forensic evidence determine whether deletion is appropriate. |
| Explicit file hash and Base64 forensics | partial | [lib/forensics_det.py](../lib/forensics_det.py) | Bounded named-file tasks tested; arbitrary transformations and evidence layouts are not supported. |
| Hidden-user and UID forensic questions | partial | [lib/forensics_det.py](../lib/forensics_det.py) | Supported deterministic templates; not arbitrary natural-language question solving. |
| PAM/backdoor forensic questions | partial | [lib/forensics_det.py](../lib/forensics_det.py) | Answers require unique supported evidence; ambiguity stops before cleanup. |
| IP attribution and historical timelines | partial | [lib/forensics_det.py](../lib/forensics_det.py) | Some evidence lookups; current DNS is not historical proof. Multi-log timelines require investigation. |
| Memory, encrypted evidence, steganography and multi-stage forensics | missing | — | No general solver; preserve evidence and investigate manually. |
| Bootloader/GRUB settings | partial | [modules/os_settings.sh](../modules/os_settings.sh) | Image-specific boot and recovery requirements can conflict with generic policy. |
| AppArmor profiles | partial | [modules/defensive_countermeasures.sh](../modules/defensive_countermeasures.sh) | Generic enforcement does not prove application compatibility or complete profile coverage. |
| Audit and system logging | partial | [modules/defensive_countermeasures.sh](../modules/defensive_countermeasures.sh) | Selected enablement; not a complete audit policy or remote log validation. |
| Custom applications, CMS, TLS and business configuration | missing | — | No universal safe application policy; derive from README and vendor documentation. |
| Windows and Active Directory | outside-linux | — | This repository is Linux-only; Windows/AD need separate tooling and training. |
| FreeBSD | outside-linux | — | Linux shell/module assumptions do not cover FreeBSD. |
| Cisco networking and Packet Tracer | outside-linux | — | Separate networking challenge and configuration workflow. |

## What changed in this revision

- Consolidated two conflicting sysctl profiles into one owned ten-key baseline. Back up changed configuration, preserve unrelated settings, check supported keys, propagate write failures, verify runtime values. Do not disable IPv6, forwarding or user namespaces by default.
- Preserve hosts mappings and make log-directory permissions 0755 instead of world writable through recursive `+X`/write changes.
- Plan standard required-service firewall ports before mutation. Stop on unknown/dynamic services, undeclared operator SSH, or conflicting global deny/reject rules. Preserve declared operator SSH connection port when available; propagate command failures and verify IPv6 settings.

**Migration:** previous aggressive settings already applied by an older revision are not automatically reversed. Restore a clean snapshot for an independent evaluation; review existing sysctl files and runtime values if upgrading in place. Existing source-specific firewall ACLs are preserved and require connectivity review. Use the VM console because sudo/launchers can strip SSH_CONNECTION.

## Evidence and practical limits

The current revision passed 200 Python tests (one root-only test skipped in the unprivileged suite), shell syntax/help, and the runner/parser/extra-hardening/README-paste checks. Archive verification is recorded separately in the release test log. The earlier SH7 full run reached 96/100 and all five forensic answers scored; that is earlier-revision evidence, not proof that this revision scores 96 or an unfamiliar image reaches 100. No Windows, FreeBSD, Cisco or cross-distribution full-system test is claimed.

Prioritize manual investigation of ACL/capability abuse, custom apps, unusual authentication/service roles and multi-stage forensics. Generic cleanup must not replace evidence preservation or requirements validation.

## Public primary-source catalog

- **T1: [Official CyberPatriot public training materials](https://www.uscyberpatriot.org/training-materials/)** — Official category/resource index; not a complete current-round rubric. Public materials only.
- **T2: [Official archived training modules](https://www.uscyberpatriot.org/archived-training-modules/)** — Historical Ubuntu training is useful for concepts; old PAM commands are not current portable instructions.
- **P1: [PySEL original practice scoring configuration](https://github.com/FWSquatch/pysel/blob/master/PySEL.conf)** — Generic author-released practice checks; not an official CyberPatriot answer key.
- **A1: [Aeacus original check documentation](https://github.com/elysium-suite/aeacus/blob/master/docs/checks.md)** — Scorer check capabilities, not evidence that every check appears in a round.
- **S1: [Aperture Science original practice bundle](https://github.com/anishgoyal1108/Aperture-Science-Practice-Image-Bundle)** — Author describes difficult practice images. External VM/key links were not downloaded or independently verified.
- **S2: [CyberPatriot Toolkit original Linux test harness](https://github.com/Ripper1004/CyberPatriot-Toolkit/blob/main/tests/linux/run-tests.sh)** — Public test source reference; its distribution-matrix claims were not independently executed here.
- **K1: [Linux kernel sysctl documentation](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html)** — Upstream meaning and compatibility caveats for kernel settings.
- **K2: [Linux kernel IP sysctl documentation](https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html)** — Networking role dependence; do not blindly apply a desktop policy to routers.

Official training resources may link answer keys for released exercises; no current active-round key was obtained. Community practice images are independent author material and their difficulty/score claims are not official classifications. Kernel documentation supports setting semantics, not CyberPatriot scoring requirements.
