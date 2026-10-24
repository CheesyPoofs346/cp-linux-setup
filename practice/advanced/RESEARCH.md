# Advanced lab research and scope

This is an original training lab for the Linux administration portion of a hard
round. It is not an official image, an unpublished answer key, or a claim of
equivalence to a complete national final. A single Ubuntu guest cannot reproduce
multiple operating systems, Cisco, a professional Red Team or the full event.

## Evidence that drives the design

- [Official CP17 Finals program](https://www.uscyberpatriot.org/Documents/CP17_Program_2025_web.pdf)
  describes small-business infrastructure, maintaining services, controlled Red
  Team attacks and scenario injects. This supports scoring business continuity
  separately from configuration improvements. It does not disclose a Linux rubric.
- [Official CP18 season history](https://www.uscyberpatriot.org/Pages/Competition/Season%20History/CyberPatriot-18.aspx)
  describes the master challenge and the introduction of Alma Linux at Finals.
  Ubuntu-only validation therefore cannot establish complete Finals readiness.
- [Aperture practice image author's README](https://github.com/anishgoyal1108/Aperture-Science-Practice-Image-Bundle)
  describes 100 vulnerabilities per image, rates difficulty between state and
  semifinals, and explicitly says the repository contains no source. We use this
  as author testimony about practice scale, not an inspected official rubric.
- [Aeacus original project](https://github.com/elysium-suite/aeacus)
  demonstrates an independent remediation scoring system. Our scorer does not
  depend on the hardener's logs or reported success, and is not CCS or Aeacus.

## Technical mechanisms checked against primary documentation

| Mechanism | Training consequence | Primary source |
|---|---|---|
| SSH first obtained settings and conditional Match | Inspect the effective result for each required identity; changing one global line is insufficient | [sshd_config](https://man.openbsd.org/sshd_config) |
| PostgreSQL configuration precedence and ALTER SYSTEM | Check running server settings and preserve peer authentication for the application | [PostgreSQL 16 configuration](https://www.postgresql.org/docs/16/config-setting.html) |
| Samba share configuration and reload semantics | Test a new authenticated connection and an anonymous connection; preserve share data | [Samba smb.conf](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html) |
| nginx locations, roots and proxy behavior | Verify URLs, hidden-file protection and API availability, not merely nginx process state | [nginx core](https://nginx.org/en/docs/http/ngx_http_core_module.html) |
| NoCloud seed media | Boot a real isolated guest reproducibly, without installing faults on the host | [Canonical NoCloud](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html) |

The planted faults are our design inference from those mechanisms and public
competition descriptions. They are not claims that a particular official round
contains these exact faults.

## Challenge contract, independent of current hardener coverage

1. Account legitimacy, hidden UID zero identity, group membership and sudo rules.
2. Nonempty authentication, aging, password quality/history and lockout.
3. Effective SSH policy including conditional exceptions, without losing access.
4. Package source health, automatic list refresh and security installation,
   timer state and package manager consistency.
5. nginx exposure, secret-file denial, permissions and security response headers.
6. PostgreSQL least privilege, HBA rules, effective settings and retained data.
7. Samba guest restrictions, protocol policy, authenticated access and group rights.
8. Inert cron/systemd/user-session persistence, SUID, interpreter capabilities,
   ACL grants and disguised executables, with forensic evidence preserved first.
9. Kernel policy and working audit service.
10. Availability penalties for SSH/web/database/share/API failures, deleted ledger
    data, broken authorized file access or broken authenticated SMB access.

No checks may be removed or weakened merely because remediation fails them.
Corrections to an invalid check must be documented and the same corrected scorer
must be run on baseline and hardened states. A second seed must change at least
configuration structure as well as identity names before it counts as a useful
generalization test. Challenge score, hardener return code, external service
availability and official score compatibility are separate results.


## Reboot finding

The [GNU GRUB signature documentation](https://www.gnu.org/software/grub/manual/grub/html_node/Using-GPG_002dstyle-digital-signatures.html)
explains that check_signatures=enforce requires detached signatures and trusted
public keys for files GRUB loads. The legacy script injected enforcement without
establishing that trust material. Live reboot validation failed; removing the
lab-injected setting restored boot on the second seed. The revised policy
preserves boot trust settings and administrator credentials for manual review.
