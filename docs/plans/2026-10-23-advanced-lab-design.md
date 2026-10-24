# Advanced practice VM design

Approved: full Ubuntu 24.04 VM, independent approximately 60-check scorer, multiple seeds, required SSH/web/database/file sharing, persistence and privilege faults, forensics, availability penalties.

The lab is an original advanced training scenario, not an official or reproduced unpublished competition image. Difficulty comes from interacting services, preserving business data and valid access, effective configuration checks, misleading defaults, and evidence preservation. A high check count alone is not evidence of competition equivalence.

VMware NAT guest, no shared folders or bridged adapters; synthetic accounts and inert persistence markers only. Download an official Ubuntu cloud VMDK and verify SHA256 before boot. No vulnerabilities are installed on the host or existing machines.

The provisioner creates a scenario README and seeded faults. An independent read-only scorer uses effective settings and functional probes; it does not import remediation helpers. Preserve a baseline snapshot, score before and after remediation, restart services/reboot, and repeat on a second seed. Missing dependencies and probe errors are failures or explicit unverified results, never passing scores.

Required services: OpenSSH, nginx, PostgreSQL, Samba. Data canaries and valid user access must survive. Forensics is answered before remediation. Target coverage includes accounts, sudo, PAM, update sources/automation, SSH Match overrides, web exposure, database and share access, firewall, ACL/capability privilege, inert cron/systemd persistence, and desktop policy where installed.

Research: official CyberPatriot training describes Windows/Linux VM security plus a separate Cisco challenge. The public Aperture Science author describes 100 vulnerabilities per image and rates its difficulty between state and semifinals; that demonstrates count alone cannot establish Finals realism. Its repository is a stub, not a source rubric.

Sources:
- https://www.uscyberpatriot.org/competition/training-materials
- https://github.com/anishgoyal1108/Aperture-Science-Practice-Image-Bundle
- https://cloud-images.ubuntu.com/noble/current/

Acceptance: record baseline and after scores, functional service probes, second seed, regressions, remaining misses and elapsed time. Never promise an official 100 score.
