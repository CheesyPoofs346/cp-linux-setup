# Measured advanced-lab results

Validated 2026-10-24 on original Ubuntu 24.04 server practice scenarios. These are
normalized practice scores, not official CyberPatriot scores or proof of Finals
readiness. Both seeds use the same independent 66-check security rubric and ten
availability checks. A separate observer performs six network probes.

| Case | Security score | Business penalties | Additional evidence |
|---|---:|---:|---|
| Vulnerable seed 17 | 28.79/100 (19/66) | 0 | Services/data working |
| Vulnerable seed 28 | 28.79/100 (19/66) | 0 | Different SSH/nginx/PostgreSQL layout |
| Automated seed 17 | 89.39/100 (59/66) | 0 | Fresh full run: 107 seconds, exit 2 |
| Automated seed 28 | 89.39/100 (59/66) | 0 | Full run completed, exit 2 |
| Seed 17 after reboot | 89.39/100 | 0 | Observer 6/6; onboarding 4/4 |
| Seed 28 after reboot | 89.39/100 | 0 | Observer 6/6; onboarding 4/4 |
| Seed 28 after coach review | 100/100 (66/66) | 0 | Fixture-specific manual remainder; NOT automated result |
| Imported vulnerable OVA | 28.79/100 | 0 | Boot, active scoring timer, all ten availability checks |

The 107-second measurement uses the already downloaded/current package state of
the lab snapshot. It does not predict first-time network downloads or every
competition image. The first onboarding pass independently measured 0/4 before
and 4/4 after the fresh seed-17 run. Subsequent reruns retained all four checks.

## Remaining automated misses

- PostgreSQL staff role remains superuser.
- PUBLIC retains CREATE on the public schema.
- Unauthorized root cron and system timer remain.
- Unauthorized shell-startup marker and user-session unit remain.
- Disguised ELF remains executable pending forensic quarantine review.

These seven misses are retained in the scorer. The normal hardener does not call
`coach_reference.py` or import the private rubric. Unknown persistence and
application/database privilege changes require an analyst decision rather than
fixture-name-specific automated deletions.

## Failures found and corrected

Live VM runs exposed business configuration replacement, deletion of valid
non-login service identities, conditional SSH exceptions, incorrect README
service parsing, a stopped update timer, and firewall planning blocked by a
verified local-only backend. Corrections preserve application paths, peer login,
SMB group access and data while checking effective service settings.

Independent review found an HBA token replacement bug, nginx inherited security
headers suppressed by a new server header, and negative scorer probes that could
turn execution errors into credit. All three were corrected and regression tested.

The reboot gate then found legacy GRUB GPG enforcement without detached signatures
or trusted key setup. It prevented the test guest from rebooting. The script now
preserves boot trust and administrator credentials for manual review; both seeds
subsequently booted successfully. The failed state is retained in a lab snapshot.

The scorer's absent-timer case was corrected to recognize systemd's explicit
`not-found` state (exit 4), while still rejecting permission/command errors. The
same corrected scorer was rerun on vulnerable, automated and coach states.

## Scorer failure tests

Stopping nginx produced 47 business penalty points and a score of 36.33/100.
Temporarily removing the SMB ledger produced 40 penalty points and 49.39/100.
Restoring the service/file returned 89.39/100 and zero penalties. Probe errors
receive no credit. These tests demonstrate failure detection, not complete
resistance to a root user's deliberate scorer tampering.

## Verification and limits

The local suite runs Python regressions plus five shell/orchestration suites.
The delivered validation directory retains raw JSON, logs, observer results,
onboarding results and boot/import evidence. An independent read-only reviewer
checked the service, privilege, firewall, account, SSH and boot-policy corrections.

This is a server VM, not a MATE/Cinnamon desktop or a complete competition network.
It does not validate Windows, AlmaLinux, Cisco, real Red Team activity, every
service configuration, browser policies or official hidden scoring. The exported
image is deliberately vulnerable and uses documented synthetic lab credentials.
