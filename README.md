# Linux hardening practice system

The default launcher uses deterministic rules and local evidence, with **no AI API calls or API key required**. It is a practice tool, not a guarantee of full credit on an unfamiliar image. Package updates and some evidence lookups still use the network.

## Run inside the practice Linux VM

Take a snapshot and read the image README and forensic questions. From this repository folder:

```bash
sudo env CP_NO_AI=1 bash start.sh --readme /path/to/image-README.html
```

Or run `sudo bash start.sh` and paste the complete image README when prompted. Use the image's README, not this repository's README. `setup.sh` is the optional legacy AI configuration wizard and is not needed for the default path.

Use the VM console and the normal image administrator account with sudo. The launcher protects that operator account, but other users, passwords, services, files, and security settings can change. Preserve a snapshot and evidence before running.

## What happens

1. Parse and validate explicit README account/service requirements. Unrecognized account-list content or inconsistent parsed actions stop remediation.
2. Save a bounded anomaly audit and run deterministic forensic solvers before cleanup. Unresolved questions stop the pipeline for manual investigation. A written answer is not proof that it scored.
3. Run the hardening modules, preserving required services and the operator account. Failures are recorded even if later modules succeed.
4. Run Sentinel to apply supported checks and list ambiguous findings for review. Interactive runs monitor continuously; redirected/noninteractive runs do one pass.

`CP_NO_AI=1` is the default even when saved API credentials exist. Unknown SSH keys and SSH services absent from the README require review. The score tracker observes scores; it does not launch speculative hardening based on missing points.

## Results and exit codes

Inspect `data/auto-results.tsv`, the run logs, `data/forensics-det.json`, forensic backups under `data/forensics-det-backups/`, and the official image scoring report. A normal noninteractive completion returns:

- `0`: automated work completed with no reported failure or outstanding Sentinel review.
- `1`: an execution/validation/module failure occurred.
- `2`: manual review or unresolved forensics requires attention.

These codes do not certify a complete security assessment or 100% score. Parser validation compares against the deterministic extractor; it cannot establish that arbitrary natural-language requirements were understood correctly. Some legacy hardening policies remain broad and may conflict with unusual image requirements.

The OS gate recognizes Mint 21–23, Ubuntu 22/24/25, and Debian 12/13. Recognition is not end-to-end validation: the earlier full live practice test used System Hardening 7 on Ubuntu 22.04; later changes have focused automated verification. This Linux tool does not handle Windows, Cisco/Packet Tracer, FreeBSD, or every round-specific challenge.

## Practice and competition rules

The [official rules book](https://www.uscyberpatriot.org/rules-book/) controls competition use. CP19 section 3010.4 prohibits AI-created programs during competition, including programs created before the round. Turning off AI calls does not change the program's authorship. Treat this AI-assisted revision as practice material.

The [official challenge table](https://www.uscyberpatriot.org/challenges-and-scoring-values/) varies by round, division, and tier. Always use the current image README and round instructions; do not assume an SH7 result transfers to another image.

## Optional legacy AI features

Legacy AI modules remain in the source for separately configured practice experiments. `CP_NO_AI=0` explicitly opts out of the default block. Historical documentation is preserved in [docs/LEGACY_AI_WORKFLOW.md](docs/LEGACY_AI_WORKFLOW.md), but its old launch instructions and safety/coverage claims do not describe the current default pipeline.

Based on [gobbler56/cp-linux-auto](https://github.com/gobbler56/cp-linux-auto), with local hardening and validation changes. See [docs/UPSTREAM_README.md](docs/UPSTREAM_README.md) for upstream documentation.

## Coverage and conservative policies

See [the researched coverage inventory](docs/COVERAGE.md) for supported families, partial coverage and missing cases. The kernel baseline preserves unrelated settings, IPv6 and forwarding roles. Existing aggressive settings from older versions require manual review or a clean snapshot. Firewall planning uses standard declared-service ports and stops on unknown/dynamic services or conflicting global denies. Custom ports, source-specific ACLs and application connectivity still require validation. Use the VM console; sudo can remove SSH connection metadata.

## Round 1 reliability fixes

The Mint 21 update path now restores the official repositories for the installed
Mint codename before refreshing APT, including Ubuntu security/updates/backports.
The first changed copy is retained with `.before-round1-fix`. Additional repository
files are preserved. Review image requirements before using this practice tool.

Full update mode permits new dependencies (including kernels), refuses package
removals, preserves modified configuration files, upgrades installed critical apps,
and updates existing system/user Flatpak installations. Failed downloads, upgrades,
or remaining updates cannot be reported as fully up to date. Reboots remain manual.

Native Mint automation and supported refresh/app-update preferences replace guessed
schema keys. Startup refresh is 10 minutes, subsequent refreshes every two hours;
Flatpak and Cinnamon spice automatic updates are enabled. The dconf defaults and
locks are readable despite the runner's private umask. Ubuntu Jammy security and
update origins are explicitly allowed by unattended-upgrades on Mint 21.

MATE now receives five-minute screen locking alongside GNOME/Cinnamon. An explicit
README instruction to block Chromium pop-ups generates a managed policy instead of
editing live browser Preferences. Check chrome://policy after reload/restart;
conflicting policies and image scoring still require live verification.

Pasted user lists accept password-label lines and end at Competition Guidelines.
`--skip-forensics` now skips both solvers by explicit request; use only after saving
and verifying your answers. Scoring remains the authority, not module PASS statuses.

Validation uses offline fixtures and Linux command stubs, not the scored image.
The final Round 1 five-point check was never confirmed and is not claimed solved.
Schema reference: https://github.com/linuxmint/mintupdate/blob/master.mint21/usr/share/glib-2.0/schemas/com.linuxmint.updates.gschema.xml

## Required-service verification and later-round investigation

See [later-round reliability](docs/LATER_ROUND_RELIABILITY.md) for SSH rollback and
access preservation, final required-service/configuration checks, capability/ACL
and disguised-file investigation, NFS/SNMP indicators, and verification boundaries.
Read `data/postflight.txt` alongside module results and the official score. A review
or failure is now propagated instead of being hidden behind a module success log.
