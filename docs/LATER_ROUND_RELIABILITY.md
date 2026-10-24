# Later-round reliability and investigation

This revision expands local verification and investigation beyond the Round 1
update fixes. It does not encode an unpublished rubric or certify a future score.

## Changes that affect remediation

- SSH now installs an idempotent global prefix before existing Includes, preserves
  Match bodies, and retires its older owned snippet. Password authentication stays
  available unless `SSH_KEY_ONLY=1` is explicitly configured. Installing a key for
  one account no longer implicitly requires keys for every authorized user.
- A rejected `sshd -t` restores the previous main file and owned snippet, preserving
  modes. Reload failures propagate. Backups remain in the usual backup directory.
- Failed user-auditing steps no longer turn into an overall PASS. Independent steps
  still run, so one failed task does not skip subsequent checks/password fixes.
- AI-proposed hires, terminations and groups must match independently extracted
  README evidence. Automatic mode no longer authorizes invented account actions.
- Mint native refresh/app settings use supported schema keys. Origin selection
  follows the installed Ubuntu base (tested Jammy/Noble). Restoring official sources
  remains limited to recognized Mint 21 codenames; custom repository files remain.
- Generated APT configuration is world-readable. Commented cleanup defaults are
  replaced by an explicit owned override. ACL and capability inspection tools are
  dependencies; failed installation cannot be reported as success.
- A Python socket import alone no longer triggers the SSH-adjacent malware alert.
  Network/terminal-handoff indicators still appear for investigation. A failed
  SUID removal is no longer recorded as a successful remediation.

## Final report

After modules and Sentinel return, the runner executes `lib/postflight.py` and
writes `data/postflight.json` and `data/postflight.txt`. For an interim check while
the interactive monitor is running, use `sudo python3 lib/postflight.py`.

The report checks:

- Known README-required services are active and enabled; unknown units are REVIEW.
- Required Chromium/Firefox/office packages have installed status, not just dpkg
  residual configuration.
- Apache, nginx, Samba, BIND and ProFTPD syntax via their installed validators.
- PostgreSQL has an online cluster, rather than trusting an exited umbrella unit.
- Effective SSH settings in a local connection context for root and each authorized
  user; root/empty-password login, missing/locked accounts, key-only requirements,
  and access-list review are reported separately.
- Incomplete dpkg state, remaining upgrades, reboot requirements, UFW when required,
  and effective Mint refresh/Flatpak/spice settings and dconf access permissions.

FAIL returns exit 1. Ambiguity or review items return exit 2. Module failures remain
failures even when subsequent checks succeed. This verifies selected local state;
remote logins, application transactions, firewall reachability and client-address
Match rules still require appropriate live tests.

## Added investigation coverage

`lib/privilege_audit.py` runs after forensics, through the anomaly audit and final
report. It never executes found files or silently deletes evidence.

- Privileged file capabilities: UID/GID switching, DAC bypass, tracing, module
  loading and other selected privilege boundaries. Ordinary ping `cap_net_raw`
  alone is not classified as a privilege-bypass finding.
- Effective named ACL grants on selected sensitive configuration paths. ACL masks
  are honored, including distinguishing masked writes and readable shadow files.
- ELF magic under document/media extensions in bounded user/temporary walks.
- NFS exports with remote-root trust or wildcard write access.
- Default SNMP communities and community-based write access. Community secrets
  are not copied into findings.

These are review findings, not blanket malware verdicts. Required NFS clients,
legitimate capabilities, ACL delegation and SNMP managers must be preserved. Walk
budgets, missing tools and command errors are explicit coverage gaps, not a clean
result. No arbitrary capability or ACL is automatically stripped.

## Validation boundary

Ubuntu 22.04 WSL: 229 Python tests passed with one platform-specific skip; all five
shell suites passed. Fixtures cover SSH rollback, Match preservation, auth mode,
service health failures, locked accounts, offline PostgreSQL clusters, Mint
refresh readback, Jammy/Noble origins, source-validation-before-mutation, ACL masks,
capabilities, disguised files, NFS/SNMP indicators, and runner failure propagation.
GitHub Actions runs the same fixtures on Ubuntu 22.04 and 24.04.

The Round 1 scored VM was not rerun with this revision. Its last confirmed score
was 95; the final five-point check was never established. No 100-point or universal
later-round coverage claim follows from these tests.

Primary references:

- [Mint 21 update schema](https://github.com/linuxmint/mintupdate/blob/master.mint21/usr/share/glib-2.0/schemas/com.linuxmint.updates.gschema.xml)
- [Mint native automation](https://github.com/linuxmint/mintupdate/blob/master.mint21/usr/bin/mintupdate-automation)
- [Net-SNMP access-control configuration](https://www.net-snmp.org/docs/man/snmpd.conf.html)
