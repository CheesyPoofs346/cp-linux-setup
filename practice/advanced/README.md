# Advanced Linux practice lab

Original Ubuntu 24.04 server scenario, researched against public competition materials.
This is a Linux training component, not an official image or a reproduction of
unpublished Finals scoring. See [research and limits](RESEARCH.md).

## What makes it difficult

66 independently evaluated security checks, ten business-availability penalties,
and a separate four-check onboarding inject. SSH, nginx, PostgreSQL and Samba
must retain authenticated access and ledger data. nginx proxies a custom service
using a non-login system identity and PostgreSQL peer authentication. Blindly
replacing configuration, deleting low-UID identities, or blocking unknown services
can break the business even while improving individual settings.

Fault families include conditional SSH overrides, sudo/PAM, automatic package
refresh/install, PostgreSQL effective overrides and excessive privileges, SMB
guest/group permissions, shadow ACLs, copied SUID/capability programs, inert
cron/timer/user-session persistence, a disguised ELF, and log-based forensics.
Seeds change identities and configuration structure, including SSH User versus
Group Match, nginx included versus inline location rules, and database overrides.
The markers do not attack another machine or execute a malicious payload.

The grader imports no remediation helpers. Public reports reveal completed checks
and availability; the private JSON is for coaches. Erroring probes do not earn
credit. No scored check is disabled just because the hardener misses it.

## Ready-made VM

Use the supplied OVA or VMware VM folder. Start a copy on NAT, with shared folders
and bridging disabled. Take a snapshot before working. Read
`/home/cpoperator/Desktop/README.md` and the forensic question first.

Synthetic console login: `cpoperator` / `Practice-Only-Lab-Admin!42`.
Initial synthetic staff/admin passwords: `Practice-Only-17!Secure` for seed 17.
The supplied image intentionally contains insecure settings; use only as a lab.
The score page is `http://GUEST-IP/scoring-report.html`, refreshed every 30 seconds.
Get the address with `ip -4 -brief addr` at the guest console.

The guest is server-only: MATE/Cinnamon/browser policy is not exercised here.
The grading files are under `/root/coach`; do not read their checks before a blind
practice run. The normal hardener is distributed separately so it cannot consume
the private rubric accidentally.

## Rebuild a separate seeded VM

Windows build prerequisites: VMware Workstation, Python 3.11+, `pycdlib`, OpenSSH.
The builder verifies the official cloud image SHA256 and refuses an existing VM
or disk path. It does not change host networking or security settings.

```powershell
python practice/advanced/vmware_lab.py build --directory C:\Labs\cp-seed28
python practice/advanced/vmware_lab.py upload --directory C:\Labs\cp-seed28
```

Inside that newly created disposable guest, provision exactly once:

```bash
sudo python3 /opt/cp-linux-setup/practice/advanced/provision.py --seed 28 --i-understand-this-is-a-disposable-vm
sudo python3 /opt/cp-linux-setup/practice/advanced/score.py --seed 28 --output /root/baseline.json
```

Provisioning refuses an unmarked host, an unexpected hostname, or a previously
provisioned VM. Do not run it on an existing machine. Shut down before taking a
baseline snapshot. Do not rewrite a VMX after snapshots; clone the cold baseline
when testing another seed and configure its own DHCP identity.

## Evaluate the hardener

After a baseline, configure the hardener's documented practice-only unattended
options, protect the operator identity, and run against the scenario README.
Record the exit status, independent score, ledger access and external probes.
Return code 2 means review remains; it is not an all-clear.

```bash
sudo python3 practice/advanced/inject.py --seed 28 --issue
sudo bash start.sh --readme /home/cpoperator/Desktop/README.md
sudo python3 practice/advanced/score.py --seed 28 --output /root/after.json
sudo python3 practice/advanced/inject.py --seed 28 --score --output /root/inject.json
```

Reboot and repeat the independent checks. `network_probe.py` belongs on a separate
observer VM on the private lab network. Pin the target SSH host key; supply a lab
key authorized for cpoperator. It checks real HTTP/API, SSH, SMB and local-only DB
exposure rather than relying on localhost or daemon process state.

`coach_reference.py` is explicitly fixture-specific manual remediation for a
reviewed synthetic scenario. It is never imported by the hardener. Preserve the
automated score first; a coach-assisted 100 is not an automated 100.

Results and remaining failures are documented with the delivered validation
artifacts. This lab alone cannot establish Windows, AlmaLinux, Cisco, Red Team,
desktop, multiple-server, or universal official-image readiness.
