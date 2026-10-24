# Advanced practice VM implementation plan

**Goal:** Build and boot a reproducible advanced Ubuntu practice VM, independently score it, improve remediation from observed failures, and verify a second seed.

**Architecture:** VMware guest provisioned with cloud-init from a SHA256-verified official VMDK. Scenario generation and scorer live under practice/advanced; remediation remains in existing modules. Host transport uses VMware guest operations with synthetic lab credentials; a separate observer VM performs real SSH/network probes.

**Tech stack:** Python standard library, PowerShell, VMware Workstation, Ubuntu 24.04, cloud-init, OpenSSH.

1. Research official format and public author scenarios; document evidence boundaries and fault matrix.
2. Build download/hash/VMX/cloud-init bootstrap tooling; keep keys and virtual disks outside git.
3. Write failing tests for seed determinism, guardrails, score accounting, probe error handling and availability penalties.
4. Implement provisioner and independent scorer with roughly 60 substantive checks, plus README/forensic evidence.
5. Boot and provision first VM; capture baseline and guest identity. Snapshot before remediation.
6. Run actual script inside guest only; collect misses and functional failures; implement focused generic fixes with regression tests.
7. Reboot and independently rescore; verify required services and preserved data remotely.
8. Repeat with different seed; test that deliberate service/data sabotage loses credit.
9. Run existing unit and shell suites; save reproducible results and practical limits in outputs.
