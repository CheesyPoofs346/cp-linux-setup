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

The OS gate recognizes Mint 21–23, Ubuntu 22/24/25, and Debian 12/13. Recognition is not end-to-end validation: the live practice testing for this revision uses System Hardening 7 on Ubuntu 22.04. This Linux tool does not handle Windows, Cisco/Packet Tracer, FreeBSD, or every round-specific challenge.

## Practice and competition rules

The [official rules book](https://www.uscyberpatriot.org/documents/rules-book) controls competition use. CP19 section 3010.4 prohibits AI-created programs during competition, including programs created before the round. Turning off AI calls does not change the program's authorship. Treat this AI-assisted revision as practice material.

The [official challenge table](https://www.uscyberpatriot.org/challenges-and-scoring-values/) varies by round, division, and tier. Always use the current image README and round instructions; do not assume an SH7 result transfers to another image.

## Optional legacy AI features

Legacy AI modules remain in the source for separately configured practice experiments. `CP_NO_AI=0` explicitly opts out of the default block. Historical documentation is preserved in [docs/LEGACY_AI_WORKFLOW.md](docs/LEGACY_AI_WORKFLOW.md), but its old launch instructions and safety/coverage claims do not describe the current default pipeline.

Based on [gobbler56/cp-linux-auto](https://github.com/gobbler56/cp-linux-auto), with local hardening and validation changes. See [docs/UPSTREAM_README.md](docs/UPSTREAM_README.md) for upstream documentation.
