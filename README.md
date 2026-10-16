# Linux competition practice setup

Short link to this repository: [bit.ly/cp-linx](https://bit.ly/cp-linx) (also [bit.ly/4eA37uw](https://bit.ly/4eA37uw)).

## Quick setup: two commands

Once downloaded, open Terminal in this repository folder as your normal user:

```bash
bash setup.sh
```

It asks for your NVIDIA API key with hidden input, the image README URL/local HTML file, and an optional forensic-question directory. It offers to install missing prerequisites, and asks explicitly before allowing an unsupported-OS experiment. Worker/reviewer models are preset. The setup saves private, Git-ignored files with mode 600; it does not start remediation.

Then take a VM snapshot and run:

```bash
sudo bash start.sh
```

The second command uses your saved setup and starts the protected, independently reviewed pipeline. Run it from the same normal account used for setup. Your OS may ask for your sudo password. All review/protection stops and manual-review limits below still apply. Missing questions, unsupported requirements, or rejected reviews do not become automatic success.

To change the key or README, rerun `bash setup.sh`. A blank key input retains a previously saved NVIDIA key. Existing private settings are backed up to `config.local.conf.previous`; known timeout/update/forensics settings are retained. Do not share these private files.

### Read-only anomaly/backdoor audit

Auto mode saves an anomaly audit before forensic investigation, so the report remains available even if forensics stop the run. You can also run it independently, without an API key or remediation:

```bash
sudo bash audit.sh
```

Reports are saved in `data/audit/<run-id>/report.txt` and `report.json`, with `data/audit/latest.json` for the latest machine-readable report. Checks cover extra UID-0 accounts, accounts absent from a validated README, login-enabled system users, cron/systemd/autostart/shell persistence indicators, world-writable access/startup configs, library preloads, passwordless-sudo indicators, authorized-key inventories, unusual set-ID locations, temporary executables, deleted running executables, listening sockets, process names, services, timers, and a bounded `dpkg -V` package-integrity snapshot.

Findings mean **investigate this**, not **confirmed malware**. Legitimate installers, package updates, and required services can produce indicators. Nothing is deleted, disabled, quarantined, or permission-changed by the audit. The independent reviewer receives finding summaries alongside the README; raw config excerpts and command inventories remain local.

Auto mode defers the broad package-integrity scan until forensics finish, then refreshes the report before peer review. Standalone `audit.sh` also defers it by default; after preserving forensic evidence, use `sudo bash audit.sh --package-check` to include it. Ordinary package reads can affect access-time evidence.

This is a bounded heuristic audit, not an exhaustive compromise assessment. File walks stop after 20 seconds/20,000 entries; config reads, command outputs, and command runtimes are limited. Reports include skipped/error/partial-coverage notes. Private keys/password hashes are not collected, but local snippets may contain other sensitive information—do not upload whole reports publicly.

Based on [gobbler56/cp-linux-auto](https://github.com/gobbler56/cp-linux-auto), snapshot `4c51f0d`, with an updated runner, README validation, NVIDIA support, and setup instructions. This is an independent repository. Original documentation is in [docs/UPSTREAM_README.md](docs/UPSTREAM_README.md); its behavior descriptions may differ from this updated runner.

Targets **Ubuntu 24.x** and **Linux Mint 21.x**. Run these commands inside the Linux VM.

## Before starting

Take a practice VM snapshot. Read the image README and its forensic questions before making changes. Check your competition rules on scripts and external AI: this tool sends README/question/evidence content to the configured provider.

**This modifies the machine.** User auditing can delete users and home directories and change passwords. Interactive mode is not a preview. The runner no longer rewrites APT sources automatically at startup. No score or unattended completion of arbitrary image requirements is guaranteed.

## 1. Download

```bash
sudo apt-get update
sudo apt-get install -y git curl jq python3
git clone https://github.com/CheesyPoofs346/cp-linux-setup.git
cd cp-linux-setup
chmod +x cp-engine.sh
```

## 2. Configure

Create an API key at [NVIDIA Build](https://build.nvidia.com/z-ai/glm-5-3-flash), then:

```bash
cp config.conf config.local.conf
chmod 600 config.local.conf
nano config.local.conf
```

The NVIDIA worker and independent reviewer are preconfigured. Paste your NVIDIA key into this line:

```bash
NVIDIA_API_KEY="paste-your-own-key-here"
```

Save with **Ctrl+O**, **Enter**, then exit with **Ctrl+X**.

```bash
chmod 600 config.local.conf
```

Never upload your populated config or share the key.

`config.local.conf` is ignored by Git and overrides the tracked defaults, so normal updates do not overwrite your key. Existing installations can copy their populated `config.conf` to this private file before updating.

### NVIDIA worker and independent reviewer

In `config.local.conf`, select NVIDIA explicitly:

```bash
AI_PROVIDER="nvidia"
NVIDIA_API_KEY="paste-your-own-nvidia-key-here"
NVIDIA_MODEL="z-ai/glm-5.3-flash"
REVIEWER_MODEL="nvidia/nemotron-3-super-120b-a12b"
```

The shared NVIDIA endpoint is `https://integrate.api.nvidia.com/v1/chat/completions`; that URL is not a model ID. Both [GLM Flash](https://build.nvidia.com/z-ai/glm-5-3-flash) and [Nemotron Super](https://build.nvidia.com/nvidia/nemotron-3-super-120b-a12b) were listed with available free prototype endpoints and no deprecation notice shown on October 16, 2026. This is not a promise of future availability or comparative accuracy. The worker and reviewer must be different models. A missing/deprecated model, quota error, malformed review, or disagreement stops the pipeline; there is no silent model/provider fallback. Live NVIDIA inference has not been verified here.

### One-command mode

After configuration, use either a local README or an HTTPS URL. The runner attempts forensics before remediation:

```bash
sudo bash ./cp-engine.sh --auto --readme /path/to/image-README.html
# Alternatively:
sudo bash ./cp-engine.sh --auto --readme-url https://example.org/image-readme.html
```

Replace the example path/URL with your image's actual README. URLs are per-run inputs, not published image defaults. Unsupported systems are refused unless you explicitly add `--allow-unsupported` for a disposable test. This does not make Ubuntu 22.04 a fully supported platform.

- Parses and independently checks explicit HTML authorized-administrator/user and critical-service lists before remediation. Missing users, changed roles, unknown formats, or additional AI account actions stop the run. A stronger model does not bypass validation.
- Sends the full original README, section list, forensic results, and proposed module/shared-library source to the separate reviewer. Each README section must receive a source quote and a covered/manual disposition. Approval is bound to the exact review input; only proposed modules explicitly approved by the reviewer can run. Oversized review input is refused rather than truncated. Providing full text and checking coverage does not prove a model understood every instruction.
- Investigates forensic questions before mutating modules. If questions cannot be found, need review, or fail, remediation stops. Read the forensics section below for auto-fill limits and evidence/backup locations.
- Starts each module in its own process to isolate its globals and readonly variables. The first nonzero module exit or timeout stops subsequent modules. Existing modules can still contain internal errors that they do not report correctly; a PASS only reflects their exit status.
- Uses `AUTO_UPDATE_MODE=1` by default (APT configuration only). Set `AUTO_UPDATE_MODE=2` for a package upgrade within the current release. Neither option performs a distribution release upgrade.
- Leaves AI-driven malware commands and package/file removals for manual review. These are not silently approved.
- Excludes legacy `user_auditing`, `account_policy`, `os_settings`, and SSH changes from unattended execution, in addition to AI-directed cleanup. They can change account identity, PAM/login policy, permissions, or access and require a separate reviewed implementation. Reviewer approval cannot override these exclusions. Manual/interactive runs of those legacy modules do not receive auto-mode protection.
- Requires launching with `sudo` from the account to protect. A direct root launch must set `PROTECTED_USER` to the intended non-root login account. Snapshots its UID/GID, groups, shell, home ownership/mode, and local fingerprints of account/login policy. Mismatches stop the run; no automatic broad rollback is attempted.
- Executes approved remediation in a private mount namespace: identity databases, sudo/PAM/security policy and the protected home tree are read-only, with only runner `data/` writable for reports. Mount/ptrace/raw-I/O/immutable capabilities are dropped before the module starts. Unsupported namespace creation or a failed read-only mount stops execution. These are direct-write protections for the trusted scripts, not a sandbox guarantee against arbitrary malicious root code or a substitute for a VM snapshot. Actual root mount enforcement still needs a disposable VM test.
- Writes module results to `data/auto-results.tsv`: exit **0** means selected modules reported success, **1** means failure, and **2** means manual review remains. Filled forensic answers and image-specific requirements still need checking in the official scoring report.

HTTP requests have a configurable `AI_TIMEOUT_SECONDS` limit (default 180 seconds); module processes have an `AUTO_MODULE_TIMEOUT` limit (default 1800 seconds). There are no automatic API retries that consume additional quota.

### AI forensic questions

Forensics uses GLM Flash as the default NVIDIA worker and Nemotron Super as a separate reviewer. The worker receives the full original README with each question; the reviewer receives that same README, question, proposed answer, and collected evidence before any answer is written. Evidence matching and independent approval are both required. These are documented available free prototype endpoints, not a benchmarked claim of the best pair for these tasks.

To investigate forensics without starting other remediation:

```bash
sudo bash ./cp-engine.sh -m forensics_questions
```

Forensics-only runs also need the image README: add `--readme /path/to/README.html`, or use a cached `data/auto-source.html` from auto mode. A missing README pauses answers rather than letting the worker guess without it.

Discovery searches user Desktops and question subfolders up to two levels deep. It recognizes multi-digit question numbers, case-insensitive `.txt` files, and extensionless files. If files are elsewhere, set `FORENSICS_DIR="/actual/question/directory"` in your private config. HTML, documents, remote links, and localized desktop directories require explicit preparation or a directory override.

The AI gets bounded read-only tools for directory/file searches, text, literal searches, printable strings, SHA-256, metadata, process names, and listening sockets. No AI-written shell commands are executed. Runner files, common credential/private-key paths, symlinks, special files, and files above the read limit are excluded. These restrictions can leave some questions unresolved. Approved question/evidence content is sent to the selected external AI provider.

Each question defaults to twelve AI exchanges (`FORENSICS_MAX_ROUNDS`, configurable from 1 to 24) with at most four evidence requests per exchange; work is sequential to reduce bursts. A rejected draft gets concrete validation feedback so the worker can follow another clue or correct its evidence citations. Repeated identical rejected drafts stop instead of looping indefinitely. Provider quotas and module/API timeouts can still interrupt it. Binary reads/hashes are limited to 2 MB; output per tool is limited to 12,000 characters. Structured path resolution, file-type checks, and package ownership queries are available without shell execution.

`FORENSICS_APPLY_ANSWERS=1` is the default. Auto-fill requires every answer to appear verbatim in a successful tool-output quote, valid citations, the model explicitly declining manual review, and exactly as many existing `ANSWER:` placeholders as answers. Confidence alone is insufficient. Computed/transformed answers, missing placeholders, fabricated citations, or uncertain results remain manual. A valid citation still does not prove semantic correctness or scoring acceptance.

Original question files are backed up before replacement, checked for intervening edits, and retain their newline style, permissions, and owner. Evidence reads request Linux no-atime access when permitted; this is not a forensic disk-image acquisition tool. Set `FORENSICS_APPLY_ANSWERS=0` for drafts only; auto remediation then pauses for review.

Results, AI rounds, reviewer decisions, evidence records, and original backups are saved under `data/forensics/<run-id>/`. Review `results.json` and the official scoring report: `FILLED_UNVERIFIED_SCORE` means a file was filled, not that an answer scored. Put special image formatting rules in `FORENSICS_IMAGE_NOTES` in your private config; the tool never hardcodes a particular practice image.

Unfinished investigations retain partial answers and the AI's explicitly unverified hypothesis, plus leads pointing to successfully inspected/discovered evidence paths. `summary.txt` provides a readable handoff; terminal output shows the exact blocker and up to three evidence locations. These are investigation leads, not confirmed answers or backdoors. Failed tool requests do not become evidence. The audit remains an additional part of normal auto mode; you do not need to run a separate read-only command. Cleanup stays paused if unresolved questions could lose evidence.

An evidence-backed final answer is forwarded to the reviewer immediately, even if the worker also asks for unnecessary additional tools. When the investigation budget is reached after a tool result, one dedicated synthesis call uses that final output with further tools disabled. This prevents losing a valid answer merely because the worker kept requesting commands; evidence validation and independent review still apply.

GLM requests use JSON-object output mode. The parser accepts one complete JSON object wrapped in explanatory text/fences and excludes completed reasoning blocks. Ambiguous, malformed, truncated, or output-budget-exhausted responses are rejected. Private raw response diagnostics are saved with mode 600 under `data/ai-responses/`; request authorization headers are never saved. These files can contain forensic evidence, so do not publish them wholesale.

Live access check on October 16, 2026: the configured key received final text from GLM Flash and Nemotron 3 Super. Nemotron Ultra returned HTTP 404 despite its catalog page showing available, so it is not the reviewer default. These small connectivity probes do not validate reasoning accuracy or full image behavior. The key is not included in this repository.

### Optional OpenRouter for standalone modules

Reviewed auto mode requires NVIDIA. Standalone modules can still use `AI_PROVIDER="openrouter"` and `OPENROUTER_API_KEY` in your private config. Forensic answer reviews also require a different reviewer model available on the selected provider; the default reviewer ID is NVIDIA-specific.

The optional `OPENROUTER_MODEL="openrouter/free"` selects from available free models, filtering for supported request features. Selection is random within eligible models, so this does not guarantee the strongest model or consistent quality. Always verify parsed users and services before remediation. See [the free router documentation](https://openrouter.ai/openrouter/free).

According to [OpenRouter pricing](https://openrouter.ai/pricing), checked October 16, 2026:

| Account | Free-model request limit |
| --- | --- |
| No credit purchase required | 50 requests/day |
| At least $10 in credits purchased | 1,000 requests/day |
| Both | Up to 20 requests/minute |

These limits are shared across free models. Switching models or creating another API key on the same account does not increase the daily quota. Provider capacity can also limit availability. Buying credits is optional; requests to this free router have zero model inference cost. Do not replace it with `openrouter/auto`, which can select paid models.

If you hit a usage limit, wait for quota availability rather than repeatedly rerunning modules. The API test also makes a request. This repository has not benchmarked free-model accuracy or tested the router on a competition image.

## 3. Check setup

```bash
./cp-engine.sh -c
./cp-engine.sh -t
./cp-engine.sh -l
```

These check compatibility/dependencies, test the API, and list modules. Resolve errors before continuing. An API test does not prove remediation works.

## 4. Parse the image README

```bash
sudo ./cp-engine.sh -m readme_parser
less data/readme_parsed.json
```

Compare users, admins, and required services against the actual image README. Press **Q** to exit. If parsing fails, the image has no README, or the results are wrong, stop before user auditing.

## 5. Run one module at a time

```bash
sudo ./cp-engine.sh -i
```

Enter a numbered module to run it. Enter **q** to quit. Check the official scoring report and required services after each module.

For your first test, avoid **a** (run all). Running `sudo ./cp-engine.sh` with no options also runs everything.

## Logs and reset

```bash
sudo less /var/log/cyberpatriot/score.log
sudo ls /var/backups/cyberpatriot
```

The action log is separate from official scoring. File backups do not fully undo account deletion, package changes, or other system changes. Restore your practice VM snapshot to reset.

## Troubleshooting

- API errors: check your key, model, internet connection, and OpenRouter limits.
- README not found: check the image README location. The parser searches standard CyberPatriot/Aeacus paths and desktop README.html files.
- Unsupported OS: use Ubuntu 24.x or Mint 21.x for this snapshot.

The runner has offline regression tests and mocked AI/evidence tests. Live NVIDIA inference, complete Linux-image remediation, and scoring acceptance have not been verified here.
