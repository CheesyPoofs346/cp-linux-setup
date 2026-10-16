# Linux competition practice setup

Short link to this repository: [bit.ly/cp-linx](https://bit.ly/cp-linx) (also [bit.ly/4eA37uw](https://bit.ly/4eA37uw)).

Based on [gobbler56/cp-linux-auto](https://github.com/gobbler56/cp-linux-auto), snapshot `4c51f0d`, with an updated runner, README validation, NVIDIA support, and setup instructions. This is an independent repository. Original documentation is in [docs/UPSTREAM_README.md](docs/UPSTREAM_README.md); its behavior descriptions may differ from this updated runner.

Targets **Ubuntu 24.x** and **Linux Mint 21.x**. Run these commands inside the Linux VM.

## Before starting

Take a practice VM snapshot. Read the image README and finish evidence-dependent forensics before making changes. Check your competition rules on scripts and external AI: this tool sends README content and some other analysis inputs to OpenRouter.

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

Create an API key at [OpenRouter](https://openrouter.ai/settings/keys), then:

```bash
cp config.conf config.local.conf
chmod 600 config.local.conf
nano config.local.conf
```

The free-model router is already configured. **Only paste your API key** into this line; leave the model setting alone:

```bash
OPENROUTER_API_KEY="paste-your-own-key-here"
```

Save with **Ctrl+O**, **Enter**, then exit with **Ctrl+X**.

```bash
chmod 600 config.local.conf
```

Never upload your populated config or share the key.

`config.local.conf` is ignored by Git and overrides the tracked defaults, so normal updates do not overwrite your key. Existing installations can copy their populated `config.conf` to this private file before updating.

### NVIDIA (optional)

In `config.local.conf`, select NVIDIA explicitly:

```bash
AI_PROVIDER="nvidia"
NVIDIA_API_KEY="paste-your-own-nvidia-key-here"
NVIDIA_MODEL="nvidia/nemotron-3-super-120b-a12b"
```

Create the key using [NVIDIA's model page](https://build.nvidia.com/nvidia/nemotron-3-super-120b-a12b). Its documented endpoint is used directly. There is no fallback to another provider. NVIDIA describes this as a free prototype endpoint; check your account's current limits. Live NVIDIA inference and model accuracy have not been tested here.

### One-command mode

After configuration and forensics, use either a local README or an HTTPS URL:

```bash
sudo bash ./cp-engine.sh --auto --readme /path/to/image-README.html
# Alternatively:
sudo bash ./cp-engine.sh --auto --readme-url https://example.org/image-readme.html
```

Replace the example path/URL with your image's actual README. URLs are per-run inputs, not published image defaults. Unsupported systems are refused unless you explicitly add `--allow-unsupported` for a disposable test. This does not make Ubuntu 22.04 a fully supported platform.

- Parses and independently checks explicit HTML authorized-administrator/user and critical-service lists before remediation. Missing users, changed roles, unknown formats, or additional AI account actions stop the run. A stronger model does not bypass validation.
- Starts each module in its own process to isolate its globals and readonly variables. The first nonzero module exit or timeout stops subsequent modules. Existing modules can still contain internal errors that they do not report correctly; a PASS only reflects their exit status.
- Uses `AUTO_UPDATE_MODE=1` by default (APT configuration only). Set `AUTO_UPDATE_MODE=2` for a package upgrade within the current release. Neither option performs a distribution release upgrade.
- Leaves AI-driven malware commands and package/file removals for manual review. These are not silently approved.
- Leaves SSH unchanged unless you configure `SSH_TARGET_USER` and `SSH_PUBLIC_KEY_FILE` with the required public key. SSH defaults to port 22. Verify the image's authentication, forwarding, and key requirements yourself before enabling it.
- Writes module results to `data/auto-results.tsv`: exit **0** means selected modules reported success, **1** means failure, and **2** means manual review remains. Forensics and image-specific requirements still need checking in the official scoring report.

HTTP requests have a configurable `AI_TIMEOUT_SECONDS` limit (default 180 seconds); module processes have an `AUTO_MODULE_TIMEOUT` limit (default 1800 seconds). There are no automatic API retries that consume additional quota.

### Automatic free models and usage

The default `OPENROUTER_MODEL="openrouter/free"` automatically selects from available free models, filtering for supported request features. You do not need to choose a model. Selection is random within eligible models, so this does not guarantee the strongest model or consistent quality. Always verify parsed users and services before remediation. See [the free router documentation](https://openrouter.ai/openrouter/free).

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

The source has been inspected; it has not been runtime-tested in a Linux competition image here.
