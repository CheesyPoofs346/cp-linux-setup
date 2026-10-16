# Linux competition practice setup

Short link to this repository: [bit.ly/cp-linx](https://bit.ly/cp-linx) (also [bit.ly/4eA37uw](https://bit.ly/4eA37uw)).

All engine files from [gobbler56/cp-linux-auto](https://github.com/gobbler56/cp-linux-auto), snapshot `4c51f0d`, with setup instructions. This is an independent repository. Engine code is unchanged; original documentation is in [docs/UPSTREAM_README.md](docs/UPSTREAM_README.md).

Targets **Ubuntu 24.x** and **Linux Mint 21.x**. Run these commands inside the Linux VM.

## Before starting

Take a practice VM snapshot. Read the image README and finish evidence-dependent forensics before making changes. Check your competition rules on scripts and external AI: this tool sends README content and some other analysis inputs to OpenRouter.

**This modifies the machine.** User auditing can delete users and home directories and change passwords. Even interactive mode and individual-module runs rewrite APT sources before starting. Interactive mode is not a preview.

## 1. Download

```bash
sudo apt-get update
sudo apt-get install -y git curl jq
git clone https://github.com/CheesyPoofs346/cp-linux-setup.git
cd cp-linux-setup
chmod +x cp-engine.sh
```

## 2. Configure

Create an API key at [OpenRouter](https://openrouter.ai/settings/keys), then:

```bash
nano config.conf
```

Set these lines:

```bash
OPENROUTER_API_KEY="paste-your-own-key-here"
OPENROUTER_MODEL="openrouter/free"
```

Save with **Ctrl+O**, **Enter**, then exit with **Ctrl+X**.

```bash
chmod 600 config.conf
```

Never upload your populated config or share the key. The free router selects an available free model; usage limits and availability vary.

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
