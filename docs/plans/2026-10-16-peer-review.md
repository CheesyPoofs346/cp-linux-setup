# Peer review and main-account protection

Goal: require an independent model review against complete source material and protect the invoking non-root account during unattended remediation.

1. Pin GLM Flash worker and Nemotron Super reviewer, require different model IDs, and fail closed on missing/invalid reviewer output. No permanence or accuracy guarantee.
2. Review forensic drafts and collected evidence before answer writes. Review the full README, forensic report, and actual module source before allowing remediation; require coverage of all README sections and exact input hashes.
3. Exclude legacy account/PAM/SSH/home policy changes from unattended execution. Capture the sudo user's identity/privileges/home metadata. Wrap remediation in a private mount namespace with identity/PAM/sudo files and the home tree read-only, except runner data; drop mount capabilities and check the account after each module.
4. Offline regression tests for approvals, fabricated/missing section coverage, same-model reviewer, main-user mutations, and fail-closed guards. Root mount protection and actual NVIDIA reviews require a disposable Linux VM test.
