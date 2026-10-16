# One-command runner implementation plan

Goal: provide a noninteractive runner with explicit provider selection and source-validated account lists. No claim of a guaranteed image score.

Architecture: keep existing module order, add a preflight that parses and validates the supplied README before system mutations, isolate module execution, and fail on failed modules. Preserve existing interactive operation. NVIDIA uses the existing OpenAI-compatible request interface.

1. Add stdlib HTML/JSON account-and-service validation with regression tests for omitted users and changed administrator roles.
2. Add --auto, --readme and --readme-url, an explicit unsupported-OS override, bounded module execution, noninteractive update selection, and truthful failure/review reporting.
3. Add NVIDIA configuration, bounded API requests, and a useful API connectivity check without tiny generation budgets.
4. Preserve SSH port 22 by default and require an installed/public key before auto SSH changes. Keep AI-selected file/package/malware cleanup out of unattended execution until reviewed.
5. Test offline with shell syntax checks, mocked modules/API calls, and validator fixtures. Publish source and instructions without keys or local paths. Linux VM remediation and NVIDIA live calls remain unverified.
