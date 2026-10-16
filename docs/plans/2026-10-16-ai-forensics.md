# AI forensics implementation plan

Goal: discover questions, gather bounded read-only evidence, and fill evidence-backed answers before remediation, using the selected OpenRouter/NVIDIA provider.

1. Replace arbitrary root shell execution with structured file listing/reading/search, strings, hashes, metadata, and process/socket inspection. Reject unknown tools and shell requests.
2. Discover multi-digit questions with/without .txt and in desktop subfolders. Back up originals, retain hashes, reject changed files before writes, preserve encoding/newlines/permissions, and never trust model-provided write paths.
3. Require successful evidence-tool citations with exact quotes and answer text supported by those quotes before auto-fill. Save all responses and unresolved reasons; never equate model confidence or writes with scoring acceptance.
4. Run forensics before mutating modules. Pause auto remediation when questions are unresolved or required files are absent. Provide explicit standalone forensics-only usage.
5. Test discovery, shell rejection, bounded reads, secret/symlink exclusion, fabricated evidence, missing answers, changed originals, CRLF/permissions, and real fake-HTTP end-to-end behavior. No live NVIDIA or scoring claims.
