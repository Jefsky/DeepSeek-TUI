# Security Policy

DeepSeek TUI is a coding agent with direct access to file operations, shell execution, and the network. Security disclosures are taken seriously.

## Supported Versions

Only the latest stable release receives security patches. No backports to older versions.

| Version | Supported |
|---|---|
| latest stable | :white_check_mark: |
| < latest | :x: |

Check the [releases page](https://github.com/Hmbown/DeepSeek-TUI/releases) for the current version.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately using **GitHub Security Advisories** (preferred):

- [Report a vulnerability](https://github.com/Hmbown/DeepSeek-TUI/security/advisories/new)

Repository owners can also enable **Private vulnerability reporting** under **Settings → Code security** on GitHub, which lets reporters open a private channel without a public issue.

An email Contact field was previously listed here; it was **not reliably deliverable**. Please use the advisory flow above. If you cannot access GitHub Security Advisories, contact the maintainers through a **verified** channel they publish on their GitHub profile or organization (do not send exploit details via public issues).

Include in your report:

- A description of the vulnerability and the impact if exploited
- Steps to reproduce or a proof of concept
- Affected versions and configuration details
- Any suggested mitigation (optional)

## Response Timeline

| Phase | Target |
|---|---|
| Acknowledgment | Within 48 hours of receipt |
| Assessment | Within 5 days — triage severity, scope, and fix approach |
| Patch (critical) | Within 14 days from assessment |
| Patch (moderate/low) | Next feature release or per-maintainer timeline |
| Disclosure | After patch is shipped and users have had time to update |

You will receive status updates at each phase. If the timeline slips, we will communicate the reason and the revised estimate.

## Scope

### In scope (what counts)

- Remote code execution through crafted prompts or model responses
- Sandbox escape — breaking out of the YOLO-mode workspace boundary or shell `cwd` confinement
- Credential leak — exfiltration of API keys, tokens, or environment secrets
- Arbitrary file read/write outside the intended workspace (`PathEscape` bypass)
- SSRF via `fetch_url` or `web_search` against internal network endpoints
- Unauthorised MCP server access or tool invocation

### Out of scope

- Social engineering of the maintainer or contributors
- Denial of service / rate-limit exhaustion against the DeepSeek API
- Vulnerabilities in third-party dependencies (report to the upstream project)
- Attacks requiring physical access to the victim's machine
- Theoretical ML-model injection attacks not demonstrated in the DeepSeek TUI context

If you are unsure whether a bug is in scope, report it anyway. We will triage and respond.

## Hall of Fame

We maintain a hall of fame for reporters who submit verified security vulnerabilities. To be credited, include your preferred name / handle in the report.

*No entries yet — be the first.*
