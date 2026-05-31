# Security Policy

## Supported Versions

Security fixes are provided for the latest released series only.

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |
| < 1.0.0 | No |

## Reporting a Vulnerability

Please report suspected security vulnerabilities privately through GitHub Security Advisories for this repository.

1. Go to the repository Security tab.
2. Choose Report a vulnerability.
3. Include clear reproduction steps, affected version, and expected impact.

If private reporting through GitHub is unavailable, open a normal issue with minimal detail and request a private contact channel.

## What to Include

- Affected component and version
- Reproduction steps or proof of concept
- Attack preconditions and expected impact
- Any suggested mitigation

## Response Targets

- Initial triage response: within 5 business days
- Status update after triage: within 10 business days
- Fix timeline: depends on severity and release constraints

## Disclosure Policy

- Do not publicly disclose vulnerabilities until a fix or mitigation is available.
- Coordinated disclosure is preferred.
- Public advisories are published after remediation and release.

## Scope Notes

This policy covers code in this repository, including:
- Host process and transport bridge
- IDA-side plugin script and RPC handlers
- Tool dispatch, schema handling, and generated tool metadata

Third-party dependencies and upstream platforms are handled through their maintainers.
