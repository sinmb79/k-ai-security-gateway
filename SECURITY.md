# Security Policy

## Supported Status

K-AI Security Gateway is currently an MVP release candidate. Security reports are
welcome, but the project should be treated as evaluation software until production
identity, deployment, and data-retention controls are added.

## Reporting a Vulnerability

Please report security issues privately before opening a public issue.

If this repository is owned by an organization, use that organization's preferred
security contact. If no contact is published, create a GitHub issue with a minimal
non-sensitive description and request a private coordination channel. Do not include
real secrets, live customer records, credentials, private prompts, or exploit payloads
that expose third-party systems.

Helpful report contents:

- Affected version or commit
- Component or endpoint
- Reproduction steps using synthetic data
- Expected impact
- Suggested fix or mitigation, if known

## Sensitive Data Handling

Do not commit:

- Real API keys or provider tokens
- Admin or approver tokens
- `.env` files
- SQLite audit stores
- Raw prompts containing personal data or confidential business data
- Customer documents or generated evidence packages from real environments

The repository intentionally ignores common runtime data paths, including `.env`,
`.env.*`, `data/`, `*.sqlite3`, logs, generated artifacts, and local worktrees.

## Production Hardening Checklist

Before using this project in a real environment, add or verify:

- SSO/OIDC or equivalent identity integration
- Role-based access control for admin and approval actions
- TLS and network access controls
- Secrets management outside environment files
- Audit retention and deletion policy
- Encrypted storage for raw prompts or separate evidence vault design
- Provider allowlists and egress restrictions
- Backup, restore, and tamper-evidence verification procedures
- Red-team tests for prompt injection, document injection, and response leakage

## Disclaimer

Generated reports and evidence packages are review aids. They do not replace a formal
security audit, legal review, privacy impact assessment, or compliance certification.
