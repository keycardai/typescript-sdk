# Security policy

Keycard sits in the credential path of every tool call an agent makes. A flaw in these packages is a flaw in someone's authorization boundary, so we treat reports here as high priority and we would rather hear about a maybe than miss a real one.

## Reporting a vulnerability

Do not open a public issue, pull request, or discussion for a security problem.

Use either channel:

- **GitHub private vulnerability reporting (preferred).** Go to the Security tab of this repository and open a private advisory. This keeps the report, our triage, and the eventual public advisory in one place.
- **Email security@keycard.ai.** If you want to encrypt, say so in a first message with no details and we will send you a key.

You do not need a working exploit to report something. A clear description of the flawed logic is enough.

Before you write it up, the platform's security model, token lifetimes, encryption scheme and threat model are documented in the [security architecture reference](https://docs.keycard.ai/reference/security-architecture/). It will tell you which behaviours are deliberate.

## What to include

The more of this you have, the faster we can act:

- Which package and version (including @keycardai/oauth, @keycardai/mcp, @keycardai/express, @keycardai/a2a, @keycardai/cloudflare, @keycardai/eve, @keycardai/langchain, @keycardai/cursor-agent-sdk, and @keycardai/sdk)
- Node version, the Express version, and the @modelcontextprotocol/client or @modelcontextprotocol/server version in use
- What an attacker gains: which token, whose data, which scope they should not have had
- The smallest reproduction you can manage, ideally a script or a failing test
- Whether the issue needs a specific configuration or middleware order, and which

Please test against a zone you control. Do not probe other tenants' zones or use credentials that are not yours.

## What happens next

| Stage | Our commitment |
| --- | --- |
| Acknowledgement | Within 3 business days |
| Initial assessment and severity | Within 10 business days |
| Fix or documented mitigation | Target 30 days for high and critical severity |
| Public advisory | When the fix ships, or 90 days from your report, whichever comes first |

If we need longer than 90 days we will tell you why and agree a date with you rather than let the clock run out silently. If we conclude something is not a vulnerability we will explain the reasoning, and you are welcome to argue with it.

## Scope

### In scope for this repository

Anything that lets a caller obtain, keep, or use authority it should not have. Concretely:

- **Token validation.** Accepting an expired, unsigned, or wrong-algorithm token. Failing to check aud, iss, or the resource indicator. JWKS handling that trusts the wrong key.
- **Token exchange (RFC 8693).** Scope escalation across an exchange, subject and actor confusion, a delegation chain that is dropped, forged, or not verifiable downstream. In @keycardai/a2a, an agent card that can steer a per-hop exchange somewhere it should not go.
- **Bearer auth and scope enforcement.** A request reaching a protected route without a valid token, or with a token missing the required scope. requireBearerAuth or AuthProvider.grant() granting authority the policy did not permit. A middleware order that a reasonable reader would expect to be safe but is not.
- **Fail-open on a failed exchange.** accessContext reports failures rather than throwing, so a handler that skips hasErrors() carries on with a missing or failed grant. Anything in the SDK, its examples, or its docs that makes that the path of least resistance is in scope, as is a case where hasErrors() returns false while a grant actually failed.
- **Authorization server metadata.** Anything in mcpAuthMetadataRouter or the .well-known handling that enables an authorization server mix-up.
- **Credential exposure.** Client secrets, access tokens, or refresh tokens appearing in logs, stack traces, error responses, or a serialized request object. Token cache entries readable across tenants or requests.
- **Insecure defaults.** A configuration that most users will reach for and that is weaker than it appears.
- PKCE, state, and nonce handling that permits replay, fixation, or cross-session confusion.

### Report to us, but not as a repository advisory

Issues in the hosted platform, the zone gateway, Keycard STS, Vault, or the Console, are not defects in this source tree. Email security@keycard.ai and say it concerns the hosted service. We will route it and keep you updated the same way.

### Out of scope

- Findings that presuppose an already-compromised host, root access, or a client secret the attacker somehow holds
- Documented design choices, unless you can show one is exploitable. Token lifetimes, refresh token reuse, and the fifteen minute data encryption key cache are described in the security architecture reference and were chosen deliberately
- Vulnerabilities in dependencies with no exploitable path through this SDK. Report those upstream, and tell us so we can pin or patch
- Missing security headers or TLS configuration on documentation sites, with no demonstrated impact
- Rate limiting or resource exhaustion without a concrete, realistic attack
- Scanner output, including npm audit results, with no analysis of exploitability
- Social engineering of Keycard staff, contributors, or customers

## Supported versions

These packages are on different major versions: @keycardai/mcp and @keycardai/sdk are on 2.x and the others are on 0.x.

Security fixes land on the latest published release of each package. We do not backport to earlier minors or majors, with one exception: @keycardai/mcp and @keycardai/sdk 1.x also get security fixes on npm's legacy dist-tag, from the release/mcp-v1 maintenance line described in [MCP_RELEASES.md](MCP_RELEASES.md). If you are pinned to an older release and cannot move, say so in your report and we will discuss options with you.

Node 18 or greater is supported.

## Coordinated disclosure

We publish fixed vulnerabilities as GitHub Security Advisories on this repository, and request a CVE where one is warranted.

You get credit in the advisory under whatever name or handle you choose, or no credit if you prefer. Tell us which.

We do not currently run a paid bug bounty.

**Safe harbour.** If you make a good-faith effort to follow this policy, we will not pursue or support legal action against you. Good faith means you do not access, modify, or exfiltrate data belonging to anyone else, you do not degrade the service for other users, you stop at the point where you have demonstrated the problem, and you give us a reasonable chance to fix it before going public.

## Regulatory reporting

Keycard Labs, Inc. may be obliged under Article 14 of Regulation (EU) 2024/2847, the EU Cyber Resilience Act, to notify ENISA and a national CSIRT within 24 hours of becoming aware that a vulnerability in one of our products is being actively exploited.

Those notifications describe the vulnerability and the affected products. They do not include your identity or contact details unless you ask us to name you. If a report you send us triggers this obligation, we will tell you that it did.

## Contact

- Security reports: security@keycard.ai
- Everything else: support@keycard.ai

Please keep security matters out of the public issue tracker until an advisory is published.
