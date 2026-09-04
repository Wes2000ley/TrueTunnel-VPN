# Security policy

TrueTunnel is a Windows-only VPN project. Its TCP transport uses Windows
Schannel TLS 1.3 and its UDP transport uses wolfSSL DTLS 1.3. This policy
describes how to report defects in this repository; it is not a claim of
certification, audit, or suitability for a particular deployment.

## Supported versions

Security fixes are developed on the default branch and are intended for the
latest tagged version. Older tags and private forks should be treated as
unsupported unless a maintainer explicitly says otherwise. Check the
repository's tags and release information for the current version; do not
assume that a version-numbered build is available merely because a version
appears in source metadata.

## Reporting a vulnerability

Please do **not** open a public issue, discussion, or pull request for a
suspected vulnerability. Use GitHub's private vulnerability-reporting flow
only when the repository interface explicitly offers it. Private reporting is
not assumed to be enabled. If that flow is unavailable, contact a repository
maintainer through a private channel you already have and ask for a secure
way to share the details. Do not put secrets, credentials, private keys, or a
working exploit in a public comment.

Include, where safe:

- the affected commit, tag, or build configuration;
- the Windows version, transport (TCP or UDP), and relevant configuration;
- a minimal reproduction or test case;
- the impact, required attacker capability, and any known mitigations; and
- logs with credentials, tunnel secrets, addresses, and other sensitive data
  removed.

Maintainers may acknowledge a report, request clarification, coordinate a
fix, and publish a coordinated advisory. There is no guaranteed response or
disclosure timeline. Please allow maintainers to confirm the affected scope
before public disclosure.

## Scope and limitations

Reports about the TrueTunnel source, build configuration, bundled runtime
handling, protocol implementation, and Windows adapter lifecycle are in scope.
Third-party vulnerabilities should also be reported to the relevant upstream
project. Do not infer that a passing test, a pinned dependency, or native
Windows cryptography constitutes an independent security audit or a guarantee
of production readiness.

For licensing and component provenance, see [NOTICE](NOTICE),
[THIRD_PARTY.md](THIRD_PARTY.md), and [LICENSE](LICENSE).
