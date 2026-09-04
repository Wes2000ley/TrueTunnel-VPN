# Changelog

This file records notable changes. It does not promise a release date,
support window, or binary availability. Version metadata and repository tags
may describe different snapshots; verify the exact commit you build.

## [Unreleased] — 3.1.0-dev

- Added authenticated make-before-break renewal for long-lived Schannel/TCP
  sessions, with bounded freeze/cutover behavior and fail-closed handling.
- Added optional client reconnect and heartbeat recovery controls for TCP and
  UDP, including bounded retry behavior and explicit stop handling.
- Hardened Wintun identity and lifecycle handling with deterministic adapter
  identity, collision checks, exact cleanup, and repeated-start coverage.
- Expanded security and integration coverage for native TLS/DTLS, malformed
  input, traffic limits, packet ordering, backpressure, recovery, and GUI
  states.
- Refined the native Windows GUI and added an unelevated visual-regression
  executable that captures the production dashboard at supported sizes.

## [3.0.0] — 2025-05-29, tag `V3`

- Added the multi-client server architecture and client-to-client routing.
- Adopted C++23 and reduced contention in the TLS forwarding path.
- Reworked the release documentation for the version 3 line.

## [2.2.0] — 2025-05-21, tag `V2.2`

- Added HMAC authentication and disconnect controls to the controller and GUI.

[Unreleased]: https://github.com/Wes2000ley/TrueTunnel-VPN/compare/V3...HEAD
[3.0.0]: https://github.com/Wes2000ley/TrueTunnel-VPN/tree/V3
[2.2.0]: https://github.com/Wes2000ley/TrueTunnel-VPN/tree/V2.2
