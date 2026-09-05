# Changelog

This file records notable changes. It does not promise a release date,
support window, or binary availability. Version metadata and repository tags
may describe different snapshots; verify the exact commit you build.

## [3.1.0] — 2026-09-05

- Published the modern desktop as a normal GitHub release, with consistent
  `3.1.0` application/package metadata and no Windows prerelease flag.
- Retained the preview's native engine, security policies and dependencies;
  this promotion does not change the VPN protocol or encryption.
- Rebuilt and revalidated the versioned package. Pending elevated qualification
  and unsigned-binary limitations remain explicit in the
  [release notes](docs/releases/3.1.0.md).

## [3.1.0-preview.1] — 2026-09-05

This is a preview for evaluation, not a stable release. Qualification of the
new desktop/worker privilege boundary with elevated, real-network GUI and E2E
tests remains pending. See the [release notes](docs/releases/3.1.0-preview.1.md).

- Added authenticated make-before-break renewal for long-lived Schannel/TCP
  sessions, with bounded freeze/cutover behavior and fail-closed handling.
- Added optional client reconnect and heartbeat recovery controls for TCP and
  UDP, including bounded retry behavior and explicit stop handling.
- Hardened Wintun identity and lifecycle handling with deterministic adapter
  identity, collision checks, exact cleanup, and repeated-start coverage.
- Expanded security and integration coverage for native TLS/DTLS, malformed
  input, traffic limits, packet ordering, backpressure, recovery, and GUI
  states.
- Replaced the ImGui interface with an embedded React/TypeScript/WebView2 desktop:
  responsive connection cards, aligned inputs, light/dark/system themes,
  accessible Radix dialogs, searchable activity, and reduced-motion support.
- Separated the unelevated desktop from an on-demand elevated native worker.
  Access keys stay outside JavaScript; bounded, identity-checked local IPC owns
  start/stop/telemetry and retains the existing cryptographic/network policies.
- Added headless Playwright/axe coverage and actual-executable, UAC-free GUI
  capture, plus native IPC, input-boundary, key-wiping, and diagnostic-file tests.
- Removed Conan/ImGui/FreeType from the active build, pinned frontend/WebView2
  dependencies, and embedded the production bundle with exact license notices.

## [3.0.0] — 2025-05-29, tag `V3`

- Added the multi-client server architecture and client-to-client routing.
- Adopted C++23 and reduced contention in the TLS forwarding path.
- Reworked the release documentation for the version 3 line.

## [2.2.0] — 2025-05-21, tag `V2.2`

- Added HMAC authentication and disconnect controls to the controller and GUI.

[3.1.0]: https://github.com/Wes2000ley/TrueTunnel-VPN/releases/tag/v3.1.0
[3.1.0-preview.1]: https://github.com/Wes2000ley/TrueTunnel-VPN/releases/tag/v3.1.0-preview.1
[3.0.0]: https://github.com/Wes2000ley/TrueTunnel-VPN/tree/V3
[2.2.0]: https://github.com/Wes2000ley/TrueTunnel-VPN/tree/V2.2
