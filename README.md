<p align="center">
  <img src="docs/images/truetunnel-logo.png" width="168" alt="TrueTunnel shield logo">
</p>

<h1 align="center">TrueTunnel</h1>

<p align="center">
  <strong>A Windows IPv4 VPN with a modern, focused desktop.</strong><br>
  DTLS 1.3 over UDP when latency matters. TLS 1.3 over TCP when networks are restrictive.
</p>

TrueTunnel is an open-source IPv4 VPN for Windows. It puts a React desktop
over Wintun and two standardized encrypted transports:

- **UDP** uses wolfSSL DTLS 1.3 and is the normal choice for interactive traffic.
- **TCP** uses Windows Schannel TLS 1.3 and is the fallback for networks that
  block UDP.

The project is deliberately honest about its scope: it is a focused Windows
VPN, not a replacement for WireGuard or a certified IPsec product. Read
[`docs/SECURITY-DESIGN.md`](docs/SECURITY-DESIGN.md) before using it for a
security-sensitive deployment.

## What you get

- TLS 1.3 and DTLS 1.3, AES-256-GCM, forward-secret handshakes, and bounded
  record processing.
- A stable `TrueTunnel VPN Adapter` identity backed by Wintun.
- One server with multiple authenticated clients, IPv4 routing, and an
  encrypted in-band chat channel.
- Optional client heartbeat and bounded automatic reconnect for both transports.
- TCP make-before-break session renewal and UDP DTLS traffic-key updates.
- A React + TypeScript desktop with responsive layouts, dark/light/system
  themes, accessible dialogs, searchable activity, and explicit recovery controls.
- An unelevated WebView2 interface and a separate, on-demand native network
  worker. Access keys stay in native memory, never in JavaScript.

![Actual TrueTunnel React desktop in WebView2, with a synthetic adapter and masked test key](docs/images/truetunnel-dashboard.png)

The current release is **[3.1.0](https://github.com/Wes2000ley/TrueTunnel-VPN/releases/tag/v3.1.0)**.
Read the [release notes and known limitations](docs/releases/3.1.0.md), including
the pending elevated real-network qualification of the new desktop/worker
boundary. Windows 11 and Windows
Server 2022 or newer and the Microsoft Edge WebView2 Evergreen Runtime are
required. Opening the interface does not require Administrator privileges.
Connecting requests approval for the native worker that owns Wintun and changes
Windows networking state. Both processes must belong to the same Windows user;
over-the-shoulder elevation as a different administrator is rejected.

## Quick start

1. Download `TrueTunnel-3.1.0-windows-x64.zip` from the
   [release page](https://github.com/Wes2000ley/TrueTunnel-VPN/releases/tag/v3.1.0),
   or build `TrueTunnel-<Config>.zip`, and extract it to a
   dedicated directory. Keep `TrueTunnel.exe` and the adjacent `wintun.dll`
   together; do not replace the pinned DLL.
2. Open `TrueTunnel.exe` normally. Choose **Server**, select the
   physical uplink, choose TCP or UDP, and select an unused listening port.
3. Generate the 256-bit shared key in the Server dashboard and transfer it to
   the client through a trusted channel. The key is not persisted by TrueTunnel.
4. Press **Start server** and approve the Windows network worker. On the client,
   choose **Client**, enter the server's address and the exact
   same port, paste the key, select the same transport, and press **Connect**.
5. Prefer UDP. Enable **Automatic recovery** only when short outages should be
   retried; it is optional and off by default.

The key is a group credential: anyone who has it can authenticate. Regenerate
it whenever a member leaves or exposure is suspected. Server startup creates a
temporary Windows Firewall rule scoped to the executable, protocol, local
address, and port; normal shutdown removes that exact rule.

## Choose a transport

| Transport | Use it when | Trade-off |
| --- | --- | --- |
| UDP / DTLS 1.3 | UDP is permitted and latency matters | Lost outer datagrams remain lost; no seamless roaming |
| TCP / TLS 1.3 | UDP is blocked or a TCP-only egress is required | TCP-in-TCP head-of-line blocking can amplify loss and delay |

Both modes use the same Wintun adapter, IPv4 framing, shared-key admission,
limits, and optional recovery. They do not share a live session: changing the
transport requires disconnecting and connecting again.

## Learn the design

The [architecture guide](docs/ARCHITECTURE.md) describes the desktop/worker
privilege boundary and the unchanged native packet path. No packets or access
keys travel through the frontend.

The [TLS session-renewal diagram](docs/images/tls-session-renewal.drawio.svg)
shows the authenticated cutover, safe pre-activation rollback, and fail-closed
post-activation path.

The deeper references are organized by job:

- [Architecture](docs/ARCHITECTURE.md) — components, packet flow, lifecycles,
  and Windows integration.
- [Security design](docs/SECURITY-DESIGN.md) — cryptographic profiles,
  authentication, renewal, limits, failure behavior, and limitations.
- [Building](docs/BUILDING.md) — dependencies, reproducible configuration,
  output layout, and packaging.
- [Testing](docs/TESTING.md) — deterministic tests, elevated Wintun E2E, logs,
  latency/throughput checks, and GUI smoke coverage.
- [Troubleshooting](docs/TROUBLESHOOTING.md) — practical recovery and cleanup
  steps for Windows networking issues.
- [Release checklist](docs/RELEASE.md) — versioning, artifact, integrity, and
  licensing checks for maintainers.
- [Security policy](SECURITY.md) — private vulnerability-reporting guidance and
  supported-version expectations.
- [Contributing](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md), and
  [Changelog](CHANGELOG.md) — project participation and release history.

## Status and boundaries

TrueTunnel is usable for controlled Windows deployments and development, but it
has important boundaries:

- IPv4 only; the tunnel MTU is 1380 bytes.
- One shared group credential; no per-peer identity, revocation, or attribution.
- No kill switch, DNS-leak policy, IPv6 policy, seamless roaming, or signed
  automatic updater.
- Automatic recovery is a bounded short-outage retry, not packet-preserving
  mobility.
- Internet sharing is optional and depends on Windows RRAS NAT. Peer-to-peer
  tunnel traffic can work when RRAS is unavailable, but Internet-bound traffic
  will not be translated.
- The complete application protocol and current wolfSSL configuration have not
  received an independent cryptographic audit and make no FIPS claim.
- The TCP certificate is an ephemeral Schannel server credential; the shared
  key and exporter-bound proof authenticate the peer. It is not hostname/CA
  identity validation.

WireGuard remains the stronger general-purpose default because it has mature
per-peer public-key identity, built-in roaming, IPv6, and a purpose-built small
protocol. IKEv2/IPsec remains the better fit for native OS clients, certificates,
EAP, enterprise policy, and standards interoperability. TrueTunnel's advantage
is its native Windows GUI, Wintun integration, standardized TLS/DTLS choices,
and TCP fallback in one focused product.

## Build and test in one minute

Prerequisites are Visual Studio 2022, a current Windows SDK, CMake 3.24+,
Node.js 22.12+ with npm, network access for pinned dependencies, and the supplied
`deps/wintun.dll`. Conan, ImGui, FreeType, and OpenSSL are not required.

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DBUILD_TESTING=ON
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

The production binary is `build/Release/TrueTunnel.exe`; the integration
harness and focused test executables remain separately named. See
[`docs/TESTING.md`](docs/TESTING.md) for the elevated real-Wintun run:

```powershell
.\build\Release\vpn_integration_test.exe --no-pause
```

The harness writes a flushed `vpn-integration.log` beside itself. Use
`--log-file C:\Logs\truetunnel-e2e.log` for an explicit safe destination.

## Uninstall and cleanup

Disconnect and exit TrueTunnel first. A normal stop removes the adapter,
owned routes, firewall rule, and temporary credentials. If Windows still shows
an exact TrueTunnel adapter after a crash, use the documented, identity-scoped
procedure in [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md). Do not delete
registry keys, routes, or adapters by a broad name prefix, and do not remove the
shared Wintun driver if another product uses it.

To uninstall a manually extracted build, delete the extracted application
directory after disconnecting. WebView2's non-secret runtime data is under
`%LOCALAPPDATA%\TrueTunnel\WebView2`; it can also be removed after all TrueTunnel
processes close. The driver package is shared with WireGuard and
must be removed only by the installer or an administrator who has verified that
no Wintun adapter depends on it.

## Licensing

TrueTunnel source is available under MIT or GPLv2, as described in `LICENSE`.
The default build statically links wolfSSL 5.9.2, which is GPLv3 or commercial;
redistribution of the combined binary must follow the applicable wolfSSL terms.
See [`NOTICE`](NOTICE), [`THIRD_PARTY.md`](THIRD_PARTY.md), and the packaged
`licenses/` directory. This summary is not legal advice.
