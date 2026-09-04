# TrueTunnel VPN

TrueTunnel is a Windows point-to-point or one-server/many-client IPv4 VPN built
on Wintun. TCP sessions use native Windows Schannel TLS 1.3. UDP sessions use
wolfSSL DTLS 1.3, which preserves UDP datagram boundaries while replacing the
project's former custom handshake and record cryptography.

wolfGuard itself is a Linux kernel module and cannot run as the transport for a
native Windows application. The Windows UDP backend therefore uses wolfSSL's
supported user-mode DTLS implementation and the same WolfCrypt primitives.

## Transport profiles

| Mode | Protection | Required profile |
|---|---|---|
| TCP | Schannel TLS 1.3 plus exporter-bound shared-key authentication | `TLS_AES_256_GCM_SHA384` |
| UDP | wolfSSL 5.9.2 DTLS 1.3 with external ECDHE-PSK authentication | `TLS_AES_256_GCM_SHA384`, P-256 |

Both backends retain TrueTunnel's typed record API, Wintun forwarding,
multi-client routing, and in-band chat channel. Older TLS versions, alternate
UDP ciphers, non-forward-secret PSK exchange, and the legacy custom UDP crypto
path are not available in the active build.

## TCP security design

- `SCH_CREDENTIALS` disables every Schannel protocol except TLS 1.3.
- Both peers verify the negotiated protocol, cipher identifier, cipher strength,
  hash, and key-exchange properties. Anything outside the required profile is
  rejected.
- The server creates an ECDSA P-384 self-signed certificate for each connection.
  Its non-exportable CNG key has a random transient container name and is deleted
  during normal cleanup. The certificate is never installed in a certificate
  store.
- The certificate supplies the TLS server signature but is not treated as a PKI
  identity. Peer authentication comes from the exporter-bound shared-key
  protocol.
- Each peer obtains 32 bytes from the Schannel TLS exporter, exchanges an
  independent 32-byte nonce inside TLS, and derives an authentication key with
  PBKDF2-HMAC-SHA-256 (100,000 iterations). Role-separated HMAC-SHA-256 proofs
  bind the shared key, exporter, nonces, roles, and required cipher to that TLS
  session. Proof comparisons are constant-time.
- TrueTunnel's one-byte type and two-byte length header is carried as TLS
  plaintext. Schannel supplies encryption, authentication, ordering, replay
  protection, and processing of TLS 1.3 post-handshake messages.
- Schannel does not expose a supported application-initiated TLS 1.3 KeyUpdate
  API. Windows owns the native provider's internal traffic-key lifecycle;
  TrueTunnel accepts and processes peer post-handshake updates and reports that
  application-initiated rotation is unavailable for this backend.
- The implementation handles fragmented and coalesced TLS input,
  `SECBUFFER_EXTRA`, incomplete records, post-handshake messages, and orderly
  `close_notify`.
- Server sockets use a 15-second timeout through TLS, shared-key authentication,
  and configuration exchange. Each complete application write has a five-second
  deadline, so a peer that stops reading cannot pin a worker forever. Server
  shutdown also interrupts unauthenticated connections before joining workers.
- Temporary shared-key copies, TLS exporter bytes, derived keys, and proofs are
  explicitly cleared when no longer needed.

## UDP security design

- The pinned wolfSSL backend uses the DTLS 1.3-only client and server methods.
- The shared key is converted to a 32-byte external PSK with
  PBKDF2-HMAC-SHA-256 (200,000 iterations) and a fixed, protocol-specific salt.
  The server derives it once for the listener instead of repeating the KDF for
  unauthenticated datagrams; application-owned PSK material is wiped when the
  listener/session state is destroyed.
- TLS 1.3 DHE-PSK is mandatory. P-256 is the only accepted key-share group, so
  each connection receives forward secrecy in addition to PSK authentication.
- `TLS_AES_256_GCM_SHA384` is the only accepted cipher suite. The result is
  checked again after negotiation.
- Session tickets are disabled. TLS 1.2 and older, RSA, finite-field DH,
  ChaCha20-Poly1305, and AES-CBC are disabled in the wolfSSL build; alternate
  elliptic-curve groups are neither offered nor accepted by TrueTunnel.
- The transport preserves one UDP datagram per wolfSSL I/O callback. DTLS
  handshake flights are retransmitted on timeout, with a 15-second overall
  handshake deadline and cancellable reads. A complete application write also
  has a five-second deadline and observes shutdown while wolfSSL reports
  backpressure, so a stalled UDP peer cannot pin a sender indefinitely.
- Each TrueTunnel `[type][length][payload]` frame occupies one DTLS application
  record. Payloads are capped at the Wintun MTU of 1380 bytes, and the outer
  DTLS datagram MTU is capped at 1472 bytes to avoid IPv4 fragmentation on a
  1500-byte physical link.
- wolfSSL's DTLS write-duplication API provides independent read and write sides
  after negotiation. The wrapper additionally serializes same-direction calls.
- Each direction automatically requests a DTLS 1.3 traffic-key update before
  sending 1,000,000 records, 1 GiB of application data, or using one traffic-key
  epoch for one hour, whichever occurs first. A failed update terminates that
  secure connection instead of continuing under an over-age epoch.
- Unknown UDP tuples first pass wolfSSL's stateless DTLS 1.3 HelloRetryRequest
  cookie check. The cookie uses an hourly rotated CNG secret and is bound to the
  complete peer socket address. wolfSSL then verifies the TLS 1.3 PSK binder in
  its stateful ClientHello parser before TrueTunnel allocates a peer queue or
  worker thread. Wrong-PSK ClientHellos and malformed floods therefore never
  enter the application's per-peer handshake path.
- Stateless attempts are limited globally and per source. Stateful handshakes
  are capped at 64 globally and 8 per source, then released from those counters
  immediately after authentication. Authenticated peers are capped at 256 and
  each peer queue is bounded to 64 datagrams.
- Secrets and decrypted record buffers are explicitly cleared during handshake,
  record processing, failure, and shutdown.

## Authentication and secret handling

- Every GUI start generates a fresh 32-byte secret with Windows CNG's system
  CSPRNG and displays it as 43 unpadded base64url characters. In Server mode the
  field is read-only and startup accepts only a key generated in that UI; Client
  mode accepts the server's copied value. The UI provides role-appropriate
  Regenerate, Clear, and Copy controls. Copy is a checked Win32 clipboard
  transaction that opts the secret out of Windows clipboard history and cloud
  synchronization. A copied secret is cleared after 30 seconds or on
  regeneration/shutdown, but only when both the clipboard owner and sequence
  still prove that TrueTunnel's value has not been replaced by another app.
- Every production boundary, including direct Schannel and wolfSSL construction,
  accepts only one canonical representation: exactly 43 unpadded base64url
  characters encoding 256 bits. Human passwords, noncanonical trailing bits,
  and obvious repeated, short-period, or sequential-byte patterns are rejected
  before any socket, certificate, KDF, or Wintun work. The pattern checks are
  misuse guards, not an entropy estimator; use the built-in CNG generator.
- TrueTunnel does not persist the generated secret. Share it through a separate
  trusted channel and regenerate it for each independent tunnel session.
- Temporary application-owned shared-key copies are cleared after secure socket
  construction and again during shutdown.

## Optional client connection recovery

- Automatic recovery is client-only and off by default. The Client dashboard
  exposes the setting while idle; once connected, the setting is locked until
  the user explicitly selects Disconnect. The status card reports when recovery
  is armed and shows the reconnect attempt and next retry delay. The server
  accepts both ordinary clients and recovery-enabled clients; watchdog tracking
  begins only after an authenticated peer sends its first heartbeat.
- An opted-in client sends an authenticated and encrypted heartbeat inside the
  selected TLS/TCP or DTLS/UDP channel every five seconds. The server
  acknowledges it and starts watchdog tracking only for peers that opt in. A
  client declares the secure session stale after 15 seconds without an
  authenticated receive, and the server applies the same negotiated timeout to
  opted-in peers. Server-side heartbeat admission is bounded globally and per
  authenticated peer. Enable recovery only when the peer runs a build that
  supports these heartbeat control records.
- Recovery retries use capped exponential equal-jitter backoff: one second at
  the first retry, doubling toward a hard 30-second ceiling. Each scheduled
  retry makes one bounded connection/handshake attempt; a failed attempt returns
  to the scheduler instead of bypassing the backoff. The previous client and
  Wintun state are fully torn down before a fresh handshake establishes new
  session keys.
- An explicit Disconnect cancels the heartbeat and retry waits immediately and
  prevents automatic recovery. While recovery is armed, one additional
  in-memory shared-key copy is retained for the next handshake. TrueTunnel asks
  Windows to page-lock that buffer, reports if page locking is unavailable,
  and explicitly zeroizes it at final stop; an administrator, debugger, or
  process compromise can still read live key material. The key is never
  persisted.
- This is short-outage recovery, not seamless roaming: endpoint addresses are
  not migrated, packets in flight or sent during the outage are not preserved,
  and applications must tolerate the interruption. The shared key remains a
  group credential, so recovery does not add per-device identity or revocation;
  rotate the key when a member leaves or exposure is suspected.

## Wintun and network hardening

- `wintun.dll` is loaded only from the executable's directory by absolute path.
  TrueTunnel rejects directory/file reparse points and hard-linked DLLs, then
  hashes the file while holding both the real containing directory and DLL open
  without delete sharing. The loader uses paths resolved from those open handles
  and re-hashes the same locked file after Windows maps it. It requires the
  pinned SHA-256
  `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`,
  and resolves exports only after the pinned image loads successfully.
- CMake applies the same hash check at configure time. The test suite verifies
  acceptance of the supplied DLL and rejection of modified and hard-linked
  copies. The application should still be installed in an administrator-writable,
  standard-user-read-only directory; integrity checks are not an updater or a
  substitute for protected installation permissions.
- The GUI uses the fixed Windows alias `TrueTunnel VPN Adapter`. TrueTunnel
  derives a case-insensitive, deterministic version-8 GUID from each validated
  adapter name with SHA-256 and passes that GUID to `WintunCreateAdapter`, so
  repeated starts reuse one Windows/NLA identity instead of generating a new
  profile every time.
- A named interprocess lease is held for the adapter's complete lifetime. Before
  creation, TrueTunnel checks both the Windows interface-alias table and
  `WintunOpenAdapter`; an existing owner is rejected before Wintun can rename it
  to a numbered alias. After creation, the actual LUID, interface GUID, and alias
  are verified before any address or route is configured. TrueTunnel never
  deletes devices or registry keys by display-name prefix.
- Wintun device removal can complete in SetupAPI before Windows retires the
  interface alias. Production teardown therefore keeps the named identity lease
  while polling the native IP Helper alias and GUID tables for up to 10 seconds.
  This makes an immediate stop/reconnect wait for its own exact identity instead
  of creating a numbered adapter. A timeout is reported and later starts still
  reject the collision safely; no foreign interface is renamed or removed.
- Authenticated clients may inject only packets whose IPv4 source equals their
  assigned tunnel address. Every packet is also checked for an IPv4 version,
  valid header length, exact total length, and the configured tunnel MTU before
  it enters the encrypted channel or Wintun. Expected IPv6 link-local chatter
  generated by Windows is discarded because this tunnel is IPv4-only.
- Routes and MTUs are configured through Windows IP Helper/NetIO calls and are
  tracked by exact-row RAII guards. TrueTunnel never deletes a route merely by
  destination, which is important when a same-machine test uses the host's own
  physical address as its server endpoint. The selected physical adapter's LUID
  is captured with the GUI selection, verified at startup, and retained for
  native bind, gateway, and route work; mutable display aliases are not
  repeatedly resolved for privileged mutations. Legacy RRAS alias commands are
  immediately checked against that LUID, and cleanup fails closed if the alias
  no longer maps to the owned interface.
- Client mode has one canonical server-address and port pair. Windows resolves
  an IPv4 literal or UTF-8 hostname for each fresh connection attempt through a
  cancellable, 10-second-bounded Winsock query, the socket uses that exact port,
  and every resolved candidate must complete the TLS/DTLS handshake before it is
  selected. Route protection pins only that authenticated numeric address. A
  forged DNS answer alone cannot authenticate a peer because the subsequent
  TLS/DTLS channel still requires the shared key.
- The optional RRAS NAT compatibility path launches only the absolute System32
  `netsh.exe`, gives every invocation a 10-second ceiling, and cancels startup
  invocations when the endpoint is stopped; it cannot hold shutdown forever.
  Existing administrator/service-owned NAT bindings are never pre-deleted, and
  cleanup removes only bindings whose add succeeded in the current endpoint.
- Each server listener uses `SO_EXCLUSIVEADDRUSE` and a temporary Windows
  Firewall rule restricted to the exact executable, protocol, local address,
  and port. Every rule has a per-instance GUID ownership name, so two servers
  on different local addresses cannot delete or replace each other's rule.
  Normal shutdown removes only that exact rule, and startup removes the broad
  Public-profile `TrueTunnel VPN` rules left by older releases.
- The server limits concurrent TCP workers and tracked UDP peers to 256 and
  bounds unauthenticated waits. Before Schannel or certificate work, TCP accepts
  are limited to 128 per second globally and 16 per second per numeric source,
  with at most 1,024 tracked sources. Authenticated chat is limited to 128
  messages/128 KiB per second globally and 16 messages/16 KiB per second per
  client; an abusive sender is disconnected before fanout. Aggregate encrypted
  fanout is independently limited to 8 MiB per second globally and 2 MiB per
  sender, with a 100 ms writer-lock wait and five-second whole-fanout deadline.
  A congested recipient cannot create an unbounded per-client write queue.
  Retained chat is bounded to 1,024 entries or 1 MiB. Shutdown cancels blocked
  Wintun reads before joining workers and ending the Wintun session.
- Each active adapter owns a temporary executable-scoped ICMP rule. It is
  Private-profile-only, restricted to the VPN subnet for both local and remote
  addresses, disables edge traversal, and is removed by normal endpoint cleanup;
  startup also removes the persistent rule name used by older builds.

## Security boundaries and limitations

- The Server GUI accepts only its application-generated 256-bit shared key; a
  Client pastes that value. Lower-level C++ entry points accept the same
  canonical 32-byte encoding but cannot prove the provenance or entropy of
  imported bytes, so embedders must use a CSPRNG. A captured UDP external-PSK
  binder still provides a verifier for offline guesses, but brute forcing a
  uniformly random 256-bit key is infeasible. This is not a PAKE and deliberately
  does not accept human-memorable passwords.
- The key is a group credential: every holder can authenticate as a client, and
  there is no individual peer identity, authorization policy, revocation, or
  attribution. Rotate the key for a new tunnel session and whenever any member
  leaves or a key may have been exposed.
- DTLS retransmits handshake traffic, not application data. UDP mode preserves
  datagram semantics: an application record lost by the network remains lost.
- DTLS supplies replay protection, but TrueTunnel does not implement connection
  migration. A changed source address or port is treated as a new peer.
- The TCP certificate is intentionally not hostname- or CA-validated. Possession
  of the shared key authenticates the peer through the exporter-bound proof.
- An abnormal process termination can leave a randomly named, non-exportable
  `TrueTunnel-TLS-*` CNG key container behind; normal cleanup removes it.
- Schannel's public API does not let this application force traffic-key updates;
  if explicit application-timed rotation is a deployment requirement, use UDP
  mode or reconnect the TCP session on the desired interval.
- This project, its application framing, and its wolfSSL configuration have not
  been independently audited and make no FIPS validation or certification claim.
  This build is not the separate wolfSSL FIPS product and does not use wolfGuard's
  Linux kernel module. Standard TLS/DTLS primitives do not make the complete VPN
  equivalent to an audited, mature VPN product.
- The tunnel is IPv4-only and uses an MTU of 1380. Client automatic recovery is
  opt-in and limited to short outages; it does not provide seamless roaming or
  packet preservation. There is no IPv6 policy, DNS-leak policy, or system-wide
  kill switch. It also has no signed automatic-update or per-device
  key-provisioning system.
- Internet sharing is optional and depends on the legacy Windows RRAS NAT
  component. If RRAS NAT is unavailable, authenticated peer-to-peer tunnel and
  chat traffic still work, but internet-bound traffic is not translated; the
  application reports this explicitly. TrueTunnel does not silently enable ICS
  because doing so can readdress an existing private interface.
- Running the VPN requires Administrator privileges because it configures Wintun
  and Windows networking. The networking and GUI currently share that elevated
  process, rather than using a separately hardened least-privilege service.

## Comparison with established VPN protocols

TrueTunnel uses strong standardized transport cryptography, but its complete VPN
protocol and product lifecycle are much younger than WireGuard or IKEv2/IPsec.
This is the practical comparison, not a claim of cryptographic equivalence:

| Property | TrueTunnel | WireGuard | IKEv2/IPsec |
|---|---|---|---|
| Peer identity | One 256-bit group key; no per-peer revocation | Static Curve25519 public key per peer; optional extra PSK | Certificates, public-key signatures, PSKs, or EAP depending on policy |
| Data protection | TLS 1.3 over TCP or DTLS 1.3 over UDP; AES-256-GCM/SHA-384 | Fixed Noise construction with Curve25519, ChaCha20-Poly1305, BLAKE2s, and HKDF | IKEv2 negotiates SAs; ESP protects data, with security depending on the selected transforms and policy |
| Forward secrecy and rekey | Ephemeral TLS/DHE sessions; UDP forces KeyUpdate at 1M records, 1 GiB, or one hour; TCP rotation is Schannel-managed or requires reconnect | Automatic timed/message-count handshakes and key erasure | Ephemeral DH for IKE; IKE/Child SA rekeying, with Child-SA PFS depending on negotiated DH |
| Replay protection | TLS sequencing; DTLS record replay protection | Monotonic counters plus a sliding receive window | ESP sequence numbers and an anti-replay window when enabled (the normal default) |
| Roaming/recovery | Optional authenticated heartbeat and bounded reconnect; no seamless endpoint migration or packet preservation | Built-in endpoint roaming, keepalives, retry, and rekey timers | MOBIKE and dead-peer/rekey machinery when implemented and configured |
| Network/product integration | Windows-only Wintun, IPv4-only, custom control/framing, no independent audit | Small purpose-built cross-platform VPN protocol and mature implementations | Long-standing IETF suite with broad OS, enterprise identity, and policy integration; substantially more configuration complexity |

For a general-purpose modern VPN, WireGuard is the stronger default: it has
per-peer public-key identity, automatic roaming/rekey/recovery, IPv6 support, and
a deliberately small specialized protocol. IKEv2/IPsec is usually the better fit
when native OS clients, certificates/EAP, enterprise policy, or standards-based
interoperability matter. TrueTunnel is best treated as a specialized Windows
TLS/DTLS VPN with a useful TCP fallback, not as a replacement for either today.

Prefer TrueTunnel's UDP mode for ordinary tunneled traffic. TCP mode is valuable
where UDP is blocked, but loss on the outer TCP stream stalls later inner packets;
the IETF explicitly warns that TCP-in-TCP can amplify delay, retransmissions, and
throughput collapse. The relevant primary specifications are the
[WireGuard protocol](https://www.wireguard.com/protocol/),
[TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html),
[DTLS 1.3](https://www.rfc-editor.org/rfc/rfc9147.html),
[IKEv2](https://www.rfc-editor.org/rfc/rfc7296.html),
[ESP](https://www.rfc-editor.org/rfc/rfc4303.html),
[MOBIKE](https://www.rfc-editor.org/rfc/rfc4555.html), and the IETF's
[TCP encapsulation performance guidance](https://www.rfc-editor.org/rfc/rfc9329.html).

## Requirements

- Windows 11 or Windows Server 2022 or newer for the Schannel TLS 1.3 profile;
- Visual Studio 2022 with C++23 and a current Windows SDK;
- CMake 3.20 or newer;
- Conan 2 for Dear ImGui, FreeType, and their transitive dependencies;
- network access during first CMake configuration so FetchContent can retrieve
  the pinned wolfSSL archive; and
- the supplied `wintun.dll` for the virtual network adapter.

OpenSSL is not required, linked, or shipped.

## Building

Install the Conan dependencies, configure CMake with Conan's generated
toolchain, then build a configuration. For example:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_TOOLCHAIN_FILE=build/conan/build/generators/conan_toolchain.cmake `
  -DCMAKE_PREFIX_PATH=build/conan/build/generators `
  -DBUILD_TESTING=ON
cmake --build build --config Release --parallel
```

CMake downloads wolfSSL 5.9.2 from its official release tag and verifies SHA-256
`2f4ef3d4fd387a9b3191d36a6316d69116c46ff69bb9583b6c82b36d7b8ca114`
before extracting it. wolfSSL is linked statically; no wolfSSL or OpenSSL DLL is
required at runtime.

The main target creates `TrueTunnel-VPN-<Config>.zip` containing `vpn.exe`,
`wintun.dll`, the project notices, and the exact third-party license texts used
by that build.

## Tests

The non-administrative suite contains eight registered tests:

- `vpn_secure_transport_test` covers Schannel TLS 1.3 and wolfSSL DTLS 1.3,
  strict profiles, maximum and empty records, malformed-buffer recovery,
  real Winsock stateless-cookie admission, address binding, malformed-flood and
  wrong-password pre-admission rejection,
  concurrent bidirectional traffic, wrong-password rejection, dropped-handshake
  retransmission, short DTLS PSK identities, a stalled DTLS application-write
  deadline, stalled and authenticated-I/O cancellation with concurrent idempotent close, failed-handshake non-retry
  behavior, forced stateless-cookie secret rollover, and forced low-threshold
  bidirectional DTLS traffic-key rotation;
- `vpn_redirect_stream_test` verifies that unit-buffered error output and
  concurrent writers remain complete logical lines in the GUI callback and
  native test log;
- `vpn_wintun_loader_test` accepts the supplied adjacent pinned DLL;
- `vpn_wintun_identity_test` locks the canonical deterministic GUID, verifies
  Windows-insensitive name casing, and rejects ambiguous or oversized names;
- `vpn_wintun_tamper_test` rejects a modified DLL;
- `vpn_source_binding_test` rejects null, truncated, malformed-header, oversized,
  IPv6, and authenticated source-address-spoofed packets; resolves `localhost`
  through the same cancellable Windows IPv4 endpoint path used by the product;
  connects the real client TCP and UDP sockets to dynamic loopback listeners;
  verifies a probe reaches the configured address and exact port; makes a real
  DTLS client reject a dead first resolved IPv4 address and authenticate the
  second; rejects embedded-NUL and malformed UTF-8 addresses; and rejects invalid
  client, server, and controller ports;
- `vpn_gui_visual_test` compiles the exact production ImGui dashboard into a
  separate executable without the administrator manifest or VPN-daemon startup.
  It proves that it is unelevated, renders Server/Client and TCP/UDP states at
  desktop, compact, and minimum-supported window sizes, exercises connected/connecting/stopping,
  recovery-enabled, and reconnecting states,
  opens both dialogs, focuses the endpoint through the real ImGui input path,
  verifies Tab focus order, Enter activation, and Escape dismissal, and renders
  field-level address, port, secret, adapter, and startup errors with the
  matching failure visible in Activity. It
  drives the outer dashboard to semantic card boundaries, snaps the Activity log
  to complete rows, captures 33 Direct3D backbuffers to PNG with Windows Imaging
  Component, crops compact scrolled views to complete target sections, and
  rejects missing, blank, incorrectly sized, incompletely scrolled,
  state-inconsistent, misaligned chrome/card/endpoint geometry, long endpoint
  overflow at the minimum supported viewport, partially clipped-control, or
  clipped-target-card
  captures; and
- `vpn_daemon_harness` exercises lifecycle transitions, re-entrant callbacks,
  invalid and retired secrets, recovery-policy validation and propagation,
  failure recovery, and repeated start/stop cycles.

```powershell
ctest --test-dir build -C Release --output-on-failure

# UAC-free visual regression only. PNGs and a flushed report are written under
# build\Release\gui-visual-test\.
ctest --test-dir build -C Release --output-on-failure -R ^vpn_gui_visual_test$
```

`vpn_integration_test` runs the real application stack once with Schannel/TCP and
once with wolfSSL DTLS/UDP. It requires a usable physical network adapter,
`wintun.dll`, and UAC consent. When started unelevated it relaunches itself with
native `ShellExecuteExW`, waits for the elevated child, and returns that child's
exit code. The native parent fails and terminates a child that exceeds five
minutes; PowerShell is not an E2E launcher.

Before touching the physical uplink, the elevated harness snapshots present and
phantom devices directly with SetupAPI's exact `SWD\Wintun`/`ROOT\Wintun`
enumerators and reads the protected NLA profile count. It creates and removes the
same deterministic adapter 12 times, verifies the actual GUID each time, rejects
concurrent ownership, requires production teardown to release the alias and GUID
before returning, proves an existing alias is not renamed, and requires the final
device inventory to equal the baseline. `--wintun-lifecycle-test` runs only this
focused elevated check.

Before the transport scenarios, the harness starts a bounded child process. It
parks the real client controller in a failed TCP connection retry and requires
`stop()` to cancel in under two seconds, then interrupts real server adapter/setup
startup and requires cancellation in under five seconds. The parent fails and
terminates that child after 20 seconds if shutdown ever regresses into a hang.

Each transport scenario binds the server and two clients to the selected
physical IPv4 address, matching the original C++ E2E topology, and creates three
real Wintun adapters. It authenticates both clients, verifies bidirectional chat,
then sends IPv4 probes through the production TLS/DTLS record framing, server
source binding, peer router, and receiving-client packet validator. Because two
independent tunnel clients share one Windows host in this topology, probe packets
are consumed by a test-only observer immediately before receiving-client Wintun
injection; the test does not claim to benchmark the host IP stack or physical
NIC. Adapter, route, firewall, session, and teardown behavior remains real.

For each transport and direction, the E2E records 30 RTT samples and transfers
2 MiB in 1,651 bounded frames, enforcing a 1,000 ms p95 latency ceiling and a
0.5 Mbit/s goodput floor. It also verifies the maximum 1,380-byte tunnel packet,
oversized packet/chat rejection without session loss, authenticated-chat sender
isolation, rate-limit recovery, and same-alias reconnect while the peer and
server stay online. The server-originated chat path is also driven through its
complete fanout budget and recovery window. Before the UDP clients connect, 320 simultaneous malformed source
tuples are sent to the real listener; the process thread count may grow by at
most four, and a valid client must connect after the one-second rate window.
Before TCP clients connect, 96 raw sockets hit the real listener and the test
requires the pre-Schannel per-source worker cap to hold and recover.
UDP reconnect uses an eight-record rotation threshold, requires at
least one wolfSSL DTLS 1.3 KeyUpdate with zero failures, and proves traffic after
the update. TCP records that Schannel owns its provider-managed key epochs and
does not expose application-initiated KeyUpdate. The TCP scenario then stalls an
authenticated receiver, floods maximum-size encrypted tunnel frames until real
Winsock backpressure stops progress, and requires server shutdown to interrupt
the blocked TLS write within five seconds. A separate production-controller
scenario for each transport enables a 100 ms test heartbeat, suppresses
authenticated acknowledgements, requires the client to enter `Reconnecting`,
restores acknowledgements, deliberately rejects the first newly authenticated
reconnect, requires the bounded scheduler to advance to attempt two, verifies
the next fresh session can send again, and proves explicit Stop prevents any
later heartbeat or reconnect. It then drops a separate default-off client and
proves that client becomes idle without sending a heartbeat or reconnecting. The
suite finally requires the exact Wintun device inventory to match its pre-run
baseline. Production defaults remain five seconds and 15 seconds; only the test
policy is accelerated.

At the end, the harness starts the actual adjacent `vpn.exe` directly with
`CreateProcessW`. The GUI must initialize D3D11, ImGui, its Win32 and DX11
backends, generate a valid 43-character base64url secret, render its core
controls, and present 30 frames within its deadline.

The harness writes and flushes its own `vpn-integration.log` beside the
executable; `--log-file <path>` selects another path. The bounded controller
child writes `vpn-controller-cancel.log`. The GUI writes `vpn-gui-smoke.log`
beside `vpn.exe`; caller-selected smoke-log paths are rejected because the GUI
runs elevated. The file is opened by handle, and reparse points or hard-linked
targets are rejected before truncation. No output-redirection
wrapper or PowerShell networking command is involved.
`--repair-network` is a one-time,
explicit recovery option for a DHCP adapter whose Windows-owned local `/32`
route was deleted by an older TrueTunnel build. It uses `IpReleaseAddress` and
`IpRenewAddress`, so the selected adapter briefly loses connectivity while its
lease is reacquired.

```powershell
# Prompts through native UAC, creates real Wintun adapters, runs both transports,
# then runs the actual GUI smoke test.
.\vpn_integration_test.exe --no-pause

# Optional explicit log destination.
.\vpn_integration_test.exe --no-pause --log-file C:\Logs\vpn-e2e.log

# Standalone GUI smoke; the app writes vpn-gui-smoke.log beside vpn.exe.
.\vpn.exe --gui-smoke-test
```

## Traffic flow

```text
Application traffic
        |
Wintun virtual IPv4 packet
        |
TrueTunnel typed frame
        |
TCP: Schannel TLS 1.3       UDP: wolfSSL DTLS 1.3
        |
Physical network
```

## Licensing

TrueTunnel's own source is offered under the MIT License or GPLv2. The default
build statically links wolfSSL, which is offered under GPLv3 or a commercial
wolfSSL license. Without a commercial wolfSSL license, redistribution of the
combined executable must comply with GPLv3, including Corresponding Source
requirements. See `LICENSE`, `NOTICE`, and `THIRD_PARTY.md`; this summary is not
legal advice.
