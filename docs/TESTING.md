# Testing TrueTunnel

Testing is split into fast deterministic checks, a UAC-free GUI visual run,
and an elevated end-to-end run against the real Wintun/IP Helper/Winsock stack.
Run the fast suite before every change; run the elevated suite before a release
or any change to transport, lifecycle, networking, or GUI startup.

## Fast suite

Build with `-DBUILD_TESTING=ON`, then run:

```powershell
ctest --test-dir build -C Release --output-on-failure
```

The registered tests cover secure transport framing/profile checks, redirect
stream logging, pinned Wintun loading and identity, DLL tamper rejection,
source binding and endpoint validation, the UAC-free ImGui visual regression,
and daemon lifecycle/recovery behavior. The exact names can be listed with:

```powershell
ctest --test-dir build -N
```

Focused examples:

```powershell
ctest --test-dir build -C Release --output-on-failure -R vpn_secure_transport_test
ctest --test-dir build -C Release --output-on-failure -R vpn_gui_visual_test
```

The visual test builds the same dashboard sources into an unelevated test
executable. It renders desktop, compact, and minimum-supported sizes, exercises
TCP/UDP and Server/Client states, dialogs, keyboard focus, recovery states,
validation errors, log scrolling, and long endpoint text. It writes PNGs and a
flushed report below `build/Release/gui-visual-test/`.

## Elevated real-stack E2E

The integration harness must run on Windows with Administrator consent, a usable
physical IPv4 adapter, and the adjacent pinned `wintun.dll`:

```powershell
.\build\Release\vpn_integration_test.exe --no-pause
```

When started unelevated, it relaunches itself through native Windows UAC and
returns the elevated child's exit code. It does not use PowerShell as a network
launcher or rely on redirected console output. To choose a log file, pass a
safe explicit path:

```powershell
.\build\Release\vpn_integration_test.exe --no-pause `
  --log-file C:\Logs\truetunnel-e2e.log
```

The harness flushes `vpn-integration.log` beside itself by default. The
controller-cancellation child writes `vpn-controller-cancel.log`. At the end,
the harness launches the actual adjacent `TrueTunnel.exe` with
`CreateProcessW --gui-smoke-test`; that process writes
`TrueTunnel-gui-smoke.log` beside the executable. Caller-selected GUI smoke log
paths are rejected because the GUI runs elevated.

## What the E2E proves

For TCP and UDP, the harness creates real Wintun adapters, routes, firewall
rules, and sessions. It authenticates two clients, verifies bidirectional chat
and numbered IPv4 probes, validates maximum-size packets, rejects oversized or
spoofed input, isolates abusive chat senders, and checks teardown inventory.

It also exercises:

- deterministic Wintun GUID/LUID/alias reuse, exact cleanup, and foreign-alias
  collision safety;
- native TCP TLS renewal and UDP DTLS traffic-key rotation;
- strict sequence ordering, packet loss/duplication checks, throughput, and
  latency before and after TCP renewal;
- pre-activation rollback, post-activation fail-closed behavior, and exact lease
  ownership;
- heartbeat admission, bounded automatic reconnect, first-attempt rejection,
  recovery on the next attempt, and explicit-stop cancellation;
- malformed UDP tuple floods and raw TCP accept floods without unbounded worker
  growth;
- blocked encrypted writes and bounded shutdown under Winsock backpressure; and
- the actual production GUI's D3D11, ImGui, secret-generation, and core-control
  smoke path.

The E2E's local acceptance limits are a 1,000 ms p95 latency ceiling, a 0.5
Mbit/s goodput floor, and a 500 ms TCP renewal interruption ceiling. These are
test-machine/LAN acceptance criteria, not Internet performance guarantees. The
two-client same-host topology observes tunneled probes immediately before the
second Wintun injection, so it validates the VPN path without pretending to
benchmark the host's physical NIC or Windows IP stack.

## Reading a failure

Keep the complete log when reporting a failure. Search for the first `[FAIL]`,
`[!] Scenario error`, or `Scenario failed`; later cleanup errors may be
secondary. Include the build configuration, Windows version, selected physical
adapter, whether UAC was accepted, and whether another VPN was running.

Do not rerun a failed lifecycle test while a prior elevated process still owns
an adapter. Confirm the process has exited and inventory exact Wintun devices as
described in [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).

## Release gate

A release candidate requires a clean Release build, all registered CTest tests,
one successful elevated E2E run for both transports, a zero-leak final Wintun
inventory, and an inspected `TrueTunnel-<Config>.zip`. Record the E2E log and
machine limitations in the release evidence. RRAS/NAT is environment-dependent;
if it is unavailable, record that external Internet translation was not tested
while peer-to-peer tunnel validation still completed.
