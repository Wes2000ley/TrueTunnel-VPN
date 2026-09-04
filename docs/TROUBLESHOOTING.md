# TrueTunnel troubleshooting

Start with the activity panel. The test harnesses also write the flushed logs
listed below; normal interactive sessions are not advertised as having a
persistent log file. Do not paste the shared key into an issue or command line.
Remove or redact addresses and secrets before sharing test logs.

## The app does not start

TrueTunnel is an elevated Windows application. Right-click `TrueTunnel.exe`
and choose **Run as administrator**. A missing or changed `wintun.dll` is a
hard failure by design; restore the DLL shipped in the same
`TrueTunnel-<Config>.zip` rather than downloading a replacement into the
application directory. Windows 11/Server 2022+ and a current x64 build are
required.

The production binary is `TrueTunnel.exe`. The test-only binary is
`vpn_integration_test.exe`; it is not the VPN client and its direct launch is
expected to request UAC for the real-stack test.

## Client cannot connect

Check all of these values:

1. The Server is running and listening on the selected protocol.
2. The Client uses the server's reachable IPv4 address or hostname and the
   **exact same port**. The server-address field is not the listening port.
3. Both peers use the same transport and the same 43-character shared key.
4. Windows Firewall has a rule for the exact executable, protocol, local
   address, and port.
5. The physical uplink is still present and has an IPv4 address.

Changing TCP/UDP, address, port, or key requires a fresh Disconnect/Connect.
The endpoint is resolved again for each fresh attempt. A DNS result alone does
not authenticate a peer; the subsequent TLS/DTLS proof still requires the group
key.

## Throughput or latency is poor

Prefer UDP on a network that permits it. TCP is a fallback: outer TCP ordering
can cause TCP-in-TCP head-of-line blocking after a lost segment. Keep the tunnel
MTU at 1380 unless you have measured a different path and understand the
fragmentation consequences. Inspect the E2E log for baseline and post-renewal
latency/throughput rather than relying on a single speed test.

During TCP renewal a bounded pause is expected. A successful handoff keeps the
same Wintun GUID/LUID and IPv4 address. A failed pre-activation handoff should
resume OLD; a post-activation ambiguity intentionally closes both generations
and relies on optional recovery to establish a clean session.

## Automatic recovery

Recovery is Client-only, optional, and off by default. It must be enabled while
idle and is locked while connected. It sends encrypted authenticated heartbeats
on the selected TCP or UDP transport and uses capped equal-jitter backoff up to
30 seconds. It is intended for short outages, not seamless roaming or packet
preservation. Explicit **Disconnect** cancels retries.

If recovery loops, verify the endpoint/port/key first. The next fresh handshake
must succeed independently; do not weaken the heartbeat interval or accept
unbounded retries to hide a configuration failure.

## Wintun adapter names or duplicates

The supported alias is `TrueTunnel VPN Adapter`. It has a deterministic identity
so a normal start/stop cycle should not create `TrueTunnel VPN Adapter 1`, `2`,
or later. Stop TrueTunnel and wait for its process to exit before reconnecting.

For read-only diagnostics from an elevated PowerShell prompt:

```powershell
Get-NetAdapter -IncludeHidden |
  Where-Object { $_.InterfaceDescription -match 'Wintun|TrueTunnel' } |
  Format-List Name,InterfaceDescription,Status,MacAddress,ifIndex
pnputil /enum-devices /class Net /connected
pnputil /enum-drivers | Select-String -Pattern 'Wintun|WireGuard'
```

Do not delete registry keys or remove every adapter whose display name contains
`TrueTunnel`. A Wintun driver package may be shared with WireGuard. If an exact
TrueTunnel adapter survives a crash, record its name, GUID/LUID, service, and
whether another TrueTunnel process is still running, then use the product's
identity-scoped cleanup or ask an administrator to remove only that exact
device. Never remove a foreign interface that merely owns a similar alias.

## “Address already exists” or stale routes

Disconnect and allow Windows time to retire the exact adapter alias/GUID. Check
only the owned IPv4 rows and routes; do not remove a route merely because its
destination matches. Another VPN, Hyper-V, WSL, or a corporate policy may own
the row. The product tracks its own rows and fails closed when ownership cannot
be proven.

`--repair-network` is an explicit one-time option for a DHCP uplink whose local
`/32` route was removed by an older build. It uses Windows IP Helper release/
renew and briefly interrupts that physical adapter. Do not use it as a generic
VPN repair command.

## Internet sharing does not work

Peer-to-peer authenticated traffic can work without RRAS. Internet-bound client
traffic additionally needs Windows RRAS NAT and a correctly selected physical
uplink. If RRAS is unavailable, TrueTunnel reports that translation is not
active; it does not silently enable ICS or readdress an existing interface.

## Logs and safe bug reports

- `vpn-integration.log` — real-stack harness output beside
  `vpn_integration_test.exe`.
- `TrueTunnel-gui-smoke.log` — actual production GUI smoke output beside
  `TrueTunnel.exe`.
- `vpn-controller-cancel.log` — bounded cancellation child output.
- `build/Release/gui-visual-test/` — UAC-free visual PNGs/report.

Use `--log-file C:\Logs\truetunnel-e2e.log` with the integration harness when a
central log is preferable. The GUI rejects caller-selected smoke-log paths
because it is elevated. Redact the shared key, hostnames, and public addresses
before sharing any log.

For a reproducible report, include the version (`3.1.0-dev` for this tree),
Windows build, exact transport, build configuration, first error line, and
whether the issue occurs after a clean reboot. See [`TESTING.md`](TESTING.md)
for the supported validation commands.
