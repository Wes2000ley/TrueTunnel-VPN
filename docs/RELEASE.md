# TrueTunnel release checklist

This checklist is for maintainers preparing a distributable Windows artifact.
This tree is **3.1.0-preview.1**; the last stable tag is **V3 (3.0.0)**.
The production executable is `TrueTunnel.exe`.

The [preview release notes](releases/3.1.0-preview.1.md) explicitly list the
pending elevated qualification. Preview publication does not satisfy or waive
the release-candidate/stable gates below. Keep evaluation previews marked as
GitHub pre-releases, not the latest stable release.

## Before tagging

- Confirm the version agrees in `CMakeLists.txt`, `src/version.rc`, the GUI
  metadata, and release notes.
- Review the security and limitation statements in `README.md` and
  `docs/SECURITY-DESIGN.md`; do not claim FIPS validation, independent audit,
  per-peer revocation, IPv6, kill switch, DNS policy, or seamless roaming.
- Run the full Release build and registered CTest suite.
- Run one elevated real-stack E2E on a clean Windows machine for both TCP and
  UDP, including the actual `TrueTunnel.exe` GUI smoke path.
- Confirm the E2E log reports stable Wintun identity, no leaked adapter, route,
  firewall, or session rows, and successful transport cleanup.
- Inspect the GUI visual-test report at desktop, compact, minimum, and scrolled
  sizes. Check that no text or controls are clipped.

## Build and artifact checks

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DBUILD_TESTING=ON
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
.\build\Release\vpn_integration_test.exe --no-pause `
  --log-file C:\Logs\truetunnel-release-e2e.log
```

Inspect `build/Release/TrueTunnel-Release.zip`. It should contain:

```text
TrueTunnel.exe
wintun.dll
README.md
LICENSE
NOTICE
THIRD_PARTY.md
SECURITY.md
CHANGELOG.md
CONTRIBUTING.md
CODE_OF_CONDUCT.md
docs/
licenses/
```

Verify the embedded manifest is `asInvoker`, the normal desktop is unelevated,
and only the native worker requests UAC. Verify version metadata, dependency
notices, and the Wintun SHA-256 before publishing. Run the frontend matrix from
`frontend/` with `npm test`, then exercise real GUI start/stop/tray behavior for
both transports. Do not substitute simulated frontend states for that check.

The package includes the focused guides and diagrams, plus the exact source and
third-party license texts required by the selected build. Test harnesses and
debug symbols are not release payloads.

## Integrity and distribution

- Build from a clean, reviewed source revision with the pinned wolfSSL archive
  and repository `deps/wintun.dll`.
- Record SHA-256 digests for `TrueTunnel.exe`, `wintun.dll`, and the release zip.
- If signing is added by a distributor, verify the Authenticode signature on a
  clean Windows machine and publish the certificate identity/fingerprint.
- Keep the application directory administrator-writable and standard-user
  read-only where practical. The runtime DLL hash is defense in depth, not a
  substitute for protected installation or an updater.
- Do not distribute a human password as a shared key. Explain that the generated
  group credential must be transferred through a trusted channel and regenerated
  after exposure or membership changes.

## Licensing

TrueTunnel's source is MIT/GPLv2 as described in `LICENSE`. The default build
statically links wolfSSL 5.9.2, which is available under GPLv3 or a commercial
license. Confirm the selected wolfSSL terms before redistribution and ship the
`licenses/` directory, `NOTICE`, and `THIRD_PARTY.md`. Corresponding Source
obligations for GPLv3 redistribution remain the distributor's responsibility.

## Publish with evidence

Publish the version, supported Windows baseline, artifact digests, transport
profiles, known limitations, and test evidence. Include the E2E log location
and clearly mark environment-dependent checks such as RRAS/NAT. Never publish
shared keys, private certificates, machine identifiers, or unredacted logs.

For the test matrix and acceptance thresholds, see
[`TESTING.md`](TESTING.md). For operational rollback and cleanup, see
[`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).
