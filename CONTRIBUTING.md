# Contributing to TrueTunnel

Thank you for helping improve TrueTunnel. Contributions should be small,
reviewable, and explain their security and operational impact. This repository
targets native Windows; Linux and macOS builds are not supported.

## Development environment

Use Windows 11 or Windows Server 2022 or newer, Visual Studio 2022 with a
current Windows SDK, CMake 3.24+, Node.js 22.12+ with npm, and WebView2 Evergreen
Runtime. The project requires
C++23. The first configure may need network access to retrieve the pinned
wolfSSL source archive. Do not replace `deps/wintun.dll`; its SHA-256 is
checked during configuration.

From a PowerShell prompt in the repository root:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DBUILD_TESTING=ON
cmake --build build --config Release --parallel
```

## Validation checklist

Run the deterministic suite before opening a pull request:

```powershell
ctest --test-dir build -C Release --output-on-failure
```

For GUI changes, also run the UAC-free visual test and inspect the generated
native screenshot beside the executable. Run the frontend matrix and inspect
its full-page captures under `frontend/test-results/captures/`:

```powershell
ctest --test-dir build -C Release --output-on-failure -R ^vpn_gui_visual_test$
cd frontend
npm test
```

The full `vpn_integration_test.exe` exercises real Schannel/TCP and wolfSSL
DTLS/UDP paths, Wintun, routing, and teardown. It requires administrator
consent and a usable physical IPv4 adapter. Run it only when you can review
its log and clean up its test adapters:

```powershell
.\build\Release\vpn_integration_test.exe --no-pause `
  --log-file C:\Logs\truetunnel-e2e.log
```

Never include generated logs, tunnel secrets, credentials, or system-specific
network details in a patch. Explain tests that cannot run and why.

Use accessible semantic controls, preserve keyboard focus and reduced-motion
behavior, and check light/dark, compact, and long-content layouts. Never put a
shared key in React state, a web message, browser storage, or a test capture.
The IPC contract lives in `src/desktop/BridgeProtocol.h`; native validation is
mandatory even if TypeScript has already validated a form.

## Pull requests

Describe the problem, the user-visible effect, and the smallest safe design.
For protocol, authentication, adapter, or privilege changes, include the
trust boundary, failure behavior, and compatibility impact. Update relevant
documentation and tests. Do not claim an audit, certification, or performance
result that was not measured in the submitted build.

By contributing, you agree that your contribution is provided under the
project terms in [LICENSE](LICENSE).
