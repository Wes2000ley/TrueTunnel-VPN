# Building TrueTunnel

## Requirements

- Windows 11 or Windows Server 2022 or newer, x64.
- Visual Studio 2022, Desktop C++ workload, and a current Windows SDK.
- CMake 3.24+, Node.js 22.12+ and npm. Node is a build tool, not a runtime dependency.
- Microsoft Edge WebView2 Evergreen Runtime to run the desktop and native GUI test.
- The reviewed `deps/wintun.dll` supplied in this repository.
- Network access on the first build for the pinned wolfSSL and WebView2 SDK archives,
  nlohmann JSON header, and lockfile-resolved frontend packages.

The desktop uses React, TypeScript, Vite, Radix Dialog, and Lucide icons. The
existing C++23 VPN engine remains responsible for all networking and cryptography.
Conan, Dear ImGui, FreeType, and OpenSSL are not used by the active build.

## Configure and build

From a normal PowerShell prompt in the repository root:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTING=ON
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

If multiple Node installations exist, select the supported executable with
`-DTRUETUNNEL_NODE=C:/path/to/node.exe`. npm must also be discoverable on PATH.
Do not reuse a build directory configured for the former Conan/ImGui frontend;
configure a new directory instead.

CMake verifies SHA-256 pins for Wintun, wolfSSL, the WebView2 SDK, and the JSON
header. It runs `npm ci --ignore-scripts`, TypeScript checking, Vite's production
build, then embeds the resulting HTML/JS/CSS as executable resources. Frontend
packages are exact-versioned with integrity hashes in `frontend/package-lock.json`.
There is no runtime localhost server, npm installation, external script/CDN,
or loose frontend asset directory in the release payload.

## Frontend development

```powershell
cd frontend
npm ci --ignore-scripts
npm run dev
npm run build
npm test
```

The browser preview cannot start a VPN or access a secret. Only automated tests
inject a simulated bridge. Production uses the native WebView2 message bridge;
do not add mock sessions or development-server URLs to the executable.

Playwright uses locally installed Microsoft Edge. Tests produce full-page,
scrolled, light/dark, and state captures under `frontend/test-results/captures/`,
and an HTML report under `frontend/playwright-report/`.

## Outputs and deployment

The internal target remains `vpn`; its public filename is `TrueTunnel.exe`.
`build/Release/TrueTunnel-Release.zip` contains the EXE, pinned Wintun DLL,
documentation, and exact third-party notices. Test executables and Node modules
are not shipped. The WebView2 loader is statically linked; the separately
installed Evergreen Runtime supplies the browser engine and its security updates.

The embedded `asInvoker` manifest keeps the desktop unelevated. Connect/Start
server launches the same executable as a privileged `--broker` child. That
branch never initializes WebView2. A normal app launch from an elevated shell
relaunches with the user's linked, unelevated token when available.

The worker requires same-user elevation. Accounts that must supply a different
administrator's credentials are not currently supported. Install the app into
an administrator-writable, standard-user-read-only location where practical.

`truetunnel_package` also runs when only documentation changes. Build that target
to refresh the ZIP after editing guides or screenshots. Use a fresh output
directory for release candidates so historical artifacts cannot contaminate
the package.

## Maintenance

`-DENABLE_ANALYSIS=ON` enables discoverable clang-tidy. Product C++ builds use
warnings as errors, `/sdl`, stack protection, static CRT, Control Flow Guard,
ASLR, DEP, and CET-compatible linking.

Keep frontend dependencies and Evergreen Runtime current, but review lockfile
updates. Never replace Wintun independently of its matching build/runtime pins.
See [Testing](TESTING.md), [Security design](SECURITY-DESIGN.md), and the
[release checklist](RELEASE.md) for the remaining release gates.
