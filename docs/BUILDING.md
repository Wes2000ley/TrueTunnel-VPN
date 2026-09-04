# Building TrueTunnel

## Supported environment

- Windows 11 or Windows Server 2022 or newer (x64 build).
- Visual Studio 2022 with the Desktop C++ workload and a current Windows SDK.
- CMake 3.20 or newer and Conan 2.0.5 or newer.
- The repository's `deps/wintun.dll`. The build refuses a missing or modified
  copy before configuring dependencies.
- Network access on the first configure so CMake can fetch the pinned wolfSSL
  5.9.2 archive. OpenSSL is not required.

The Schannel profile depends on Windows TLS 1.3 support. The application must
run elevated because Wintun, IP Helper, routes, and firewall rules are system
resources.

## Configure and build

Install the Conan dependencies and generate the toolchain before configuring a
clean Visual Studio build:

```powershell
conan profile detect --force
conan install . -of=build/conan -s build_type=Release --build=missing
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_TOOLCHAIN_FILE=build/conan/build/generators/conan_toolchain.cmake `
  -DCMAKE_PREFIX_PATH=build/conan/build/generators -DBUILD_TESTING=ON
cmake --build build --config Release --parallel
```

The configure-time Wintun check compares the supplied DLL with the reviewed
SHA-256. CMake also pins wolfSSL's source archive by SHA-256 and disables
protocol/cipher families outside the product's TLS/DTLS profile.

## Outputs

The production target remains named `vpn` for build-system compatibility, but
its external file name is **`TrueTunnel.exe`**. A Release build places it in
`build/Release/` beside the pinned `wintun.dll`, `README.md`, the root project
notices, `licenses/`, and `docs/`. The fallback UAC manifest is
`TrueTunnel.exe.manifest` when the Windows SDK `mt.exe` tool is unavailable;
when `mt.exe` is available the manifest is embedded in the executable.

The package step creates `TrueTunnel-Release.zip` (and the corresponding
configuration name for other generators). It contains:

- `TrueTunnel.exe` and `wintun.dll`;
- `README.md`, `SECURITY.md`, `CHANGELOG.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, the project notices, and the focused `docs/`
  guides/diagrams;
- `licenses/` with the TrueTunnel, Wintun, wolfSSL, ImGui, FreeType, and
  transitive dependency notices used by the build.

The test-only executables (`vpn_integration_test.exe`,
`vpn_secure_transport_test.exe`, `vpn_gui_visual_test.exe`, and
`vpn_daemon_harness.exe`) are not release payloads.

## Developer configurations

Use `-DBUILD_TESTING=ON` for the normal test targets. `-DENABLE_ANALYSIS=ON`
enables `clang-tidy` when it is installed and discoverable. Release builds use
static MSVC runtime linking, Control Flow Guard, ASLR, DEP, and CET-compatible
linking where the toolchain supports those options.

Do not copy DLLs from another Wintun release into the output directory. If the
pin changes intentionally, update the reviewed digest in `CMakeLists.txt`, the
loader's matching digest, release notes, and the test fixture as one reviewed
change.

## Clean rebuild

To preserve source changes while removing generated state, close running
TrueTunnel processes and remove only the generated build directory, then
configure again:

```powershell
Remove-Item -LiteralPath build -Recurse -Force
conan install . --output-folder=build/conan --build=missing -s build_type=Release
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_TOOLCHAIN_FILE=build/conan/build/generators/conan_toolchain.cmake `
  -DCMAKE_PREFIX_PATH=build/conan/build/generators -DBUILD_TESTING=ON
cmake --build build --config Release --parallel
```

If an old build left a Wintun adapter behind, follow the exact-identity cleanup
in [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) before rebuilding. Never remove a
shared Wintun driver or unrelated adapter by a broad name match.

For the validation matrix, see [`TESTING.md`](TESTING.md); for release signing,
integrity, and license checks, see [`RELEASE.md`](RELEASE.md).
