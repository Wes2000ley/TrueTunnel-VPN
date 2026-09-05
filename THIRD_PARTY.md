# Third-party components

TrueTunnel uses the components below. Redistributors are responsible for the
terms that apply to their exact build and distribution.

## wolfSSL

- Version: 5.9.2 (`v5.9.2-stable`)
- Repository: https://github.com/wolfSSL/wolfssl
- Source archive: https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.9.2-stable.tar.gz
- Archive SHA-256: `2f4ef3d4fd387a9b3191d36a6316d69116c46ff69bb9583b6c82b36d7b8ca114`
- License: GPLv3, or a separate commercial license from wolfSSL Inc.
- Purpose: statically linked DTLS 1.3 and WolfCrypt implementation for UDP.

The default open-source build creates a combined executable subject to wolfSSL's
GPLv3 terms. A distributor that cannot comply with GPLv3 must obtain an
appropriate commercial wolfSSL license before distributing that build. The
release ZIP contains the exact upstream `LICENSING` file and GPLv3 `COPYING`
text from the pinned archive. Providing notices alone does not replace GPLv3
Corresponding Source obligations.

wolfGuard is not incorporated. Its `wolfguard.ko` component is Linux-kernel
software and is not a Windows transport library.

## Wintun prebuilt binary

- Website: https://www.wintun.net/
- License: Wintun Prebuilt Binaries License
- Purpose: Windows layer-3 tunnel adapter
- Distributed DLL SHA-256:
  `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`
- Distribution: the repository's unmodified `deps/wintun.dll` is copied next to
  the application executable.

WireGuard LLC publishes separate terms for the prebuilt `wintun.dll`. Those
terms, rather than the Wintun source repository's GPLv2 license, govern this
prebuilt binary distribution. The exact text is in
`licenses/Wintun-PREBUILT-LICENSE.txt` and the release ZIP.

## Modern desktop frontend

- React / React DOM 19.2.8: MIT.
- Radix UI Dialog 1.1.23 and its dependencies: MIT.
- Lucide React 1.41.0: ISC, with retained third-party icon notices.
- Runtime dependency versions and integrity hashes: `frontend/package-lock.json`.
- Purpose: the embedded React/TypeScript desktop interface.

The release ZIP includes `licenses/Frontend-NOTICES.txt`, assembled from the
exact installed runtime packages' LICENSE/NOTICE files. The script fails if a
notice is missing. The sole pinned fallback is react-remove-scroll-bar 2.3.8,
whose npm tarball omits LICENSE; its exact upstream MIT text is retained at
`licenses/react-remove-scroll-bar-MIT.txt` from
https://github.com/theKashey/react-remove-scroll-bar/blob/master/LICENSE.

TypeScript, Vite, Playwright, axe, and Prettier are development tools, not shipped
runtime modules. Dear ImGui and FreeType are no longer linked by the product.

## Microsoft WebView2

- SDK: 1.0.4191.47, NuGet `Microsoft.Web.WebView2`.
- Archive SHA-256: `f492bbf547d0da329553b6727435b677579b1e9f91cc9e4a1ad029366d5f23d0`.
- Purpose: Windows desktop web host, with statically linked SDK loader.
- Terms: Microsoft WebView2 SDK license, copied verbatim into
  `licenses/WebView2-LICENSE.txt` in the release ZIP.

The separately installed Microsoft Edge WebView2 Evergreen Runtime is not
bundled in the ZIP. Its runtime distribution terms and updates remain separate.

## nlohmann JSON

- Version: 3.12.0, single-header JSON parser for bounded native control messages.
- Header SHA-256: `aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63`.
- License: MIT; exact upstream text is in `licenses/nlohmann-json-MIT.txt`, from
  https://github.com/nlohmann/json/blob/v3.12.0/LICENSE.MIT.

## Windows platform services

The application calls Schannel, SSPI, CNG, CryptoAPI, Winsock, DWM, and
other Windows APIs through the Windows SDK. These operating-system components
are not bundled cryptographic libraries.

TrueTunnel does not depend on or redistribute OpenSSL.
