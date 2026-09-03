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

## Dear ImGui

- Version: 1.91.8-docking
- Repository: https://github.com/ocornut/imgui
- License: MIT
- Purpose: native graphical user interface

The release ZIP copies the exact MIT license from the Conan package used by the
selected build configuration.

## FreeType and transitive font/image libraries

- FreeType 2.13.3: FreeType License or GPLv2
- Brotli: MIT-style license
- bzip2: bzip2 license
- libpng: libpng license
- zlib: zlib license

FreeType provides font rendering for Dear ImGui. Its Conan package may link the
listed libraries transitively. The release ZIP copies their exact package
license texts so the binary distribution retains the notices for the resolved
build.

## Windows platform services

The application calls Schannel, SSPI, CNG, CryptoAPI, Winsock, Direct3D, and
other Windows APIs through the Windows SDK. These operating-system components
are not bundled cryptographic libraries.

TrueTunnel does not depend on or redistribute OpenSSL.
