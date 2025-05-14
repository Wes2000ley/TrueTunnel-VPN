📦 Third-Party Licenses
This project, TrueTunnel VPN, incorporates several third-party libraries and components.
Each component is governed by its respective license. You are responsible for complying with these terms when using, modifying, or redistributing this software.

🔐 OpenSSL
Website: https://www.openssl.org/

License: Apache License 2.0

Purpose: Provides TLS 1.2/1.3 encryption and cryptographic primitives.

🛡️ FIPS Compliance Notice
This project redistributes the OpenSSL FIPS 140-3 validated module (version 3.1.2) in its original, unmodified binary form.
See the FIPS Notice for full redistribution terms.

⚠️ Important:
TrueTunnel VPN itself is not FIPS-certified.
Inclusion of the OpenSSL FIPS module does not imply compliance with FIPS 140-3.
You must not claim FIPS validation unless your build environment, configuration, and use strictly conform to the official CMVP certificate requirements.

🌐 Wintun
Website: https://www.wintun.net/

License: GNU General Public License v2.0 (GPLv2)

Purpose: Provides a virtual TUN/TAP adapter for Windows networking.

The wintun.dll binary is redistributed unmodified.

⚠️ GPLv2 Applicability:
If you redistribute TrueTunnel VPN (even under MIT), the GPLv2 terms still apply to Wintun.
Redistribution must fully comply with GPLv2 obligations, including offering source code or an equivalent written offer.

🖥️ wxWidgets
Website: https://www.wxwidgets.org/

License: wxWindows Library License 3.1 (based on LGPL-2.1 with exceptions)

Purpose: Cross-platform C++ GUI library used to build the TrueTunnel VPN user interface.

📜 Special License Note
The wxWindows License allows usage in both open-source and proprietary software, without the strict copyleft requirements typical of LGPL libraries.
You are permitted to link against wxWidgets without your application becoming subject to the LGPL.

For full terms, see the wxWidgets License FAQ.

⚙️ EASTL (Electronic Arts Standard Template Library)
Repository: https://github.com/electronicarts/EASTL

License: BSD-3-Clause

Purpose: High-performance, drop-in alternative to the standard C++ STL, used for internal data structures.

🧩 cxxopts
Repository: https://github.com/jarro2783/cxxopts

License: MIT License

Purpose: Lightweight, header-only library for command-line argument parsing.

🎨 termcolor
Repository: https://github.com/ikalnytskyi/termcolor

License: BSD-3-Clause

Purpose: Provides cross-platform terminal color output for better CLI readability.

📄 License Summary
This third-party license summary is current as of May 2025.
If you redistribute TrueTunnel VPN or incorporate it into another product, you are responsible for ensuring your own compliance with all applicable third-party license terms — particularly in commercial, redistributed, or closed-source settings.

📘 For full license texts, see the LICENSE file included in this project.
