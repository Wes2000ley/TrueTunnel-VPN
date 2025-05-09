# 📦 Third-Party Licenses

This project, **TrueTunnel VPN**, incorporates the following third-party libraries and components.  
Each component is governed by its respective license. You are responsible for complying with these terms in your use, modification, and redistribution.

---

### 🔐 OpenSSL

- **Website**: https://www.openssl.org/
- **License**: Apache License 2.0
- **Purpose**: Provides TLS 1.2/1.3 encryption and cryptographic primitives

#### 🛡️ FIPS Compliance Note

This project includes the [OpenSSL FIPS 140-3 validated module (version 3.1.2)](https://www.openssl.org/docs/fips.html), redistributed **in its original binary form** without modification.  
See full redistribution terms in the project’s [FIPS Notice](./README.md#redistribution-notice-for-openssl-fips-provider).

> ⚠️ **This project is NOT FIPS-certified.**  
> Inclusion of the OpenSSL FIPS module does not imply compliance.  
> **You must NOT claim FIPS validation** unless your environment, build process, and configuration exactly match the conditions described in the module's official CMVP certificate.

---

### 🌐 Wintun

- **Website**: https://www.wintun.net/
- **License**: GNU General Public License v2 (GPLv2)
- **Purpose**: Acts as the virtual TUN/TAP adapter on Windows

The `wintun.dll` is redistributed **unmodified** for user convenience.

> ⚠️ If you redistribute this project under a different license (e.g., MIT), the GPLv2 terms of Wintun **still apply** to `wintun.dll`.  
> Redistribution **must fully comply** with the GPLv2, including providing source or a written offer as required.

---

### ⚙️ EASTL (Electronic Arts Standard Template Library)

- **Repository**: https://github.com/electronicarts/EASTL
- **License**: BSD-3-Clause
- **Purpose**: High-performance drop-in STL replacement used for internal data structures

---

### 🧩 cxxopts

- **Repository**: https://github.com/jarro2783/cxxopts
- **License**: MIT
- **Purpose**: Lightweight, header-only command-line argument parser

---

### 🎨 termcolor

- **Repository**: https://github.com/ikalnytskyi/termcolor
- **License**: BSD-3-Clause
- **Purpose**: Cross-platform terminal output coloring for enhanced CLI readability

---

## 🗓️ License Summary

This license list is current as of **May 2025**.  
If you distribute a modified version of this project or incorporate it into a larger system, **you are responsible for ensuring your own compliance** with each upstream license — especially in commercial, redistributed, or closed-source deployments.

> 📘 For full license texts, see the [LICENSE](./LICENSE) file.
