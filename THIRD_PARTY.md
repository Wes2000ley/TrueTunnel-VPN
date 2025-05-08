# 📦 Third-Party Licenses

This project makes use of the following third-party libraries and components.  
Each is governed by its own license terms, summarized below.

---

### **OpenSSL**

- **Website**: https://www.openssl.org/
- **License**: Apache License 2.0
- **Purpose**: Provides TLS 1.2/1.3 encryption and cryptographic primitives
- **FIPS Note**:  
  Includes the [OpenSSL FIPS 140-3 validated module (version 3.1.2)](https://www.openssl.org/docs/fips.html), redistributed **without modification**.  
  See full redistribution terms in the project’s [FIPS Notice](./README.md) section.

> ⚠️ This project is **not FIPS certified**, and redistribution of the FIPS module **does not grant validation**.  
> You must not claim compliance unless your build strictly follows OpenSSL’s official validated configuration.

---

### **Wintun**

- **Website**: https://www.wintun.net/
- **License**: GNU General Public License v2 (GPLv2)
- **Purpose**: Acts as the virtual TUN/TAP adapter on Windows
- **Redistribution**: The unmodified `wintun.dll` is shipped for end-user convenience.  
  Per [WireGuard’s terms](https://www.wintun.net/), Wintun is open source but redistribution **must comply with GPLv2**.

---

### **EASTL (Electronic Arts Standard Template Library)**

- **Repository**: https://github.com/electronicarts/EASTL
- **License**: BSD-3-Clause
- **Purpose**: Drop-in STL replacement with performance-oriented containers

---

### **cxxopts**

- **Repository**: https://github.com/jarro2783/cxxopts
- **License**: MIT
- **Purpose**: Lightweight C++ library for command-line argument parsing

---

### **termcolor**

- **Repository**: https://github.com/ikalnytskyi/termcolor
- **License**: BSD-3-Clause
- **Purpose**: Provides ANSI terminal color formatting for cross-platform CLI output

---

### 🗓️ License Snapshot

This license list is current as of **May 2025**.  
You are responsible for ensuring your own compliance with all applicable upstream license terms, especially in commercial or redistributable builds.
