# TrueTunnel VPN

A secure, minimalist, **FIPS-capable** VPN over TCP using TLS and the Wintun driver.  
Designed for simple, authenticated IP tunnels between trusted peers — no third-party servers, just you and your traffic.

> ⚠️ **Disclaimer**: While this software uses the OpenSSL FIPS 140-3 validated module (`fips.dll`),  
> **this project and its author have not been certified or validated under FIPS 140-3 by NIST or CMVP**.  
> Use of this module does **not** imply your usage or distribution is FIPS-compliant or certified.

---

## ✨ Features

* 🔒 **Encrypted tunneling over TLS 1.2/1.3** using OpenSSL FIPS provider
* 🔐 **Mutual authentication** via HMAC-SHA256 over nonces + password
* 💬 **Interactive messaging channel** over the encrypted tunnel
* 🧠 **Raw IP tunnel** via Wintun — handles TCP, UDP, ICMP, etc.
* 🧱 **Works through NAT** (client side — no port forwarding required)
* ⚙️ **GUI
* 🪪 **Single binary, no install**, no registry modification
* 🧵 Dual-threaded packet pump with optional control channel
* 🖥️ Full Windows compatibility — ideal for power users or lab setups

---

## 🚀 Getting Started

### 🧰 Requirements

* Windows 10/11 (admin privileges required)
* [Wintun driver](https://www.wintun.net/) (`wintun.dll` must be present)
* OpenSSL 3.x with FIPS module (`fips.dll`, `fipsmodule.cnf`, `openssl.cnf`)

### 🛠️ Building

```bash
git clone https://github.com/yourname/vpn
cd vpn
cmake -B build
cmake --build build --config Release
```

### ⚠️ Important: First Run

Before using the VPN, run the following once to install the FIPS module:

```bash
run_fipsinstall.bat
```

This step configures `fipsmodule.cnf` and ensures OpenSSL uses the FIPS provider correctly.

---

## 🌐 Usage

### ✅ Server (public IP or port-forwarded):


### ✅ Client (can be behind NAT):


## 🌍 Network Behavior

* ✅ Client can be **fully behind NAT**, no port forwarding required
* ✅ All traffic is routed via Wintun (IP-layer)
* ✅ Supports **TCP, UDP, ICMP, DNS, etc.**
* ✅ Compatible with tools like `ping`, `curl`, `ssh`, etc.
* ⚠️ Server must be reachable (public IP or NAT port forward)

---

## 🔐 Security Design

## 📛 FIPS 140-3 Notice

This project **includes** the OpenSSL FIPS 140-3 validated module (version 3.1.2, certificate #A3548)  
as provided by The OpenSSL Project. It is redistributed **unmodified**, alongside its official security policy.

> ⚠️ **FIPS Validation Disclaimer**:
> - This software has **not** itself been submitted to or validated by NIST or the CMVP.
> - The author (Wesley Atwell) makes **no claim** of FIPS 140-3 certification for this application.
> - You are **solely responsible** for ensuring your deployment meets applicable regulatory or compliance standards.
> - Any deviation from the tested operational environment described in the OpenSSL FIPS module may **invalidate** FIPS status.

For compliance-sensitive use cases, consult official CMVP guidance:
👉 [https://csrc.nist.gov/projects/cryptographic-module-validation-program](https://csrc.nist.gov/projects/cryptographic-module-validation-program)


| Layer            | Technology     | Details                          |
| ---------------- | -------------- | -------------------------------- |
| Transport        | TCP            | Encrypted with OpenSSL           |
| Encryption       | TLS 1.2/1.3    | AES-128/256-GCM only (FIPS only) |
| Authentication   | HMAC-SHA256    | Derived from shared passphrase   |
| Tunnel Interface | Wintun         | High-performance IP adapter      |
| Key Management   | Ephemeral      | 3072-bit RSA self-signed per run |
| Memory Security  | OpenSSL Secure | Nonces & HMAC buffers zeroed     |

---

## 📦 File Structure

| File                  | Description                             |
| --------------------- | --------------------------------------- |
| `vpn.exe`             | Compiled VPN binary                     |
| `wintun.dll`          | Wintun driver DLL                       |
| `fips.dll`            | OpenSSL FIPS shared object              |
| `fipsmodule.cnf`      | FIPS module configuration               |
| `openssl.cnf`         | OpenSSL base config (loads FIPS module) |
| `run_fipsinstall.bat` | One-time FIPS initialization script     |

---

## ⚠️ Limitations

* Only one client can connect at a time
* IPv4 only (no IPv6 support)
* Static IP setup — no DHCP or DNS by default
* No reconnection logic — restart on disconnect
* Server must run with admin privileges
* MTU must be tuned manually (`1380` is a good default)


---

## 🧪 Tested Scenarios

| Test Case                                 | Result                   |
| ----------------------------------------- | ------------------------ |
| Client behind NAT → public server         | ✅ Works                  |
| Client & server on same LAN               | ✅ Works                  |
| Encrypted ping, curl, SSH                 | ✅ Works                  |
| UDP over tunnel (e.g., DNS, game traffic) | ✅ Works                  |
| Large packets > MTU (unfragmented)        | ⚠️ Limit manually        |
| Client/server on mobile networks          | ✅ Works (as client only) |

---

## 🛰️ Traffic Flow (Client ↔ Server)

```text
CLIENT (behind NAT)                            SERVER (public IP)
──────────────────────                        ──────────────────────
[App Data: DNS, HTTP]                         [App Data: DNS, HTTP]
        ↓                                            ↑
[Virtual UDP/TCP: 10.0.0.2 → 10.0.0.1]        [Virtual UDP/TCP: 10.0.0.2 → 10.0.0.1]
        ↓                                            ↑
[Virtual IP Packet (Layer 3)]                [Virtual IP Packet (Layer 3)]
        ↓                                            ↑
[TLS Encryption (Layer 4)]                   [TLS Decryption (Layer 4)]
        ↓                                            ↑
[Real TCP: 192.168.1.42 → 198.51.100.1]      [Real TCP: 198.51.100.1 ← 192.168.1.42]
        ↓                                            ↑
[Ethernet / Wi-Fi Frame]                    [Ethernet / Wi-Fi Frame]
        ↓                                            ↑
[Physical Medium (copper/fiber)]            [Physical Medium]
```

---

## 📦 Encapsulation View (ASCII)

```text
┌────────────────────────────────────────────────────────────────────────┐
│               Real TCP over Ethernet/Wi-Fi (Layers 1–4)                │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │              TLS Encrypted Stream (Real Layer 4)                 │  │
│  │  ┌────────────────────────────────────────────────────────────┐  │  │
│  │  │      Virtual IP Packet (VPN Tunnel Payload, Layer 3)       │  │  │
│  │  │  ┌──────────────────────────────────────────────────────┐  │  │  │
│  │  │  │   Virtual TCP/UDP Header: 10.0.0.2 → 10.0.0.1         │  │  │  │
│  │  │  │  ┌────────────────────────────────────────────────┐  │  │  │  │
│  │  │  │  │   Application Data: DNS / HTTP / SSH etc.     │  │  │  │  │
│  │  │  │  └────────────────────────────────────────────────┘  │  │  │  │
│  │  │  └──────────────────────────────────────────────────────┘  │  │  │
│  │  └────────────────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🧠 Future Ideas

* [ ] UDP or QUIC-based transport
* [ ] Cross-platform support (Linux + tun)
* [ ] Multiple clients (multi-threaded accept)
* [ ] GUI interface for setup and logs
* [ ] Dynamic routing or NAT helper
* [ ] Compression (optional)

---

## 📜 License

Dual-licensed under **MIT** or **GPLv2** — your choice.

> ⚠️ Use responsibly. This software is not intended for high-risk or regulated production environments.
> You are solely responsible for compliance with applicable local laws, including export controls and cryptographic regulations.

---

👏 Credits

Wintun by WireGuard

OpenSSL Project

wxWidgets Library

EASTL (EA's STL)

cxxopts (CLI parser)

termcolor (Terminal colors)
