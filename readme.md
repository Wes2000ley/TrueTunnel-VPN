# TrueTunnel VPN

*A secure, minimalist, FIPS-capable VPN for Windows that speaks raw IP over a
TLS-encrypted TCP stream*.

TrueTunnel creates a point-to-point or **multi-point** (one server, many
clients) virtual /24 network with static addresses.  There are **no third-party
servers or SaaS accounts** – only you and the peers you trust.

> **FIPS disclaimer**  
> This project **bundles the OpenSSL 3.1.2 FIPS 140-3 validated module
> (`fips.dll`)**, but the TrueTunnel application itself has **not** been
> submitted to NIST/CMVP for validation.  Using the module does *not* make your
> deployment automatically FIPS-certified.

---

## ✨ Features

| Category          | Details                                                        |
|-------------------|----------------------------------------------------------------|
| **Crypto**        | TLS 1.2/1.3 with AES-GCM only • OpenSSL FIPS provider          |
| **Auth**          | Mutual HMAC-SHA-256 over nonces + shared passphrase            |
| **Tunnel**        | Raw IPv4 via **Wintun** (handles TCP/UDP/ICMP etc.)            |
| **Topology**      | /24 static pool – now supports **multiple clients per server** |
| **NAT-friendly**  | Client dials outbound TCP – no port-forwarding required        |
| **Zero-install**  | Single portable EXE, no registry writes                        |
| **Control-plane** | Optional in-band chat channel (`PACKET_TYPE_MSG`)              |
| **GUI**           | Custom ImGui front-end with themed dropdowns & sliders         |
| **Performance**   | Dual-threaded packet pumps, TCP NODELAY, zero-alloc fast path  |
| **Code quality**  | C++23, static CRT, LTO, Control-Flow-Guard, `/guard:cf`        |
| **Build**         | Pure CMake; all deps (Wintun, OpenSSL, ImGui) fetched locally  |

---

## 🧰 Requirements

* Windows 10/11 **with Administrator rights**
* `wintun.dll` (bundled)
* OpenSSL 3.x + `fips.dll`, `fipsmodule.cnf`, `openssl.cnf` (bundled)
* A single TCP port open on the **server** 

---

## 🛠️ Building

```bash
git clone https://github.com/<your-handle>/truetunnel
cd truetunnel
cmake -B build
cmake --build build --config Release
On first run execute run_fipsinstall.bat once to initialise the FIPS
module.

🚀 Usage
Role	Command	Notes
Server	vpn.exe --mode server --port 4433 --password "<secret>"	Needs public IP or port-forward
Client	vpn.exe --mode client --host <server-ip> --port 4433 --password "<secret>"	Works behind NAT

Each client receives 10.10.100.x where x is deterministic for that client,
so routes stay stable across reconnects.

🧭 Network Behaviour
Works through NAT and most firewalls (TCP outbound)

Multi-client routing: server forwards peer-to-peer traffic in user-space
before it hits the kernel, reducing latency

Handles any IPv4 protocol (SSH, DNS, games, etc.)

MTU fixed at 1380 (safe default through TLS/TCP)

🔐 Security Design
Layer	Tech	Notes
Transport	TCP	NODELAY + backlog tuning
Encryption	TLS 1.2/1.3	AES-256-GCM / AES-128-GCM only
Authentication	HMAC-SHA-256	Nonce + password, no PKI required
Key exchange	Ephemeral RSA-3072	Generated at each start-up
Tunnel IF	Wintun	In-kernel virtual NIC
Memory hygiene	OpenSSL secure calloc	Key material cleansed on free

📛 FIPS 140-3 Notice
The OpenSSL 3.1.2 FIPS module (certificate #A3548) is redistributed unmodified
along with its official security policy. You must perform your own
validation to claim FIPS compliance for any regulated deployment.

CMVP site → https://csrc.nist.gov/projects/cryptographic-module-validation-program

📦 Directory Layout (release ZIP)
File	Purpose
vpn.exe	TrueTunnel binary
wintun.dll	WireGuard’s TUN driver
fips.dll	OpenSSL validated module
fipsmodule.cnf / openssl.cnf	FIPS & global OpenSSL config
run_fipsinstall.bat	One-time FIPS initialisation script

⚠️ Known Limitations
IPv4 only (IPv6 roadmap)

Static addresses (no built-in DHCP/DNS)

No automatic reconnect/heartbeat yet

MTU hard-coded to 1380

Windows-only (Linux/macOS ports planned)

✅ Test Matrix
Scenario	Status
NAT client → public server	✅
Multiple clients (3+)	✅ (latency ≤ 5 ms added)
Large UDP bursts (gaming)	✅
Cellular 4G client	✅
> MTU fragmentation	⚠️ Passes but defers to TCP-MSS

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

🧠 Roadmap
UDP / QUIC transport option

TUN/TAP support on Linux & macOS

Automatic reconnect & keep-alive

Optional LZ4/Zstd compression

GUI profile manager & QR import

📜 License
Dual-licensed under MIT or GPL v2 – choose whichever suits your
project.

🙏 Credits
WireGuard – Wintun

OpenSSL (FIPS provider)

Dear ImGui – GUI
