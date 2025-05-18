TrueTunnel VPN
A secure, minimalist, FIPS-capable VPN over TCP using TLS and the Wintun driver.
Designed for simple, authenticated IP tunnels between trusted peers — no third-party servers, just you and your traffic.

⚠️ Disclaimer: While this software uses the OpenSSL FIPS 140-3 validated module (fips.dll),
this project and its author have not been certified or validated under FIPS 140-3 by NIST or CMVP.
Use of this module does not imply your usage or distribution is FIPS-compliant or certified.

✨ Features
🔒 Encrypted tunneling over TLS 1.2/1.3 using OpenSSL FIPS provider

🔐 Mutual authentication via HMAC-SHA256 over nonces + password

💬 Interactive messaging channel over the encrypted tunnel

🧠 Raw IP tunnel via Wintun — handles TCP, UDP, ICMP, etc.

🌐 Static IP scheme for consistent point-to-point routing (new in V2)

🧱 Works through NAT (client side — no port forwarding required)

🎨 Custom GUI powered by Dear ImGui with stylized dropdowns and controls (new in V2)

🪪 Single binary, no install, no registry modification

🧵 Dual-threaded packet pump with optional control channel

🖥️ Full Windows compatibility — ideal for power users or lab setups

🚀 Getting Started
🧰 Requirements
Windows 10/11 (admin privileges required)

Wintun driver (wintun.dll must be present)

OpenSSL 3.x with FIPS module (fips.dll, fipsmodule.cnf, openssl.cnf)

🛠️ Building
bash
Copy
Edit
git clone https://github.com/yourname/vpn
cd vpn
cmake -B build
cmake --build build --config Release
⚠️ First-Time Setup
Run the FIPS install script once:

bash
Copy
Edit
run_fipsinstall.bat
This sets up fipsmodule.cnf and configures OpenSSL to use the validated FIPS provider.

🌐 Usage
✅ Server (public IP or port-forwarded)
Run vpn.exe in server mode and share your public IP with the client.
The server will listen for connections on the configured port.

✅ Client (can be behind NAT)
Run vpn.exe in client mode and provide:

Server IP and port

Shared password

🧭 Network Behavior
✅ Fully NAT-compatible client

✅ Static IP point-to-point routing

✅ Supports TCP, UDP, ICMP, DNS, and more

✅ Compatible with tools like ping, curl, ssh, etc.

⚠️ Server must be reachable from the client

🔐 Security Design
Layer	Technology	Details
Transport	TCP	Encrypted with OpenSSL
Encryption	TLS 1.2/1.3	AES-128/256-GCM only (FIPS only)
Authentication	HMAC-SHA256	Derived from shared passphrase
Tunnel Interface	Wintun	High-performance IP adapter
Key Management	Ephemeral	3072-bit RSA self-signed per run
Memory Security	OpenSSL Secure	Nonces & HMAC buffers zeroed

📛 FIPS 140-3 Notice
This project includes the OpenSSL FIPS 140-3 validated module (version 3.1.2, certificate #A3548)
as provided by The OpenSSL Project. It is redistributed unmodified, alongside its official security policy.

⚠️ FIPS Validation Disclaimer:

This software has not itself been validated by NIST or the CMVP.

The author makes no claim of FIPS 140-3 certification for this application.

Deployment in regulated environments requires your own compliance validation.

For official CMVP guidance:
👉 https://csrc.nist.gov/projects/cryptographic-module-validation-program

📦 File Structure
File	Description
vpn.exe	Compiled VPN binary
wintun.dll	Wintun driver DLL
fips.dll	OpenSSL FIPS shared object
fipsmodule.cnf	FIPS module configuration
openssl.cnf	OpenSSL base config (loads FIPS module)
run_fipsinstall.bat	One-time FIPS initialization script

⚠️ Known Limitations
Single client per server instance

IPv4 only

Static IPs only — no DHCP, DNS, or dynamic routing

Manual MTU tuning (1380 is a safe default)

No reconnect or heartbeat logic (yet)

Server must be run as Administrator

🧪 Tested Scenarios
Scenario	Status
NAT client ↔ public server	✅ Works
LAN-only client/server	✅ Works
TLS tunnel with ping, curl, SSH	✅ Works
UDP (e.g., DNS, games)	✅ Works
Large packets (> MTU)	⚠️ Limit
Cellular network (client side)	✅ Works

🛰️ Traffic Flow (Client ↔ Server)
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
📦 Encapsulation View (ASCII)
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

🧠 Future Ideas
UDP or QUIC-based transport mode

Linux/macOS support (via tun)

Multi-client support on server

NAT traversal helpers / punch-through

Optional data compression

📜 License
Dual-licensed under MIT or GPLv2 — your choice.

⚠️ Use responsibly. Not certified for production use or export-controlled environments.

🙏 Credits
Wintun by WireGuard

OpenSSL (with FIPS provider)

Dear ImGui for GUI

termcolor — Terminal styling helper
