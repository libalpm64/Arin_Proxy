# Arin Proxy

Arin Proxy is a high-performance, DDoS-protected reverse proxy designed to sit behind CDNs like Cloudflare, Sucuri, and others. It prevents DDoS attacks that exhaust your server's resources.

**Rebuilt from the ground up using [May](https://github.com/Xudong-Huang/may),** Arin Proxy uses stackful coroutines to deliver the absolute fastest speed possible out of Rust.

By pairing Arin Proxy with an unmetered dedicated server (e.g., Hetzner 10Gbps), you can mitigate massive HTTP/HTTPS floods (400k+ RPS). The bottleneck becomes your network bandwidth, not your CPU.

All of this is supported by **SIMD acceleration**; most of the stack uses SIMD instructions tailored for server hardware. All libraries used are SIMD supported, such as `blake3` for hashing and `simd-json` for parsing.

## How It Works

Arin Proxy filters traffic through three progressive stages. Legitimate users pass through unnoticed, while attackers are blocked.

1.  **Stage 1: Cookie Challenge**
    A value is set as a cookie. If the client can accept cookies, it passes.
2.  **Stage 2: JavaScript Challenge**
    A tiny HTML payload ensures the client can execute JavaScript (Revamp soon).
3.  **Stage 3: Proof of Work (PoW)**
    If a client bypasses the emulation checks, the proxy serves a cryptographic challenge. The client must spend significant CPU time solving a generic hash. This makes the attack economically unviable: the attacker burns their resources while your server is chilling.

## Recommendations

*   **Run Behind a CDN:** For maximum efficacy, place Arin Proxy behind Cloudflare.
*   **Hardware:** A multi-core dedicated server with **AVX2 support** is recommended.
*   **Network:** A 10Gbps+ unmetered line is ideal. The PoW stage uses bandwidth to exhaust the attacker's CPU.
*   **Security:** Whitelist your CDN's IP ranges (e.g., Cloudflare IPs) in your firewall (`iptables`/`ufw`) to prevent attackers from bypassing the proxy.

## License
GNU Affero General Public License v3.0
