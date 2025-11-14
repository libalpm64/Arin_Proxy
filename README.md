# Arin Proxy

Arin Proxy is a DDoS-protected reverse proxy designed to run behind CDNs like Cloudflare. It helps prevent bypass attempts that could overwhelm your application. Built using the Actix Web framework, Arin Proxy is both fast and feature-rich and optimized for high performance, with various challenges to mitigate HTTP/HTTPS DDoS attacks without taxing the client's backend server.

Arin Proxy's primary goal is to cut costs from HTTP/HTTPS DDoS attacks; the cost for ingress/egress traffic on most services is expensive. This, paired with a hosting such as Hetzner (or any unmetered dedicated server seller) with a 10 GB NIC/Port speed, you can handle up to 400k RPS on 1 server. It isn't CPU-bound; you will likely run out of bandwidth before this proxy uses up your entire system's resources. 

In contrast, my other project, LostLab Proxy, utilizes the Actix Web framework with HTTP/2 for slightly faster performance. However, Arin Proxy is designed to be more feature-rich. It integrates seamlessly with existing infrastructures (IaaS), including Cloudflare and other CDNs.

## Key Features

- **Multi-threaded:** Arin Proxy makes use of multi-core systems, allowing it to handle increased traffic effectively and very quickly.
- **Blocks Automated Bots:** Being new, Arin Proxy does not yet have specific signatures for AI scrapers, crawlers, and other automated bots, unintentionally providing protection from such vexations.
- **Expandable:** Actix Web offers numerous load-balancing technologies, with many resources available for implementing multi-server and origin configurations.

## What Does Arin Proxy Do?

Arin Proxy operates through three distinct stages:

1. **Standard Cookie Challenge:** A simple challenge that sets a cookie in the header.
2. **JavaScript Challenge:** Ensures the client browser has JavaScript enabled, blocking a majority of headless browsers.
3. **Proof of Work (PoW) Challenge:** Creates CPU-intensive tasks that deter attackers by requiring them to solve complex computational hashes. This stage demands significant server resources and operates with multiple workers.

## Recommendations

- **Run Behind a CDN:** For optimal protection, deploy Arin Proxy behind Cloudflare or another CDN.
- **Use a Multi-core Server:** Arin Proxy is asynchronous, allowing for multi-threading. More cores will enhance performance.
- **High Bandwidth Server:** For the PoW challenge, a server with high port-speed (10+ Gbps) is recommended to manage the increased data transmission, as each visitor request generates a large response.
- **Check your CPU for instruction sets:** Most server hardware supports AVX2 but AVX2 is the recommendation to check do ```lscpu``` and find the flag AVX.

- **Only allow traffic from your CDN by whitelisting its IP ranges, or use IPv6, or set up a tunnel (like Cloudflare Tunnel) so no outside service can access your server directly:**
This prevent automatic scanners like Shodan or Censys from leaking your backend IP. 

- We have an ALT repo for our JSDeliver, https://github.com/libalpm64/Blake3-JS. It is highly recommended to fork this so that you are in control of the JavaScript (in case anything happens, but unlikely).

## Arin Proxy vs. AWS Cloudfront + AWS Lambda

| Feature / Metric                     | Without Arin Proxy (AWS)                     | With Arin Proxy (Dedicated + Unmetered)     |
|-------------------------------------|----------------------------------------------|---------------------------------------------|
| **Server Model**                    | ❌ Serverless (Lambda, API Gateway, etc.)    | ✅ Bare metal / Dedicated server            |
| **Bandwidth Model**                 | ❌ Metered egress ($0.09/GB+)                | ✅ **Unmetered** (flat monthly fee)         |
| **DDoS Protection**                 | ❌ Pay-per-attack (Shield Advanced: $3k+/month | ✅ **Built-in** (PoW + JS + Cookie challenges) |
| **Egress Cost During Attack**       | ❌ **$0.1k – $50k+** (scales with response size)    | ✅ **$0 extra** (unmetered)                 |
| **Scalability**                     |⚠️ Auto-scales (but at high cost)            | ✅ **Horizontally scalable** (multi-core, 10Gbps+) |
| **Self-Hosted & Transparent**       | ❌ Black-box SaaS                            | ✅ Full control, MIT license                |
| **Attack Mitigation Latency**       |⚠️ Minutes (WAF rules, manual intervention, pain)  | ✅ **Sub-second** |

`` Even if you run your own infra, it's just better to apply on top (except for API endpoints).  ``

## For Technical Users
After getting multiple DDoS attacks, Cloudflare blocked a total of 435 requests out of 80,740 requests (0.00538766410701%). Arin Proxy, which can run behind Cloudflare, had to handle all of these requests, and all were blocked (0% of these got through).

<img width="1638" height="514" alt="image" src="https://github.com/user-attachments/assets/91368185-9d52-40fc-85d2-1303f6ac1aa8" />

Arin Proxy effectively eliminates HTTP/HTTPS DDoS attacks when paired with Cloudflare, and only dedicated attacks with large proxy lists + large botnets will be able to take down your website. The stage sensor allows for detecting when attacks are getting through (too many
requests allowed) In which it will employ a stricter challenge until the PoW (which is effectively impossible to take down unless they overwhelm the proxy itself, they would need 20-30 times the amount of compute needed per 1 request than you).

**Optimizations:**  
I’ve taken optimizations to the absolute extreme—using the best-fit CPU instructions and SIMD wherever possible. This is as fast as it can get, down to the flag level. The *only* overhead comes from Tokio, Actix, and Rust’s std library. I’ve avoided most hot paths introduced by these runtimes, and the critical logic runs on the stack with strong cache coherence. Here’s the control flow graph / branch layout that LLVM generated (it primarily uses SSE instructions—LLVM loves SSE because they’re great for floats).

<img width="1023" height="622" alt="image" src="https://github.com/user-attachments/assets/5eb885b9-1904-4797-851b-f1c6253e30df" />

**Atomic Data Storage:**  
All program counters are **lock-free**. A lot of Rust programs use `Mutex`, which is fine in some cases, but for performance, **atomic storage is faster and causes fewer issues**.

**DashMaps:**  
We heavily use **localized cache pointers** and concurrent hash maps (`DashMap`). This avoids unnecessary memory reads and keeps memory usage very low.

**Bandwidth Usage:**  
Our PoW challenge is only **2 KB**, which is way smaller than most other services. We use **JSDelivr** to serve the static challenge assets, so your server doesn’t have to—this helps avoid saturating your port. On a **1 Gbps port**, you can handle **~45k RPS** just from the PoW stage.

The other challenge stages (cookie + JS) are only a few bytes and require almost no effort—they’re completely invisible to the client. Users won’t even notice these checks are running.
