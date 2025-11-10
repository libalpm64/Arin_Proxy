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
- **Don't know where to find a server:** Hetzner is probally your best bet (not sponsored, I wish, EU locations) for US 
## Licensing Requirements

## For Technical Users

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

We have an MIT License; we are not liable or provide any warranty for this software. Please do your own due diligence if you are going to use this in production.
