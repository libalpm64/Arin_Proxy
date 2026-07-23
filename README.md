# Arin Proxy

Arin Proxy is a DDoS-protected reverse proxy designed to run behind CDNs like Cloudflare. It helps prevent bypass attempts that could overwhelm your application. Built using Hyper, Arin Proxy is both fast and feature-rich and optimized for high performance, with various challenges to mitigate HTTP/HTTPS DDoS attacks without taxing the client's backend server.

Arin Proxy's primary goal is to cut costs from HTTP/HTTPS DDoS attacks; the cost for ingress/egress traffic on most services is expensive. This, paired with a hosting such as Hetzner (or any unmetered dedicated server seller) with a 10 GB NIC/Port speed, you can handle up to 400k RPS on 1 server. It isn't compute bound; you will likely run out of bandwidth before this proxy uses up your entire system's resources. 

## Key Features

- **Blocks Automated Bots:** Being new, Arin Proxy does not yet have specific signatures for AI scrapers, crawlers, and other automated bots, unintentionally providing protection from vexation.

## What Does Arin Proxy Do?

Arin Proxy operates through three distinct stages:

1. **Standard Cookie Challenge:** A simple challenge that sets a cookie in the header.
2. **JavaScript Challenge:** Ensures the client browser has JavaScript enabled, blocking a majority of headless browsers.
3. **Sequential VDF Challenge:** Forces clients to complete sequential work that cannot be accelerated with more CPU cores, GPUs, or parallel workers.

## VDF Tradeoffs

The VDF approach is slower than BLAKE3, but its sequential-only work makes it the better hardened option for threats such as web scraping. For large-scale DDoS protection where maximum server throughput matters, the BLAKE3 approach on the main branch is the better option.

## Recommendations

- **Run Behind a CDN:** For optimal protection, deploy Arin Proxy behind Cloudflare or another CDN.
- **Use a Multi-core Server:** Arin Proxy is asynchronoius runtime. The more cores, the better load the balancing.
- **High Bandwidth Server:** For the PoW challenge, a server with high port-speed (10+ Gbps) is recommended to manage the increased data transmission, as each visitor request generates a large response.

- **Only allow traffic from your CDN by whitelisting its IP ranges, or use IPv6, or set up a tunnel (like Cloudflare Tunnel) so no outside service can access your server directly:**
This prevent automatic scanners like Shodan or Censys from leaking your backend IP. 

- We have an ALT repo for our JSDeliver, https://github.com/libalpm64/Blake3-JS. It is highly recommended to fork this so that you are in control of the JavaScript (in case anything happens, but unlikely).

## For Technical Users
After getting multiple DDoS attacks, Cloudflare blocked a total of 435 requests out of 80,740 requests (0.00538766410701%). Arin Proxy, which can run behind Cloudflare, had to handle all of these requests, and all were blocked (0% of these got through).

<img width="1638" height="514" alt="image" src="https://github.com/user-attachments/assets/91368185-9d52-40fc-85d2-1303f6ac1aa8" />

Arin Proxy effectively eliminates HTTP/HTTPS DDoS attacks when paired with Cloudflare, and only dedicated attacks with large proxy lists + large botnets will be able to take down your website. The stage sensor allows for detecting when attacks are getting through (too many
requests allowed) In which it will employ a stricter challenge until the PoW (which is difficullt to take down because they need to overwhelm the proxy itself which would require hundreds of times the amount of compute needed per 1 request that you serve).

**Bandwidth Usage:**  
Our PoW challenge is only **2 KB**, which is way smaller than most other services. We use **JSDelivr** to serve the static challenge assets, so your server doesn’t have to—this helps avoid saturating your port. On a **1 Gbps port**, you can handle **~45k RPS** just from the PoW stage.

The other challenge stages (cookie + JS) are only a few bytes and require almost no effort—they’re completely invisible to the client. Users won’t even notice these checks are running.
