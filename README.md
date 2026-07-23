# Arin Proxy

Arin Proxy is a DDoS-protected reverse proxy designed to run behind CDNs like Cloudflare. It helps prevent bypass attempts that could overwhelm your application. Built using Hyper, Arin Proxy is fast and feature-rich. It is optimized for high performance and uses various challenges to mitigate HTTP/HTTPS DDoS attacks without taxing the client's backend server.

Arin Proxy's primary goal is to cut costs from HTTP/HTTPS DDoS attacks. Ingress and egress traffic on most services is expensive. Pair this with hosting such as Hetzner or any unmetered dedicated server seller with a 10 GB NIC/Port speed and you can handle up to 400k RPS on 1 server. It isn't compute bound. You will likely run out of bandwidth before this proxy uses up your entire system's resources.

## Key Features

* **Blocks Automated Bots:** Being new, Arin Proxy does not yet have specific signatures for AI scrapers, crawlers and other automated bots. This unintentionally provides protection from vexation.

## What Does Arin Proxy Do?

Arin Proxy operates through three distinct stages:

1. **Standard Cookie Challenge:** A simple challenge that sets a cookie in the header.
2. **JavaScript Challenge:** Ensures the client browser has JavaScript enabled. This blocks a majority of headless browsers.
3. **Proof of Work (PoW) Challenge:** Creates CPU-intensive tasks that deter attackers by requiring them to solve complex computational hashes. This stage demands significant server resources and operates with multiple workers.

## Recommendations

* **Run Behind a CDN:** For optimal protection, deploy Arin Proxy behind Cloudflare or another CDN.

* **Use a Multi-core Server:** Arin Proxy is asynchronoius runtime. The more cores the better the load balancing.

* **High Bandwidth Server:** For the PoW challenge, a server with high port speed of 10+ Gbps is recommended. This helps manage the increased data transmission because each visitor request generates a large response.

* **Only allow traffic from your CDN by whitelisting its IP ranges. You can also use IPv6 or set up a tunnel like Cloudflare Tunnel so no outside service can access your server directly.**

This prevents automatic scanners like Shodan or Censys from leaking your backend IP.

* We have an ALT repo for our JSDeliver: https://github.com/libalpm64/Blake3-JS. It is highly recommended to fork this so that you are in control of the JavaScript in case anything happens. This is unlikely.

## For Technical Users

After getting multiple DDoS attacks, Cloudflare blocked a total of 435 requests out of 80,740 requests. This is 0.00538766410701%. Arin Proxy can run behind Cloudflare and had to handle all of these requests. All were blocked. 0% of these got through.

<img width="1638" height="514" alt="image" src="https://github.com/user-attachments/assets/91368185-9d52-40fc-85d2-1303f6ac1aa8" />

Arin Proxy effectively eliminates HTTP/HTTPS DDoS attacks when paired with Cloudflare. Only dedicated attacks with large proxy lists and large botnets will be able to take down your website. The stage sensor detects when attacks are getting through or when too many requests are allowed. It will then employ a stricter challenge until the PoW. The PoW is difficullt to take down because attackers need to overwhelm the proxy itself. This would require hundreds of times the amount of compute needed per 1 request that you serve.

**Bandwidth Usage:**
Our PoW challenge is only **2 KB**. This is way smaller than most other services. We use **JSDelivr** to serve the static challenge assets so your server doesn’t have to. This helps avoid saturating your port. On a **1 Gbps port** you can handle **~45k RPS** just from the PoW stage.
