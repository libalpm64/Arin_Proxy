# Arin Proxy

Arin Proxy is a DDoS-protected reverse proxy designed to run behind CDNs like Cloudflare. It helps prevent bypass attempts that could overwhelm your application. Arin Proxy is built using Hyper. It is fast and feature-rich. It is optimized for high performance and uses various challenges to mitigate HTTP/HTTPS DDoS attacks without taxing the client's backend server.

Arin Proxy's primary goal is to cut costs from HTTP/HTTPS DDoS attacks. Ingress and egress traffic on most services is expensive. Pair this with hosting such as Hetzner or any unmetered dedicated server seller with a 10 GB NIC/Port speed and you can handle up to 400k RPS on 1 server. It isn't compute bound. You will likely run out of bandwidth before this proxy uses up your entire system's resources.

## Key Features

* **Blocks Automated Bots:** Arin Proxy uses layered browser and automation checks to detect AI scrapers and crawlers plus headless browsers and other automated bots. This provides protection from vexation and commodity automation before it reaches your backend.

## What Does Arin Proxy Do?

Arin Proxy operates through four distinct stages:

1. **Standard Cookie Challenge:** A simple challenge that sets a cookie in the header.
2. **JavaScript Challenge:** Ensures the client browser has JavaScript enabled. This blocks a majority of headless browsers.
3. **Proof of Work (PoW) Challenge:** Uses BLAKE3 with an 18-bit target. Clients scan nonces from 0 through `2_600_000` to find a valid hash. This requires attackers to compute a large hash range before receiving stage-three clearance.
4. **Private-Verifier VDF Challenge:** Uses `2^22` which is `4_194_304` sequential RSA repeated squarings for a single-use request-bound challenge. One solve cannot be parallelized. The server verifies it cheaply with its private verifier before granting the exact request.

## Recommendations

* **Run Behind a CDN:** For optimal protection deploy Arin Proxy behind Cloudflare or another CDN.

* **Use a Multi-core Server:** Arin Proxy is asynchronoius runtime. The more cores the better the load balancing.

* **High Bandwidth Server:** For the PoW challenge use a server with high port speed of 10+ Gbps. This helps manage the increased data transmission because each visitor request generates a large response.

* **Only allow traffic from your CDN by whitelisting its IP ranges. You can also use IPv6 or set up a tunnel like Cloudflare Tunnel so no outside service can access your server directly.**

This prevents automatic scanners like Shodan or Censys from leaking your backend IP.

* We have an ALT repo for our JSDeliver: https://github.com/libalpm64/Blake3-JS. It is highly recommended to fork this so that you are in control of the JavaScript in case anything happens. This is unlikely.

## For Technical Users

Arin Proxy reduces HTTP/HTTPS DDoS costs when paired with Cloudflare. The stage sensor detects when too many requests get through. It then employs a stricter challenge. The final VDF stage makes successful requests sequential and single-use. Each grant is bound to one exact request. Dedicated attacks need significant compute plus large proxy lists and botnets.

**Bandwidth Usage:**
Our challenge HTML is capped at **2 KB**. This is way smaller than most other services. We use **JSDelivr** to serve the static challenge assets so your server doesn’t have to. This helps avoid saturating your port. On a **1 Gbps port** you can handle **~45k RPS** just from the PoW stage.
