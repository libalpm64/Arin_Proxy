# Arin Proxy

Arin Proxy is a DDoS-protected reverse proxy designed to run behind CDNs like Cloudflare. It helps prevent bypass attempts that could overwhelm your application. Built using the Actix Web framework, Arin Proxy is both fast and feature-rich and optimized for high performance with various challenges to mitigate HTTP/HTTPS DDoS attacks without taxing the client's backend server.

In contrast, my other project, LostLab Proxy, utilizes the Atix Web framework with HTTP/2 for slightly faster performance. However, Arin Proxy is designed to be more feature-rich. It integrates seamlessly with existing infrastructures (IaaS), including Cloudflare and other CDNs.

## Key Features

- **Multi-threaded:** Arin Proxy makes use of multi-core systems, allowing it to handle increased traffic effectively and very quickly.
- **Blocks Automated Bots:** Being new, Arin Proxy does not yet have specific signatures for AI scrapers, crawlers, and other automated bots, unintentionally providing protection from such vexations.
- **Easy-to-Read Codebase:** Unlike LostLab's, this codebase is straightforward and avoids complex structures like sizing vectors, making it easier to maintain.
- **Expandable:** Actix Web offers numerous load-balancing technologies, with many resources available for implementing multi-server and origin configurations.

## What Does Arin Proxy Do?

Arin Proxy operates through three distinct stages:

1. **Standard Cookie Challenge:** A simple challenge that sets a cookie in the header.
2. **JavaScript Challenge:** Ensures the client browser has JavaScript enabled, blocking a majority of headless browsers.
3. **Proof of Work (PoW) Challenge:** Creates CPU-intensive tasks that deter attackers by requiring them to solve complex computational hashes. This stage demands significant server resources and operates with multiple workers.

## Recommendations

- **Run Behind a CDN:** For optimal protection, deploy Arin Proxy behind Cloudflare or another CDN.
- **Use a Multi-core Server:** Arin Proxy is asynchronous, allowing for multi-threading. More cores will enhance performance.
- **High Bandwidth Server:** For the PoW challenge, a server with high port-speed (2+ Gbps) is recommended to manage the increased data transmission, as each visitor request generates a large response.

## Licensing Requirements

To maintain integrity, please include the word "Arin" anywhere on your site or in your code if you use or have built on top of it. (It doesn't have to be visible). This is apart of the MIT License.
