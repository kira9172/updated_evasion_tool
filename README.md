## 🤖 Anti-Bot Evasion Tool in Go

[cite_start]This is a custom HTTPS tool built in Go, designed to fly under the radar of tough anti-bot systems like Cloudflare, PerimeterX, and Akamai[cite: 3]. It works by carefully imitating a real web browser, from its TLS handshake down to its HTTP headers.

[cite_start]The key here is that it's all built from the ground up, with **no headless browsers** or automation frameworks like Puppeteer or Playwright involved[cite: 11, 102]. [cite_start]The focus is on being stable, stealthy, and effective[cite: 109].

---

### What It Does ✨

* [cite_start]**Mimics Real Browsers**: It swaps out TLS fingerprints (the ClientHello packet) to look exactly like popular browsers such as Chrome, Firefox, or Safari[cite: 4, 16]. [cite_start]You can even set it to randomize the fingerprint for each request to keep things unpredictable[cite: 17].

* [cite_start]**Smart Proxy Rotation**: It routes all of its traffic through your own list of HTTP or SOCKS5 proxies[cite: 6, 23]. [cite_start]Proxies are rotated automatically on each request or whenever one fails, ensuring the tool keeps running smoothly[cite: 24].

* [cite_start]**A Convincing Disguise**: The tool doesn't just spoof the TLS signature; it sends a full set of matching HTTP headers to make the disguise complete[cite: 44, 46]. A Chrome fingerprint gets Chrome headers.

* **Handles Blocks & Challenges**: It's smart enough to know when it's been blocked or is facing a challenge. [cite_start]It checks HTTP status codes (like 403 Forbidden) and even scans the page content for CAPTCHA keywords[cite: 32, 53, 54]. [cite_start]When it hits a wall, it just tries again with a new proxy and fingerprint[cite: 34].

* [cite_start]**Human-Like Behavior**: It handles cookies and follows redirects just like a real browser session[cite: 9, 50]. [cite_start]Plus, it adds random delays between requests to mimic human Browse patterns, not a predictable bot[cite: 68, 70].

---

### Getting Started 🚀

Getting this up and running is straightforward.

1.  [cite_start]**You'll need**: Go 1.20+ installed on your machine[cite: 72].
2.  **Clone the project**:
    ```sh
    git clone <your-repo-url>
    cd go-https-evasion-tool
    ```
3.  **Install the dependencies**:
    ```sh
    go mod tidy
    ```
4.  **Build the application**:
    ```sh
    go build -o anti-bot-tool .
    ```

---

### How to Configure It ⚙️

Instead of messy command-line flags, you can set everything up in a single `config.yaml` file. Just create one in the same directory and paste this template in.

```yaml
# config.yaml

# Add all the URLs you want to request
targets:
  - "[https://www.viagogo.co.uk/Concert-Tickets/Rock-and-Pop/Sting-Tickets/E-157332132](https://www.viagogo.co.uk/Concert-Tickets/Rock-and-Pop/Sting-Tickets/E-157332132)"
  - "[https://www.stubhub.com/stardew-valley-denver-tickets-9-13-2025/event/156264784](https://www.stubhub.com/stardew-valley-denver-tickets-9-13-2025/event/156264784)"

# Your list of proxies in user:pass@ip:port format
proxies:
  - "user1:pass1@1.2.3.4:8080"
  - "user2:pass2@5.6.7.8:9000"

# General settings for the tool
settings:
  # How many successful requests to perform
  request_count: 50
  # TLS Profile to use: "chrome", "firefox", "safari", or "random"
  tls_profile: "random"
  # Delay between requests (in milliseconds) to seem more human
  delay_ms:
    min: 500
    max: 3000
