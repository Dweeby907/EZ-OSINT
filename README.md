# EZ-OSINT — Open-Source Intelligence Multitool

Pick what you want to look up — a **username, domain, IP, email, phone number,
image, or website** — type it in, and EZ-OSINT gathers what's **publicly
available** about it from public sources, all in one window.

## ⚖️ Use it responsibly

EZ-OSINT only queries **public** information (public DNS/WHOIS, public profile
pages, free no-key APIs, and metadata inside files you give it). It's built for:

- **Security research** and **CTFs**
- **Auditing your *own* online footprint** (what can people find about you?)
- **Authorised** penetration-testing reconnaissance

It is **not** for stalking, harassing, or building dossiers on private
individuals. Respect privacy and the laws where you live. The tool deliberately
sticks to public-source lookups and includes no scraping of private data.

## How to use it

1. Go to the `dist` folder and run **`EZ-OSINT.exe`**.
2. Choose a lookup type from the **Look up:** dropdown.
3. Type your target in the box (the hint under it shows the expected format) and
   click **🔎 Search**. Blue underlined text in the results is **clickable**.

## 🚀 Auto-Recon — the one-click feature

Pick **Auto-Recon (everything)**, type *anything* — a domain, IP, email, or
username — and EZ-OSINT figures out what it is and runs **every relevant module
automatically**, streaming the results into one report as they arrive:

- **Domain** → DNS, WHOIS, subdomains, website fingerprint, IP intel, open
  ports & vulns, reverse IP, archived URLs, and search dorks.
- **IP** → IP intel, open ports & known CVEs, reverse IP.
- **Email** → email recon, GitHub, username footprint, the domain's DNS, dorks.
- **Username** → GitHub profile, username footprint across ~30 sites, dorks.

Then hit **💾 Export** to save the whole thing as an HTML or text report.

If you've added free API keys (see below), Auto-Recon **automatically includes**
those richer sources too.

## 🔑 Optional API keys (all free, forever)

Click **🔑 API Keys** (top-right) to paste keys for these services. Each has a
**permanent free tier** (no trial, no expiry) and unlocks an extra lookup. Keys
are saved locally on your PC only (`~/.ez_osint_keys.json`) and never sent
anywhere except that service.

| Service | Unlocks | Free tier |
|---------|---------|-----------|
| **VirusTotal** | Domain/IP/URL/file-hash reputation & how many vendors flag it | 4 req/min, 500/day, forever |
| **AbuseIPDB** | IP abuse score & report history | 1,000 checks/day, forever |
| **Shodan** | Full host details, service banners, vulnerabilities | free key, forever |
| **IPinfo** | Richer geo/ASN + VPN/proxy/Tor/hosting flags | 50k/month, forever |
| **GreyNoise** | "Is this IP a known internet scanner / benign?" | community key, forever |
| **Hunter.io** | Professional email addresses for a *business domain* | ~25/month, forever |

Each row in the dialog has a **"get free key ↗"** link straight to where you
sign up. You don't need any of them — every other module works without a key.

## What each lookup does

| Lookup | What you get |
|--------|--------------|
| **🚀 Auto-Recon** | Auto-detects the target type and chains *all* the relevant lookups below into one streamed report (up to 15 steps for a domain). |
| **Username footprint** | Checks a username across **~100 public sites** (GitHub, GitLab, Reddit, Steam, Telegram, Medium, Keybase, Twitch, DeviantArt, Lichess, Patreon, NPM, PyPI, Docker Hub, Kaggle and many more). *Heuristic* — some sites soft-block or soft-404. |
| **Subdomains (cert transparency)** | Finds subdomains from certificate-transparency logs (crt.sh, with a certspotter fallback). |
| **SSL/TLS certificate** | Issuer, validity dates, TLS version, and the cert's **SAN names** — which often reveal even more subdomains. |
| **Web deep-dive** | Grades the site's **security headers** (A+→F) and checks for **commonly-exposed files** (`/.git`, `/.env`, `/admin`, `security.txt`, `sitemap.xml`, etc.). |
| **ASN / BGP info** | Via RIPEstat: the owning ASN, org, and **every IP range** that network announces. Accepts an IP, host, or `AS####`. |
| **urlscan.io history** | Public scans others have run on a domain — with timestamps, IPs, and report links. |
| **Open ports & vulns (Shodan)** | Open ports, detected software, and known CVEs for an IP — via Shodan's free InternetDB (no key). |
| **Reverse IP (shared host)** | Other domains hosted on the same IP address. |
| **GitHub user** | Public profile: real name, company, location, public email, repos, followers, join date. |
| **Archived URLs (Wayback)** | URLs the Internet Archive has captured for a domain. |
| **Domain / DNS records** | A, AAAA, MX, NS, TXT, CNAME, SOA records for a domain. |
| **Domain WHOIS** | Registrar, creation/expiry dates, name servers, contact org/country (when public). |
| **IP / host intelligence** | Resolves a host, reverse DNS, and free geolocation: country/city, ISP, org, ASN, timezone, and proxy/VPN/hosting flags. Links the coordinates to Maps. |
| **Email recon** | Validates the format, checks the domain's mail servers (MX), looks for a public **Gravatar**, and links a Have-I-Been-Pwned breach check. |
| **Phone number** | Country, region, carrier, timezone, and line type (metadata only — never the owner). Include the country code, e.g. `+1 202 456 1111`. |
| **Image metadata (EXIF)** | Camera, timestamps, and — if present — **GPS coordinates** (with a Maps link). Click **Browse** to pick a file. Great for checking what your own photos leak. |
| **Website fingerprint** | HTTP status, final URL, server, detected tech (WordPress, Cloudflare, React…), key security headers, and `robots.txt`. |
| **Search-dork generator** | Builds ready-made Google/Bing "dork" queries (exposed files, login pages, directory listings, mentions…) and links them so you can run them in one click. |

## Notes & limits

- Most lookups need an **internet connection**. Image EXIF works offline.
- Username results are **best-effort** — a "found" can be a false positive on
  sites that always return a page, and a "not found" can be a false negative on
  sites that block bots. Always click through to confirm.
- Free APIs (geolocation, etc.) have rate limits; if a lookup is blank, wait a
  bit and retry.
- No API keys are required, so deeper sources that *need* a key (full breach
  data, paid people-search, etc.) are intentionally not included.

## For developers

- `osint_engine.py` — all the lookups as plain functions returning structured
  data. Importable and testable on its own; has a small `__main__` self-test.
- `osint_gui.py` — the Tkinter GUI.

### Rebuild the .exe
```
pip install requests dnspython python-whois phonenumbers Pillow pyinstaller
pyinstaller --noconfirm --onefile --windowed --name "EZ-OSINT" \
  --collect-all phonenumbers --hidden-import dns.resolver \
  --collect-submodules whois osint_gui.py
```
Result: `dist\EZ-OSINT.exe` (a single self-contained file; no Python needed).
