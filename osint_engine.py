"""
EZ-OSINT : open-source-intelligence engine
===========================================
Each function looks up PUBLIC information from public sources (DNS, WHOIS,
public profile pages, free no-key APIs, file metadata) and returns structured
results for the GUI to display.

Intended for: security research, CTFs, auditing your OWN online footprint, and
authorised testing. Respect privacy and the law — don't use it to harass,
stalk, or profile private individuals.
"""

import hashlib
import json
import os
import re
import socket
import concurrent.futures
from urllib.parse import urlsplit, quote

import requests

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
HEADERS = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}
TIMEOUT = 8

# One pooled session for the whole app — keep-alive + a big connection pool make
# the 100-site username sweep and Auto-Recon dramatically faster, with light
# retries for transient network blips.
SESSION = requests.Session()
SESSION.headers.update(HEADERS)
try:
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    _adapter = HTTPAdapter(
        pool_connections=32, pool_maxsize=64,
        max_retries=Retry(total=1, backoff_factor=0.3,
                          status_forcelist=(502, 503, 504),
                          allowed_methods=frozenset(["GET", "HEAD"])))
    SESSION.mount("https://", _adapter)
    SESSION.mount("http://", _adapter)
except Exception:
    pass


# ===========================================================================
#  API keys  (all of these services have a PERMANENT free tier)
# ===========================================================================
# service id -> (display name, where to get a free key, what it adds)
KEY_SERVICES = {
    "virustotal": ("VirusTotal", "https://www.virustotal.com/gui/my-apikey",
                   "domain / IP / URL / file-hash reputation & detections"),
    "abuseipdb": ("AbuseIPDB", "https://www.abuseipdb.com/account/api",
                  "IP abuse score and report history"),
    "shodan": ("Shodan", "https://account.shodan.io/",
               "full host details, banners and vulnerabilities"),
    "ipinfo": ("IPinfo", "https://ipinfo.io/account/token",
               "richer IP geolocation, ASN and org data"),
    "greynoise": ("GreyNoise", "https://viz.greynoise.io/account/",
                  "is an IP a known internet scanner / benign?"),
    "hunter": ("Hunter.io", "https://hunter.io/api-keys",
               "professional email addresses for a domain"),
}
KEYS_PATH = os.path.join(os.path.expanduser("~"), ".ez_osint_keys.json")


def load_keys():
    try:
        with open(KEYS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_keys(d):
    with open(KEYS_PATH, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)


KEYS = load_keys()


def get_key(service):
    return (KEYS.get(service) or "").strip()


def set_keys(d):
    """Update the in-memory + on-disk key store."""
    KEYS.clear()
    KEYS.update({k: v for k, v in d.items() if v})
    save_keys(KEYS)


# ===========================================================================
#  Username footprint  (mini-Sherlock)
# ===========================================================================
# name -> (url_template, method)   — `method` is the BASELINE detector:
#   "status"            : HTTP 200 => exists, 404 => not
#   ("absent", "text")  : if `text` is NOT in the page => exists
#   ("present", "text") : if `text` IS in the page     => exists (taken)
# Every site additionally passes through the accuracy filters in
# `_check_username_site` (redirect-away, anti-bot wall, soft-404 markers) and
# any per-site override in SITE_RULES below, which together kill the soft-404
# false positives that a naive "HTTP 200 == found" check produces.
USERNAME_SITES = {
    # --- code / dev ---
    "GitHub":        ("https://github.com/{}", "status"),
    "GitLab":        ("https://gitlab.com/{}", "status"),
    "Bitbucket":     ("https://bitbucket.org/{}/", "status"),
    "SourceForge":   ("https://sourceforge.net/u/{}/profile/", "status"),
    "Replit":        ("https://replit.com/@{}", "status"),
    "CodePen":       ("https://codepen.io/{}", "status"),
    "Dev.to":        ("https://dev.to/{}", "status"),
    "Hashnode":      ("https://hashnode.com/@{}", "status"),
    "Hackaday":      ("https://hackaday.io/{}", "status"),
    "Docker Hub":    ("https://hub.docker.com/u/{}", "status"),
    "NPM":           ("https://www.npmjs.com/~{}", "status"),
    "PyPI":          ("https://pypi.org/user/{}/", "status"),
    "RubyGems":      ("https://rubygems.org/profiles/{}", "status"),
    "Packagist":     ("https://packagist.org/users/{}/", "status"),
    "Atcoder":       ("https://atcoder.jp/users/{}", "status"),
    "Codewars":      ("https://www.codewars.com/users/{}", "status"),
    "Codecademy":    ("https://www.codecademy.com/profiles/{}", "status"),
    "Leetcode":      ("https://leetcode.com/{}/", "status"),
    "HackerRank":    ("https://www.hackerrank.com/{}", "status"),
    "HackerNews":    ("https://news.ycombinator.com/user?id={}", ("absent",
                      "No such user.")),
    "Keybase":       ("https://keybase.io/{}", "status"),
    "Wakatime":      ("https://wakatime.com/@{}", "status"),
    "Postman":       ("https://www.postman.com/{}", "status"),
    "Kaggle":        ("https://www.kaggle.com/{}", "status"),
    "HuggingFace":   ("https://huggingface.co/{}", "status"),
    # --- social / blogging ---
    "Reddit":        ("https://www.reddit.com/user/{}/about.json", "status"),
    "Telegram":      ("https://t.me/{}", ("absent", "tgme_page_additional")),
    "Medium":        ("https://medium.com/@{}", "status"),
    "Substack":      ("https://{}.substack.com", "status"),
    "Wordpress":     ("https://{}.wordpress.com", "status"),
    "Blogger":       ("https://{}.blogspot.com", "status"),
    "Tumblr":        ("https://{}.tumblr.com", "status"),
    "About.me":      ("https://about.me/{}", "status"),
    "Linktree":      ("https://linktr.ee/{}", "status"),
    "AllMyLinks":    ("https://allmylinks.com/{}", "status"),
    "Gravatar":      ("https://en.gravatar.com/{}", "status"),
    "Disqus":        ("https://disqus.com/by/{}/", "status"),
    "Ello":          ("https://ello.co/{}", "status"),
    "Minds":         ("https://www.minds.com/{}", "status"),
    "VK":            ("https://vk.com/{}", "status"),
    "Trello":        ("https://trello.com/{}", "status"),
    "ProductHunt":   ("https://www.producthunt.com/@{}", "status"),
    "Wattpad":       ("https://www.wattpad.com/user/{}", "status"),
    "Quora":         ("https://www.quora.com/profile/{}", "status"),
    "Telegra.ph":    ("https://telegra.ph/{}", "status"),
    # --- media / streaming ---
    "Twitch":        ("https://m.twitch.tv/{}", "status"),
    "YouTube":       ("https://www.youtube.com/@{}", "status"),
    "Dailymotion":   ("https://www.dailymotion.com/{}", "status"),
    "Vimeo":         ("https://vimeo.com/{}", "status"),
    "SoundCloud":    ("https://soundcloud.com/{}", "status"),
    "Bandcamp":      ("https://{}.bandcamp.com", "status"),
    "Mixcloud":      ("https://www.mixcloud.com/{}/", "status"),
    "Spotify":       ("https://open.spotify.com/user/{}", "status"),
    "Last.fm":       ("https://www.last.fm/user/{}", "status"),
    "Genius":        ("https://genius.com/{}", "status"),
    "Audiomack":     ("https://audiomack.com/{}", "status"),
    "Smule":         ("https://www.smule.com/{}", "status"),
    # --- art / photo / design ---
    "Behance":       ("https://www.behance.net/{}", "status"),
    "Dribbble":      ("https://dribbble.com/{}", "status"),
    "DeviantArt":    ("https://www.deviantart.com/{}", "status"),
    "ArtStation":    ("https://www.artstation.com/{}", "status"),
    "Flickr":        ("https://www.flickr.com/people/{}", "status"),
    "500px":         ("https://500px.com/p/{}", "status"),
    "Unsplash":      ("https://unsplash.com/@{}", "status"),
    "Pinterest":     ("https://www.pinterest.com/{}/", "status"),
    "VSCO":          ("https://vsco.co/{}/gallery", "status"),
    "Imgur":         ("https://imgur.com/user/{}", "status"),
    "Giphy":         ("https://giphy.com/{}", "status"),
    # --- gaming ---
    "Steam":         ("https://steamcommunity.com/id/{}", ("absent",
                      "The specified profile could not be found")),
    "Chess.com":     ("https://www.chess.com/member/{}", "status"),
    "Lichess":       ("https://lichess.org/@/{}", "status"),
    "Itch.io":       ("https://{}.itch.io", "status"),
    "GameJolt":      ("https://gamejolt.com/@{}", "status"),
    "Kongregate":    ("https://www.kongregate.com/accounts/{}", "status"),
    "Speedrun":      ("https://www.speedrun.com/users/{}", "status"),
    "Xbox Gamertag": ("https://xboxgamertag.com/search/{}", "status"),
    "osu!":          ("https://osu.ppy.sh/users/{}", "status"),
    "Fortnite Trk":  ("https://fortnitetracker.com/profile/all/{}", "status"),
    # --- creators / commerce ---
    "Patreon":       ("https://www.patreon.com/{}", "status"),
    "Ko-fi":         ("https://ko-fi.com/{}", "status"),
    "BuyMeACoffee":  ("https://www.buymeacoffee.com/{}", "status"),
    "Gumroad":       ("https://{}.gumroad.com", "status"),
    "Fiverr":        ("https://www.fiverr.com/{}", "status"),
    "Etsy":          ("https://www.etsy.com/shop/{}", "status"),
    "Slideshare":    ("https://www.slideshare.net/{}", "status"),
    "Scribd":        ("https://www.scribd.com/{}", "status"),
    # --- books / film / hobbies ---
    "Goodreads":     ("https://www.goodreads.com/{}", "status"),
    "Letterboxd":    ("https://letterboxd.com/{}/", "status"),
    "Trakt":         ("https://trakt.tv/users/{}", "status"),
    "MyAnimeList":   ("https://myanimelist.net/profile/{}", "status"),
    "AniList":       ("https://anilist.co/user/{}/", "status"),
    "Untappd":       ("https://untappd.com/user/{}", "status"),
    "Pinkbike":      ("https://www.pinkbike.com/u/{}/", "status"),
    "Strava":        ("https://www.strava.com/athletes/{}", "status"),
    # --- academic / professional ---
    "Academia.edu":  ("https://independent.academia.edu/{}", "status"),
    "ORCID":         ("https://orcid.org/{}", "status"),
    "Wellfound":     ("https://wellfound.com/u/{}", "status"),
    "Crunchbase":    ("https://www.crunchbase.com/person/{}", "status"),
    # --- paste / misc ---
    "Pastebin":      ("https://pastebin.com/u/{}", "status"),
    "Archive.org":   ("https://archive.org/details/@{}", "status"),
    "Cash App":      ("https://cash.app/${}", "status"),
    "Venmo":         ("https://account.venmo.com/u/{}", "status"),
    "Carrd":         ("https://{}.carrd.co", "status"),
}


# ---------------------------------------------------------------------------
# Per-site accuracy overrides.  Most sites are fine with the generic filters,
# but some always return HTTP 200 (single-page apps, marketing landing pages,
# bot walls), so a bare status check reports EVERY username as "found".  For
# those we use a key-free API/JSON probe or a confirmed page marker; where no
# reliable signal exists, we report "uncertain" instead of a false "found".
#
# Rule keys:
#   "probe"          alternate URL to GET (e.g. a JSON API); existence is then
#                    decided by "exists":
#                       ("status",)            -> HTTP 200 on the probe
#                       ("not_text", s)        -> exists unless body == s (e.g. "null")
#                       ("absent_text", s)     -> exists unless s appears in body
#   "gql"            (endpoint, headers, query, var, json_path) GraphQL POST;
#                    exists if the node at json_path is non-null
#   "not_found_text" list of strings that appear ONLY on "no such user" pages
#   "found_text"     list of strings that appear ONLY on real profile pages
#   "verify": False  cannot be confirmed from public, key-free sources -> the
#                    result is reported as "uncertain" (link given to check by hand)
SITE_RULES = {
    # -- clean key-free existence APIs --
    "HackerNews":  {"probe": "https://hacker-news.firebaseio.com/v0/user/{}.json",
                    "exists": ("not_text", "null")},
    "Trello":      {"probe": "https://trello.com/1/members/{}",
                    "exists": ("status",)},
    "Dailymotion": {"probe": "https://api.dailymotion.com/user/{}?fields=username",
                    "exists": ("status",)},
    "GameJolt":    {"probe": "https://gamejolt.com/site-api/web/profile/@{}",
                    "exists": ("absent_text", '"user":null')},
    "Lichess":     {"probe": "https://lichess.org/api/user/{}",
                    "exists": ("status",)},
    "Speedrun":    {"probe": "https://www.speedrun.com/api/v1/users/{}",
                    "exists": ("status",)},
    # account pages sit behind the homepage shell; the metadata API is exact
    # ({} == no such account)
    "Archive.org": {"probe": "https://archive.org/metadata/@{}",
                    "exists": ("not_text", "{}")},
    "Minds":       {"probe": "https://www.minds.com/api/v1/channel/{}",
                    "exists": ("absent_text", '"status":"error"')},
    # -- first-party GraphQL endpoints (no key) --
    "Twitch":      {"gql": ("https://gql.twitch.tv/gql",
                            {"Client-ID": "kimne78kx3ncx6brgo4mv6wki5h1ko"},
                            "query($l:String!){user(login:$l){id}}",
                            "l", ("data", "user"))},
    "AniList":     {"gql": ("https://graphql.anilist.co", {},
                            "query($n:String!){User(name:$n){id}}",
                            "n", ("data", "User"))},
    # -- confirmed soft-404 page markers --
    "Medium":      {"not_found_text": ["page not found"]},
    "Mixcloud":    {"not_found_text": ["page not found"]},
    "Pinterest":   {"not_found_text": ["user not found"]},
    "Audiomack":   {"not_found_text": ["music platform empowering"]},
    "Telegram":    {"found_text": ["tgme_page_title"]},
    # -- single-page apps with no key-free way to confirm a user exists --
    "500px":       {"verify": False},
    "Imgur":       {"verify": False},
    "Spotify":     {"verify": False},
    "Postman":     {"verify": False},
    "HackerRank":  {"verify": False},
    "ArtStation":  {"verify": False},
}

# Anti-bot / interstitial pages that answer HTTP 200 but tell us nothing about
# whether the username exists — treated as "uncertain", never "found".
_BLOCK_MARKERS = (
    "client challenge", "checking your browser", "just a moment",
    "attention required", "enable javascript and cookies", "verify you are human",
    "verify you are a human", "are you a robot", "px-captcha", "captcha-delivery",
    "access denied", "request unsuccessful", "ddos protection",
    "cf-browser-verification", "please enable cookies",
    # overload / throttling pages that 200 but tell us nothing
    "temporarily unavailable", "rate limited", "service unavailable",
    "too many requests",
)
# Phrases in a page <title> that mean "no such user" almost everywhere.
_TITLE_NOTFOUND = (
    "not found", "page isn't available", "page isn’t available",
    "account suspended", "doesn't exist", "doesn’t exist",
    "page does not exist", "page unavailable",
)


def _is_subdomain_tmpl(template):
    """True if the username goes in the host (e.g. https://{}.tumblr.com)."""
    after = template.split("://", 1)[-1]
    return "{}" in after.split("/", 1)[0]


def _fmt(template, username):
    """Fill the template, URL-encoding usernames placed in the path."""
    if _is_subdomain_tmpl(template):
        return template.format(username)
    return template.format(quote(username, safe=""))


def _title(html):
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return (m.group(1).strip().lower() if m else "")


def _username_in_url(url, username):
    """Is the username still in the final URL's host+path (ignoring the query)?
    Catches sites that redirect a missing user to a home/login/landing page."""
    s = urlsplit(url)
    hp = (s.netloc + s.path).lower()
    u = username.lower()
    return u in hp or quote(username, safe="").lower() in hp


def _looks_blocked(resp):
    head = (_title(resp.text) + " " + resp.text[:2500]).lower()
    return any(m in head for m in _BLOCK_MARKERS)


def _r(name, url, status, note):
    return {"site": name, "url": url, "status": status, "note": note}


def _check_gql(name, display_url, username, gql):
    endpoint, headers, query, var, path = gql
    try:
        resp = SESSION.post(endpoint, headers={**HEADERS, **headers},
                            json={"query": query, "variables": {var: username}},
                            timeout=TIMEOUT)
        if resp.status_code != 200:
            return _r(name, display_url, "uncertain", f"API HTTP {resp.status_code}")
        node = resp.json()
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
        return _r(name, display_url, "found" if node is not None else "not found",
                  "API")
    except Exception as e:
        return _r(name, display_url, "uncertain", f"API error: {str(e)[:40]}")


def _check_username_site(name, template, method, username):
    rule = SITE_RULES.get(name, {})
    display_url = _fmt(template, username)

    # GraphQL POST probes (first-party, exact yes/no)
    if "gql" in rule:
        return _check_gql(name, display_url, username, rule["gql"])

    fetch_url = (rule["probe"].format(quote(username, safe=""))
                 if "probe" in rule else display_url)
    try:
        r = SESSION.get(fetch_url, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException as e:
        return _r(name, display_url, "error", str(e)[:60])

    code = r.status_code
    note = f"HTTP {code}"

    # 1) explicit API/JSON probe verdict
    if "exists" in rule:
        kind = rule["exists"][0]
        if kind == "status":
            ok = code == 200
        elif kind == "not_text":
            ok = code == 200 and r.text.strip().lower() != rule["exists"][1].lower()
        elif kind == "absent_text":
            ok = code == 200 and rule["exists"][1].lower() not in r.text.lower()
        else:
            ok = code == 200
        return _r(name, display_url, "found" if ok else "not found", note)

    # 2) definitive "not found" status codes
    if code in (404, 410):
        return _r(name, display_url, "not found", note)

    # 3) anti-bot wall / rate limit / server error -> can't tell
    if code in (401, 403, 429) or code >= 500 or _looks_blocked(r):
        return _r(name, display_url, "uncertain", f"blocked / anti-bot ({code})")

    # 4) redirected away from the username (home / login / landing page)
    if not _username_in_url(r.url, username):
        return _r(name, display_url, "not found", f"redirected ({code})")

    body, low, title = r.text, r.text.lower(), _title(r.text)

    # 5) soft-404 markers (generic title + per-site confirmed strings)
    if code == 200 and any(m in title for m in _TITLE_NOTFOUND):
        return _r(name, display_url, "not found", "soft-404 (title)")
    if "not_found_text" in rule and any(t.lower() in low
                                        for t in rule["not_found_text"]):
        return _r(name, display_url, "not found", "soft-404")
    if "found_text" in rule:
        ok = any(t.lower() in low for t in rule["found_text"])
        return _r(name, display_url, "found" if ok else "not found",
                  note if ok else "no profile markers")

    # 6) baseline absent/present text rules from the table
    if isinstance(method, tuple):
        kind, text = method
        present = text in body
        ok = present if kind == "present" else (not present)
        return _r(name, display_url, "found" if ok else "not found", note)

    # 7) site that 200s for everyone and has no key-free confirmation
    if rule.get("verify") is False:
        return _r(name, display_url, "uncertain", "can't confirm (JS app)")

    # 8) default: a clean HTTP 200 means the profile exists
    return _r(name, display_url, "found" if code == 200 else "not found", note)


def username_search(username, progress=None, max_workers=25):
    """Check a username across many public sites. Returns a list of result dicts
    with status one of: 'found', 'not found', 'uncertain', 'error'."""
    username = (username or "").strip()
    results = []
    total = len(USERNAME_SITES)
    if not username:
        return results
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_check_username_site, n, t, m, username): n
                for n, (t, m) in USERNAME_SITES.items()}
        for fut in concurrent.futures.as_completed(futs):
            results.append(fut.result())
            done += 1
            if progress:
                progress(done, total)
    # found first, then uncertain, then the rest — each group alphabetical
    rank = {"found": 0, "uncertain": 1}
    results.sort(key=lambda d: (rank.get(d["status"], 2), d["site"].lower()))
    return results


# ===========================================================================
#  Domain / DNS
# ===========================================================================
def dns_lookup(domain):
    out = {"domain": domain, "records": {}, "errors": []}
    try:
        import dns.resolver
    except Exception:
        out["errors"].append("dnspython not available")
        return out
    domain = domain.strip().replace("http://", "").replace("https://", "").strip("/")
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"):
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=TIMEOUT)
            out["records"][rtype] = [r.to_text() for r in answers]
        except Exception:
            pass
    # email-security posture: SPF (in TXT), DMARC (_dmarc TXT)
    posture = {}
    spf = [t for t in out["records"].get("TXT", []) if "v=spf1" in t.lower()]
    posture["SPF"] = spf[0].strip('"') if spf else "missing"
    try:
        dmarc = dns.resolver.resolve("_dmarc." + domain, "TXT", lifetime=TIMEOUT)
        posture["DMARC"] = [r.to_text().strip('"') for r in dmarc][0]
    except Exception:
        posture["DMARC"] = "missing"
    out["email_security"] = posture
    return out


def whois_lookup(domain):
    out = {"domain": domain, "data": {}, "error": None}
    domain = domain.strip().replace("http://", "").replace("https://", "").strip("/")
    try:
        import whois
        w = whois.whois(domain)
        keys = ["registrar", "creation_date", "expiration_date",
                "updated_date", "name_servers", "status", "emails",
                "org", "country", "registrant_country"]
        for k in keys:
            v = getattr(w, k, None) or (w.get(k) if hasattr(w, "get") else None)
            if v:
                out["data"][k] = v
    except Exception as e:
        out["error"] = str(e)[:120]
    return out


# ===========================================================================
#  IP intelligence
# ===========================================================================
def ip_info(target):
    """Resolve a host/IP and look up free geolocation + reverse DNS + ASN."""
    out = {"input": target, "ip": None, "reverse_dns": None, "geo": {}, "error": None}
    host = target.strip().replace("http://", "").replace("https://", "").strip("/")
    try:
        ip = socket.gethostbyname(host)
        out["ip"] = ip
    except Exception as e:
        out["error"] = f"Couldn't resolve '{host}': {e}"
        return out
    try:
        out["reverse_dns"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        out["reverse_dns"] = "(none)"
    try:  # free, no-key API
        r = requests.get(f"http://ip-api.com/json/{ip}"
                         "?fields=status,country,regionName,city,zip,lat,lon,"
                         "timezone,isp,org,as,reverse,mobile,proxy,hosting",
                         timeout=TIMEOUT)
        data = r.json()
        if data.get("status") == "success":
            out["geo"] = data
    except Exception as e:
        out["error"] = f"Geo lookup failed: {e}"
    return out


# ===========================================================================
#  Email recon
# ===========================================================================
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "temp-mail.org", "throwawaymail.com", "yopmail.com", "getnada.com",
    "trashmail.com", "sharklasers.com", "maildrop.cc", "fakemailgenerator.com",
    "dispostable.com", "mailnesia.com", "mintemail.com", "spamgourmet.com",
    "tempinbox.com", "mohmal.com", "emailondeck.com", "burnermail.io",
    "1secmail.com", "moakt.com", "tempmailo.com", "luxusmail.org",
}
ROLE_ACCOUNTS = {
    "admin", "administrator", "info", "support", "contact", "sales", "help",
    "billing", "abuse", "postmaster", "webmaster", "noreply", "no-reply",
    "hello", "team", "office", "marketing", "hr", "jobs", "careers", "security",
}


def email_recon(email):
    out = {"email": email, "valid_format": False, "domain": None, "local": None,
           "mx": [], "gravatar": None, "hibp_url": None,
           "disposable": False, "role_account": False, "notes": []}
    email = email.strip()
    out["valid_format"] = bool(EMAIL_RE.match(email))
    if not out["valid_format"]:
        out["notes"].append("That doesn't look like a valid email address.")
        return out
    local, domain = email.split("@", 1)
    out["domain"] = domain
    out["local"] = local
    out["disposable"] = domain.lower() in DISPOSABLE_DOMAINS
    out["role_account"] = local.lower() in ROLE_ACCOUNTS
    if out["disposable"]:
        out["notes"].append("This is a known DISPOSABLE / throwaway email domain.")
    if out["role_account"]:
        out["notes"].append("This is a ROLE account (a team inbox, not a person).")
    # can the domain receive mail?
    try:
        import dns.resolver
        mx = dns.resolver.resolve(domain, "MX", lifetime=TIMEOUT)
        out["mx"] = sorted(r.to_text() for r in mx)
    except Exception:
        out["notes"].append("No MX records found — may not receive email.")
    # gravatar (does this email have a public avatar?)
    h = hashlib.md5(email.lower().encode()).hexdigest()
    try:
        r = requests.get(f"https://www.gravatar.com/avatar/{h}?d=404",
                         headers=HEADERS, timeout=TIMEOUT)
        out["gravatar"] = (f"https://www.gravatar.com/avatar/{h}"
                           if r.status_code == 200 else None)
    except Exception:
        pass
    # breach self-check (HIBP requires a key for the API; link out)
    out["hibp_url"] = f"https://haveibeenpwned.com/account/{email}"
    return out


# ===========================================================================
#  Phone number (metadata only, via the phonenumbers library)
# ===========================================================================
def phone_info(number, default_region="US"):
    out = {"input": number, "valid": False, "data": {}, "error": None}
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone
        num = phonenumbers.parse(number, default_region)
        out["valid"] = phonenumbers.is_valid_number(num)
        out["data"] = {
            "International": phonenumbers.format_number(
                num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "E.164": phonenumbers.format_number(
                num, phonenumbers.PhoneNumberFormat.E164),
            "Country code": f"+{num.country_code}",
            "Region": geocoder.description_for_number(num, "en"),
            "Carrier": carrier.name_for_number(num, "en") or "(unknown)",
            "Timezones": ", ".join(timezone.time_zones_for_number(num)),
            "Line type": str(phonenumbers.number_type(num)).split(".")[-1]
            if hasattr(phonenumbers, "number_type") else "?",
        }
    except Exception as e:
        out["error"] = str(e)
    return out


# ===========================================================================
#  Image EXIF / metadata  (great for OSINT: cameras, timestamps, GPS)
# ===========================================================================
def exif_extract(path):
    out = {"path": path, "tags": {}, "gps": None, "error": None}
    try:
        from PIL import Image, ExifTags
        img = Image.open(path)
        out["tags"]["Image size"] = f"{img.width} x {img.height}"
        out["tags"]["Format"] = img.format
        exif = img.getexif()
        if not exif:
            out["notes"] = "No EXIF metadata found in this image."
            return out
        gps_raw = None
        for tag_id, value in exif.items():
            tag = ExifTags.TAGS.get(tag_id, tag_id)
            if tag == "GPSInfo":
                gps_raw = exif.get_ifd(tag_id)
                continue
            sval = str(value)
            if len(sval) < 120:
                out["tags"][str(tag)] = sval
        if gps_raw:
            out["gps"] = _decode_gps(gps_raw)
    except FileNotFoundError:
        out["error"] = "File not found."
    except Exception as e:
        out["error"] = f"Couldn't read image: {e}"
    return out


def _decode_gps(gps):
    from PIL import ExifTags
    g = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps.items()}

    def to_deg(v, ref):
        d, m, s = [float(x) for x in v]
        deg = d + m / 60 + s / 3600
        if ref in ("S", "W"):
            deg = -deg
        return round(deg, 6)

    try:
        lat = to_deg(g["GPSLatitude"], g.get("GPSLatitudeRef", "N"))
        lon = to_deg(g["GPSLongitude"], g.get("GPSLongitudeRef", "E"))
        return {"lat": lat, "lon": lon,
                "maps": f"https://www.google.com/maps?q={lat},{lon}"}
    except Exception:
        return None


# ===========================================================================
#  Website headers / fingerprint
# ===========================================================================
def http_headers(url):
    out = {"url": url, "status": None, "final_url": None, "headers": {},
           "tech": [], "robots": None, "error": None}
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                         allow_redirects=True)
        out["status"] = r.status_code
        out["final_url"] = r.url
        out["headers"] = dict(r.headers)
        body = r.text.lower()
        tech_signs = {
            "WordPress": "wp-content", "Cloudflare": "cloudflare",
            "React": "react", "jQuery": "jquery", "Bootstrap": "bootstrap",
            "Shopify": "shopify", "Wix": "wix.com", "Squarespace": "squarespace",
            "Google Analytics": "google-analytics", "Nginx": "nginx",
        }
        srv = (out["headers"].get("Server", "") + " "
               + out["headers"].get("X-Powered-By", "")).lower()
        for tech, sign in tech_signs.items():
            if sign in body or sign in srv:
                out["tech"].append(tech)
    except requests.RequestException as e:
        out["error"] = str(e)
        return out
    try:
        base = "/".join(out["final_url"].split("/")[:3])
        rb = requests.get(base + "/robots.txt", headers=HEADERS, timeout=TIMEOUT)
        out["robots"] = rb.text[:1500] if rb.status_code == 200 else "(none)"
    except Exception:
        out["robots"] = "(couldn't fetch)"
    return out


# ===========================================================================
#  Google/Bing dork generator
# ===========================================================================
def dork_generator(target):
    """Build handy search-engine 'dork' queries for a target (domain/name)."""
    t = target.strip()
    dorks = [
        ("Files (PDF/DOC/XLS)", f'site:{t} (filetype:pdf OR filetype:doc OR filetype:xls)'),
        ("Login / admin pages", f'site:{t} (inurl:login OR inurl:admin OR inurl:signin)'),
        ("Directory listings", f'site:{t} intitle:"index of"'),
        ("Config / backup files", f'site:{t} (ext:env OR ext:bak OR ext:sql OR ext:log)'),
        ("Exposed documents", f'site:{t} (intext:"confidential" OR intext:"internal use")'),
        ("Subdomains (rough)", f'site:*.{t}'),
        ("Email addresses", f'site:{t} intext:"@{t}"'),
        ("Mentions elsewhere", f'"{t}" -site:{t}'),
        ("Pastebin mentions", f'site:pastebin.com "{t}"'),
        ("LinkedIn", f'site:linkedin.com "{t}"'),
    ]
    out = []
    for label, q in dorks:
        out.append({"label": label, "query": q,
                    "google": "https://www.google.com/search?q=" + requests.utils.quote(q),
                    "bing": "https://www.bing.com/search?q=" + requests.utils.quote(q)})
    return out


# ===========================================================================
#  Certificate transparency -> subdomains   (à la Sublist3r / Amass)
# ===========================================================================
def crtsh_subdomains(domain, limit=300):
    """Find subdomains from certificate-transparency logs. Tries crt.sh first,
    then falls back to certspotter (both free, no key)."""
    out = {"domain": domain, "subdomains": [], "source": None, "error": None}
    domain = domain.strip().lower().replace("http://", "").replace(
        "https://", "").strip("/")
    seen = set()

    # 1) crt.sh
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                         headers=HEADERS, timeout=25)
        if r.status_code == 200 and r.text.strip():
            for row in r.json():
                for name in str(row.get("name_value", "")).splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(domain):
                        seen.add(name)
            if seen:
                out["source"] = "crt.sh"
    except Exception:
        pass

    # 2) fallback: certspotter
    if not seen:
        try:
            r = requests.get(
                "https://api.certspotter.com/v1/issuances"
                f"?domain={domain}&include_subdomains=true&expand=dns_names",
                headers=HEADERS, timeout=20)
            if r.status_code == 200:
                for issuance in r.json():
                    for name in issuance.get("dns_names", []):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(domain):
                            seen.add(name)
                if seen:
                    out["source"] = "certspotter"
            elif r.status_code == 429:
                out["error"] = "Both crt.sh and certspotter are rate-limited " \
                               "right now — try again shortly."
        except Exception as e:
            out["error"] = f"Subdomain lookup failed: {str(e)[:70]}"

    out["subdomains"] = sorted(seen)[:limit]
    if not seen and not out["error"]:
        out["error"] = "No subdomains found (sources may be temporarily down)."
    return out


# ===========================================================================
#  Wayback Machine archived URLs   (à la waybackurls)
# ===========================================================================
def wayback_urls(domain, limit=250):
    out = {"domain": domain, "urls": [], "error": None}
    domain = domain.strip().replace("http://", "").replace("https://", "").strip("/")
    try:
        r = requests.get(
            "http://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*&output=json&fl=original&collapse=urlkey"
            f"&limit={limit}", headers=HEADERS, timeout=20)
        rows = r.json()
        out["urls"] = [row[0] for row in rows[1:]]  # skip header row
    except Exception as e:
        out["error"] = f"Wayback lookup failed: {str(e)[:80]}"
    return out


# ===========================================================================
#  Shodan InternetDB  (FREE, no key): open ports, CPEs, vulns for an IP
# ===========================================================================
def shodan_internetdb(target):
    out = {"input": target, "ip": None, "ports": [], "hostnames": [],
           "cpes": [], "tags": [], "vulns": [], "error": None}
    host = target.strip().replace("http://", "").replace("https://", "").strip("/")
    try:
        ip = socket.gethostbyname(host)
        out["ip"] = ip
    except Exception as e:
        out["error"] = f"Couldn't resolve '{host}': {e}"
        return out
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}",
                         headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 404:
            out["error"] = "No InternetDB data for this IP (nothing indexed)."
            return out
        d = r.json()
        out["ports"] = d.get("ports", [])
        out["hostnames"] = d.get("hostnames", [])
        out["cpes"] = d.get("cpes", [])
        out["tags"] = d.get("tags", [])
        out["vulns"] = d.get("vulns", [])
    except Exception as e:
        out["error"] = f"InternetDB lookup failed: {str(e)[:80]}"
    return out


# ===========================================================================
#  GitHub user intelligence  (api.github.com, no key, rate-limited)
# ===========================================================================
def github_user(username):
    out = {"username": username, "found": False, "data": {}, "error": None}
    try:
        r = requests.get(f"https://api.github.com/users/{username.strip()}",
                         headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 404:
            out["error"] = "No such GitHub user."
            return out
        if r.status_code == 403:
            out["error"] = "GitHub rate limit hit (no API key). Try later."
            return out
        d = r.json()
        out["found"] = True
        for label, key in [("Name", "name"), ("Bio", "bio"),
                           ("Company", "company"), ("Location", "location"),
                           ("Public email", "email"), ("Blog/site", "blog"),
                           ("Twitter", "twitter_username"),
                           ("Public repos", "public_repos"),
                           ("Followers", "followers"),
                           ("Following", "following"),
                           ("Joined", "created_at"),
                           ("Profile", "html_url")]:
            v = d.get(key)
            if v not in (None, "", 0) or key in ("public_repos", "followers"):
                out["data"][label] = v
    except Exception as e:
        out["error"] = f"GitHub lookup failed: {str(e)[:80]}"
    return out


# ===========================================================================
#  Reverse IP  (other domains on the same server) - hackertarget free API
# ===========================================================================
def reverse_ip(target, limit=200):
    out = {"input": target, "ip": None, "domains": [], "error": None}
    host = target.strip().replace("http://", "").replace("https://", "").strip("/")
    try:
        ip = socket.gethostbyname(host)
        out["ip"] = ip
    except Exception as e:
        out["error"] = f"Couldn't resolve '{host}': {e}"
        return out
    try:
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                         headers=HEADERS, timeout=TIMEOUT)
        text = r.text.strip()
        if "API count exceeded" in text or "error" in text.lower():
            out["error"] = "Free reverse-IP quota exceeded for today."
            return out
        out["domains"] = [d for d in text.splitlines() if d][:limit]
    except Exception as e:
        out["error"] = f"Reverse-IP lookup failed: {str(e)[:80]}"
    return out


# ===========================================================================
#  SSL / TLS certificate inspection  (issuer, validity, SANs -> subdomains)
# ===========================================================================
def ssl_cert(target, port=443):
    import ssl
    out = {"host": target, "data": {}, "san": [], "error": None}
    host = target.strip().replace("http://", "").replace("https://", "").strip("/")
    host = host.split("/")[0]
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                out["data"]["TLS version"] = ss.version()
                out["data"]["Cipher"] = ss.cipher()[0] if ss.cipher() else "?"
        subj = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        out["data"]["Subject (CN)"] = subj.get("commonName", "?")
        out["data"]["Issuer"] = issuer.get("organizationName",
                                            issuer.get("commonName", "?"))
        out["data"]["Valid from"] = cert.get("notBefore")
        out["data"]["Valid until"] = cert.get("notAfter")
        out["data"]["Serial"] = cert.get("serialNumber", "")[:32]
        out["san"] = sorted({v for k, v in cert.get("subjectAltName", [])
                             if k == "DNS"})
    except ssl.SSLCertVerificationError as e:
        out["error"] = f"Certificate is INVALID/untrusted: {str(e)[:80]}"
    except Exception as e:
        out["error"] = f"Couldn't read certificate: {str(e)[:80]}"
    return out


# ===========================================================================
#  ASN / BGP info  (RIPEstat, RIPE NCC's official data API — free, no key)
# ===========================================================================
def _ripe(call, resource):
    r = requests.get(f"https://stat.ripe.net/data/{call}/data.json",
                     params={"resource": resource}, headers=HEADERS,
                     timeout=TIMEOUT)
    return r.json().get("data", {})


def asn_info(target):
    out = {"input": target, "ip": None, "data": {}, "prefixes": [], "error": None}
    raw = target.strip()
    try:
        asn_num = None
        if _IPV4.match(raw):
            ip = raw
        elif raw.upper().lstrip("AS").isdigit():
            ip, asn_num = None, int(raw.upper().lstrip("AS"))
        elif _DOMAIN.match(_clean_host(raw)):
            ip = socket.gethostbyname(_clean_host(raw))
        else:
            ip = None
        if ip:
            out["ip"] = ip
            ni = _ripe("network-info", ip)
            out["data"]["IP"] = ip
            out["data"]["Prefix"] = ni.get("prefix")
            asns = ni.get("asns", [])
            if asns:
                asn_num = int(asns[0])
                out["data"]["ASN"] = f"AS{asn_num}"
        if asn_num:
            ov = _ripe("as-overview", f"AS{asn_num}")
            out["data"]["ASN"] = f"AS{asn_num}  {ov.get('holder', '')}"
            out["data"]["Type"] = ov.get("type")
            out["data"]["Announced"] = ov.get("announced")
            # geolocation / country of the ASN
            try:
                geo = _ripe("rir", f"AS{asn_num}")
            except Exception:
                geo = {}
            # announced prefixes
            ap = _ripe("announced-prefixes", f"AS{asn_num}")
            for p in ap.get("prefixes", [])[:120]:
                out["prefixes"].append(p.get("prefix"))
        if not out["data"]:
            out["error"] = "Couldn't resolve to an IP or ASN."
    except Exception as e:
        out["error"] = f"ASN/BGP lookup failed: {str(e)[:80]}"
    return out


# ===========================================================================
#  urlscan.io public scan history (free, no key for search)
# ===========================================================================
def urlscan_search(domain, limit=20):
    out = {"domain": domain, "results": [], "error": None}
    dom = _clean_host(domain)
    try:
        r = requests.get("https://urlscan.io/api/v1/search/",
                         params={"q": f"domain:{dom}", "size": limit},
                         headers=HEADERS, timeout=15)
        if r.status_code != 200:
            out["error"] = f"urlscan returned HTTP {r.status_code}."
            return out
        for res in r.json().get("results", []):
            page = res.get("page", {})
            out["results"].append({
                "url": page.get("url"),
                "time": (res.get("task", {}).get("time") or "")[:10],
                "ip": page.get("ip"),
                "server": page.get("server"),
                "report": "https://urlscan.io/result/" + res.get("_id", "") + "/",
            })
    except Exception as e:
        out["error"] = f"urlscan lookup failed: {str(e)[:80]}"
    return out


# ===========================================================================
#  Web deep-dive: exposed files, security.txt, sitemap, header grade
# ===========================================================================
DEEP_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/security.txt", "/humans.txt", "/.git/HEAD", "/.env", "/.htaccess",
    "/config.php", "/wp-login.php", "/wp-json/wp/v2/users", "/admin/",
    "/administrator/", "/phpinfo.php", "/server-status", "/.DS_Store",
    "/backup.zip", "/.well-known/openid-configuration", "/api/", "/graphql",
]
SECURITY_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy",
                    "X-Frame-Options", "X-Content-Type-Options",
                    "Referrer-Policy", "Permissions-Policy"]


def web_deep(url):
    out = {"url": url, "base": None, "paths": [], "headers_present": [],
           "headers_missing": [], "grade": None, "error": None}
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                         allow_redirects=True)
        base = "/".join(r.url.split("/")[:3])
        out["base"] = base
        for h in SECURITY_HEADERS:
            (out["headers_present"] if h in r.headers
             else out["headers_missing"]).append(h)
        got = len(out["headers_present"])
        out["grade"] = ["F", "E", "D", "C", "B", "A", "A+"][min(got, 6)]
    except requests.RequestException as e:
        out["error"] = str(e)[:90]
        return out

    def check(path):
        try:
            rr = requests.get(base + path, headers=HEADERS, timeout=TIMEOUT,
                              allow_redirects=False)
            interesting = rr.status_code in (200, 401, 403)
            return {"path": path, "status": rr.status_code,
                    "interesting": interesting,
                    "size": len(rr.content)}
        except Exception:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for res in ex.map(check, DEEP_PATHS):
            if res and res["interesting"]:
                out["paths"].append(res)
    out["paths"].sort(key=lambda p: p["path"])
    return out


# ===========================================================================
#  Key-powered enrichment  (each needs a free, permanent API key)
# ===========================================================================
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


def _clean_host(t):
    return t.strip().replace("http://", "").replace("https://", "").strip("/")


def vt_lookup(target):
    """VirusTotal reputation for an IP, domain, or file hash."""
    out = {"input": target, "kind": None, "stats": {}, "data": {}, "error": None}
    key = get_key("virustotal")
    if not key:
        out["error"] = "needs_key"; return out
    t = _clean_host(target)
    if _IPV4.match(t):
        endpoint, out["kind"] = f"ip_addresses/{t}", "IP"
    elif _HASH_RE.match(t):
        endpoint, out["kind"] = f"files/{t}", "file hash"
    elif _DOMAIN.match(t):
        endpoint, out["kind"] = f"domains/{t}", "domain"
    else:
        out["error"] = "VirusTotal takes an IP, domain, or file hash."
        return out
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/{endpoint}",
                         headers={"x-apikey": key, **HEADERS}, timeout=TIMEOUT)
        if r.status_code == 401:
            out["error"] = "VirusTotal rejected the key."; return out
        if r.status_code == 404:
            out["error"] = "Not found in VirusTotal."; return out
        a = r.json().get("data", {}).get("attributes", {})
        out["stats"] = a.get("last_analysis_stats", {})
        for label, k in [("Reputation", "reputation"),
                         ("Owner / ASN", "as_owner"), ("Country", "country"),
                         ("Registrar", "registrar"),
                         ("Categories", "categories"),
                         ("Type", "type_description"),
                         ("Names", "names"), ("Size", "size"),
                         ("Times submitted", "times_submitted")]:
            v = a.get(k)
            if v:
                out["data"][label] = (", ".join(v) if isinstance(v, list)
                                      else (", ".join(f"{kk}:{vv}" for kk, vv
                                            in v.items()) if isinstance(v, dict)
                                            else v))
    except Exception as e:
        out["error"] = f"VirusTotal lookup failed: {str(e)[:70]}"
    return out


def abuseipdb_lookup(target):
    out = {"input": target, "ip": None, "data": {}, "error": None}
    key = get_key("abuseipdb")
    if not key:
        out["error"] = "needs_key"; return out
    try:
        out["ip"] = socket.gethostbyname(_clean_host(target))
    except Exception as e:
        out["error"] = f"Couldn't resolve: {e}"; return out
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         params={"ipAddress": out["ip"], "maxAgeInDays": 90},
                         headers={"Key": key, "Accept": "application/json"},
                         timeout=TIMEOUT)
        d = r.json().get("data", {})
        out["data"] = {
            "Abuse score": f"{d.get('abuseConfidenceScore', 0)} / 100",
            "Total reports": d.get("totalReports", 0),
            "Distinct reporters": d.get("numDistinctUsers", 0),
            "ISP": d.get("isp"), "Domain": d.get("domain"),
            "Usage type": d.get("usageType"), "Country": d.get("countryCode"),
            "Tor exit node": d.get("isTor"),
            "Last reported": d.get("lastReportedAt"),
        }
    except Exception as e:
        out["error"] = f"AbuseIPDB lookup failed: {str(e)[:70]}"
    return out


def shodan_host(target):
    out = {"input": target, "ip": None, "data": {}, "ports": [], "vulns": [],
           "banners": [], "error": None}
    key = get_key("shodan")
    if not key:
        out["error"] = "needs_key"; return out
    try:
        out["ip"] = socket.gethostbyname(_clean_host(target))
    except Exception as e:
        out["error"] = f"Couldn't resolve: {e}"; return out
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{out['ip']}",
                         params={"key": key}, timeout=TIMEOUT)
        if r.status_code == 401:
            out["error"] = "Shodan rejected the key."; return out
        if r.status_code == 404:
            out["error"] = "No Shodan data for this IP."; return out
        d = r.json()
        out["ports"] = d.get("ports", [])
        out["vulns"] = list(d.get("vulns", []) or [])
        for label, k in [("Org", "org"), ("ISP", "isp"), ("OS", "os"),
                         ("Country", "country_name"), ("City", "city"),
                         ("Hostnames", "hostnames")]:
            v = d.get(k)
            if v:
                out["data"][label] = ", ".join(v) if isinstance(v, list) else v
        for item in d.get("data", [])[:8]:
            prod = item.get("product", "")
            out["banners"].append(f"port {item.get('port')}: "
                                  f"{prod or item.get('_shodan', {}).get('module', '')}")
    except Exception as e:
        out["error"] = f"Shodan lookup failed: {str(e)[:70]}"
    return out


def ipinfo_lookup(target):
    out = {"input": target, "data": {}, "error": None}
    key = get_key("ipinfo")
    if not key:
        out["error"] = "needs_key"; return out
    try:
        ip = socket.gethostbyname(_clean_host(target))
    except Exception as e:
        out["error"] = f"Couldn't resolve: {e}"; return out
    try:
        r = requests.get(f"https://ipinfo.io/{ip}", params={"token": key},
                         headers=HEADERS, timeout=TIMEOUT)
        d = r.json()
        if d.get("error"):
            out["error"] = str(d["error"].get("message", "IPinfo error"))
            return out
        for label, k in [("IP", "ip"), ("Hostname", "hostname"),
                         ("City", "city"), ("Region", "region"),
                         ("Country", "country"), ("Postal", "postal"),
                         ("Location", "loc"), ("Org / ASN", "org"),
                         ("Timezone", "timezone")]:
            if d.get(k):
                out["data"][label] = d[k]
        if isinstance(d.get("privacy"), dict):
            p = d["privacy"]
            flags = [n for n in ("vpn", "proxy", "tor", "relay", "hosting")
                     if p.get(n)]
            out["data"]["Privacy flags"] = ", ".join(flags) or "none"
    except Exception as e:
        out["error"] = f"IPinfo lookup failed: {str(e)[:70]}"
    return out


def greynoise_lookup(target):
    out = {"input": target, "ip": None, "data": {}, "error": None}
    key = get_key("greynoise")
    if not key:
        out["error"] = "needs_key"; return out
    try:
        out["ip"] = socket.gethostbyname(_clean_host(target))
    except Exception as e:
        out["error"] = f"Couldn't resolve: {e}"; return out
    try:
        r = requests.get(f"https://api.greynoise.io/v3/community/{out['ip']}",
                         headers={"key": key, **HEADERS}, timeout=TIMEOUT)
        d = r.json()
        if r.status_code == 401:
            out["error"] = "GreyNoise rejected the key."; return out
        out["data"] = {
            "Classification": d.get("classification", "unknown"),
            "Internet scanner (noise)": d.get("noise"),
            "Known-benign (RIOT)": d.get("riot"),
            "Actor / name": d.get("name"),
            "Last seen": d.get("last_seen"),
            "Note": d.get("message"),
        }
    except Exception as e:
        out["error"] = f"GreyNoise lookup failed: {str(e)[:70]}"
    return out


def hunter_domain(domain):
    out = {"domain": domain, "organization": None, "emails": [], "error": None}
    key = get_key("hunter")
    if not key:
        out["error"] = "needs_key"; return out
    try:
        r = requests.get("https://api.hunter.io/v2/domain-search",
                         params={"domain": _clean_host(domain), "api_key": key,
                                 "limit": 25}, timeout=TIMEOUT)
        if r.status_code == 401:
            out["error"] = "Hunter rejected the key."; return out
        d = r.json().get("data", {})
        out["organization"] = d.get("organization")
        for e in d.get("emails", []):
            out["emails"].append({
                "value": e.get("value"),
                "confidence": e.get("confidence"),
                "position": e.get("position") or "",
                "type": e.get("type") or "",
            })
    except Exception as e:
        out["error"] = f"Hunter lookup failed: {str(e)[:70]}"
    return out


# ===========================================================================
#  Target-type detection + Auto-Recon orchestrator
# ===========================================================================
_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,}$", re.I)


def detect_target_type(target):
    t = target.strip().replace("http://", "").replace("https://", "").strip("/")
    if EMAIL_RE.match(t):
        return "email"
    if _IPV4.match(t):
        return "ip"
    if _DOMAIN.match(t):
        return "domain"
    return "username"


def auto_recon(target, progress=None):
    """
    Generator that auto-detects the target type and runs every relevant module,
    yielding display 'events' so the GUI can stream results as they arrive.

    Event tuples:
      ("h", text)              -> big heading
      ("sub", text)            -> section heading
      ("kv", key, value)       -> key/value row
      ("link", text, url)      -> clickable link (on its own line)
      ("line", text, tag)      -> a plain line with a tag
    """
    ttype = detect_target_type(target)
    yield ("h", f"Auto-Recon: {target}")
    yield ("line", f"Detected target type: {ttype.upper()}\n", "good")

    steps, done = [], [0]

    def step(title, fn):
        steps.append((title, fn))

    # build the plan based on type
    if ttype == "domain":
        step("DNS records & email security", lambda: _ev_dns(dns_lookup(target)))
        step("WHOIS", lambda: _ev_whois(whois_lookup(target)))
        step("SSL/TLS certificate", lambda: _ev_ssl(ssl_cert(target)))
        step("Subdomains (cert transparency)",
             lambda: _ev_subs(crtsh_subdomains(target)))
        step("Website fingerprint", lambda: _ev_headers(http_headers(target)))
        step("Web deep-dive (exposed files)", lambda: _ev_webdeep(web_deep(target)))
        step("IP intelligence", lambda: _ev_ip(ip_info(target)))
        step("ASN / BGP", lambda: _ev_asn(asn_info(target)))
        step("Open ports & vulns", lambda: _ev_idb(shodan_internetdb(target)))
        step("Reverse IP (neighbours)", lambda: _ev_revip(reverse_ip(target)))
        step("urlscan.io history", lambda: _ev_urlscan(urlscan_search(target)))
        step("Archived URLs (Wayback)", lambda: _ev_wb(wayback_urls(target)))
        if get_key("virustotal"):
            step("VirusTotal reputation", lambda: _ev_vt(vt_lookup(target)))
        if get_key("shodan"):
            step("Shodan host", lambda: _ev_shodan(shodan_host(target)))
        if get_key("hunter"):
            step("Domain emails (Hunter)", lambda: _ev_hunter(hunter_domain(target)))
        step("Search dorks", lambda: _ev_dorks(dork_generator(target)))
    elif ttype == "ip":
        step("IP intelligence", lambda: _ev_ip(ip_info(target)))
        step("ASN / BGP", lambda: _ev_asn(asn_info(target)))
        step("Open ports & vulns", lambda: _ev_idb(shodan_internetdb(target)))
        step("Reverse IP (neighbours)", lambda: _ev_revip(reverse_ip(target)))
        if get_key("virustotal"):
            step("VirusTotal reputation", lambda: _ev_vt(vt_lookup(target)))
        if get_key("abuseipdb"):
            step("AbuseIPDB", lambda: _ev_abuse(abuseipdb_lookup(target)))
        if get_key("shodan"):
            step("Shodan host", lambda: _ev_shodan(shodan_host(target)))
        if get_key("ipinfo"):
            step("IPinfo", lambda: _ev_ipinfo(ipinfo_lookup(target)))
        if get_key("greynoise"):
            step("GreyNoise scanner check", lambda: _ev_grey(greynoise_lookup(target)))
    elif ttype == "email":
        step("Email recon", lambda: _ev_email(email_recon(target)))
        local = target.split("@", 1)[0]
        dom = target.split("@", 1)[1]
        step("GitHub user", lambda: _ev_gh(github_user(local)))
        step("Username footprint", lambda: _ev_user(username_search(local)))
        step("Domain MX / DNS", lambda: _ev_dns(dns_lookup(dom)))
        if get_key("hunter"):
            step("Domain emails (Hunter)", lambda: _ev_hunter(hunter_domain(dom)))
        if get_key("virustotal"):
            step("VirusTotal (domain)", lambda: _ev_vt(vt_lookup(dom)))
        step("Search dorks", lambda: _ev_dorks(dork_generator(dom)))
    else:  # username
        step("GitHub user", lambda: _ev_gh(github_user(target)))
        step("Username footprint", lambda: _ev_user(username_search(target)))
        step("Search dorks", lambda: _ev_dorks(dork_generator(target)))

    total = len(steps)
    for i, (title, fn) in enumerate(steps, 1):
        yield ("sub", f"[{i}/{total}]  {title}")
        try:
            for ev in fn():
                yield ev
        except Exception as e:
            yield ("line", f"   (failed: {str(e)[:80]})\n", "warn")
        if progress:
            progress(i, total)
    yield ("line", "\n✔ Auto-Recon complete.\n", "good")


# -- helpers that turn a module result dict into a stream of events ----------
def _ev_dns(d):
    if not d["records"]:
        yield ("line", "   no DNS records\n", "warn")
    for rt, vals in d["records"].items():
        yield ("kv", rt, ", ".join(vals)[:200])
    for k, v in d.get("email_security", {}).items():
        tag = "warn" if v == "missing" else "good"
        yield ("line", f"   {k}: {v[:120]}\n", tag)


def _ev_ssl(s):
    if s["error"]:
        yield ("line", "   " + s["error"] + "\n", "warn"); return
    for k, v in s["data"].items():
        yield ("kv", k, str(v))
    if s["san"]:
        yield ("line", f"   {len(s['san'])} names on cert (SANs):\n", "good")
        for n in s["san"][:40]:
            yield ("line", "     " + n + "\n", "val")


def _ev_webdeep(w):
    if w["error"]:
        yield ("line", "   " + w["error"] + "\n", "warn"); return
    yield ("kv", "Security headers", f"{w['grade']} "
           f"({len(w['headers_present'])}/6 present)")
    if w["headers_missing"]:
        yield ("line", "   missing: " + ", ".join(w["headers_missing"]) + "\n",
               "warn")
    if w["paths"]:
        yield ("line", f"   {len(w['paths'])} interesting paths:\n", "warn")
        for p in w["paths"]:
            yield ("line", f"     {p['status']}  {p['path']}\n", "val")
    else:
        yield ("line", "   no commonly-exposed files found\n", "good")


def _ev_asn(a):
    if a["error"]:
        yield ("line", "   " + a["error"] + "\n", "warn"); return
    for k, v in a["data"].items():
        if v:
            yield ("kv", k, str(v))
    if a["prefixes"]:
        yield ("line", f"   {len(a['prefixes'])} announced prefixes (first few):\n",
               "good")
        for p in a["prefixes"][:15]:
            yield ("line", "     " + p + "\n", "val")


def _ev_urlscan(u):
    if u["error"]:
        yield ("line", "   " + u["error"] + "\n", "warn"); return
    yield ("line", f"   {len(u['results'])} public scans on urlscan.io\n", "good")
    for r in u["results"][:20]:
        yield ("link", f"   {r['time']}  {r['url']}", r["report"])


def _ev_whois(w):
    if w["error"]:
        yield ("line", "   " + w["error"] + "\n", "warn")
    for k, v in w["data"].items():
        yield ("kv", k, str(v)[:200])


def _ev_subs(s):
    if s["error"]:
        yield ("line", "   " + str(s["error"]) + "\n", "warn"); return
    yield ("line", f"   {len(s['subdomains'])} unique subdomains found\n", "good")
    for sub in s["subdomains"]:
        yield ("link", "   " + sub, "https://" + sub)


def _ev_headers(h):
    if h["error"]:
        yield ("line", "   " + h["error"] + "\n", "warn"); return
    yield ("kv", "Status", str(h["status"]))
    yield ("kv", "Server", h["headers"].get("Server", "?"))
    if h["tech"]:
        yield ("kv", "Tech", ", ".join(h["tech"]))


def _ev_ip(i):
    if i["error"] and not i["ip"]:
        yield ("line", "   " + i["error"] + "\n", "warn"); return
    yield ("kv", "IP", str(i["ip"]))
    yield ("kv", "Reverse DNS", str(i["reverse_dns"]))
    g = i["geo"]
    for k in ("country", "city", "isp", "org", "as"):
        if g.get(k):
            yield ("kv", k.upper() if k == "as" else k.title(), str(g[k]))
    if g.get("lat") is not None:
        yield ("link", f"   map: {g['lat']},{g['lon']}",
               f"https://www.google.com/maps?q={g['lat']},{g['lon']}")


def _ev_idb(d):
    if d["error"]:
        yield ("line", "   " + d["error"] + "\n", "warn"); return
    yield ("kv", "Open ports", ", ".join(map(str, d["ports"])) or "none")
    if d["hostnames"]:
        yield ("kv", "Hostnames", ", ".join(d["hostnames"]))
    if d["vulns"]:
        yield ("line", "   ⚠ Known CVEs: " + ", ".join(d["vulns"][:20]) + "\n", "warn")
    if d["cpes"]:
        yield ("kv", "Software", ", ".join(d["cpes"][:8]))


def _ev_revip(r):
    if r["error"]:
        yield ("line", "   " + r["error"] + "\n", "warn"); return
    yield ("line", f"   {len(r['domains'])} domains share IP {r['ip']}\n", "good")
    for d in r["domains"][:60]:
        yield ("line", "   " + d + "\n", "val")


def _ev_wb(w):
    if w["error"]:
        yield ("line", "   " + w["error"] + "\n", "warn"); return
    yield ("line", f"   {len(w['urls'])} archived URLs\n", "good")
    for u in w["urls"][:60]:
        yield ("link", "   " + u, u)


def _ev_dorks(ds):
    for d in ds:
        yield ("link", "   " + d["label"], d["google"])


def _ev_email(e):
    yield ("kv", "Valid format", "yes" if e["valid_format"] else "no")
    if e["mx"]:
        yield ("kv", "Mail servers", ", ".join(e["mx"]))
    if e["gravatar"]:
        yield ("link", "   Gravatar avatar", e["gravatar"])
    if e["hibp_url"]:
        yield ("link", "   Breach check (HIBP)", e["hibp_url"])


def _ev_gh(g):
    if g["error"]:
        yield ("line", "   " + g["error"] + "\n", "warn"); return
    for k, v in g["data"].items():
        if k == "Profile":
            yield ("link", "   " + str(v), str(v))
        else:
            yield ("kv", k, str(v))


def _ev_user(results):
    found = [r for r in results if r["status"] == "found"]
    uncertain = sum(1 for r in results if r["status"] == "uncertain")
    yield ("line", f"   confirmed on {len(found)} of {len(results)} sites "
           f"({uncertain} unverifiable)\n", "good")
    for r in found:
        yield ("link", "   " + r["site"], r["url"])


def _ev_vt(d):
    if d["error"]:
        yield ("line", "   " + d["error"] + "\n", "warn"); return
    s = d["stats"]
    mal = s.get("malicious", 0) + s.get("suspicious", 0)
    tag = "warn" if mal else "good"
    yield ("line", f"   {mal} engines flagged it "
           f"(harmless: {s.get('harmless', 0)})\n", tag)
    for k, v in d["data"].items():
        yield ("kv", k, str(v)[:200])


def _ev_abuse(d):
    if d["error"]:
        yield ("line", "   " + d["error"] + "\n", "warn"); return
    score = d["data"].get("Abuse score", "")
    yield ("line", f"   Abuse score: {score}\n",
           "warn" if not str(score).startswith("0 ") else "good")
    for k, v in d["data"].items():
        if v not in (None, ""):
            yield ("kv", k, str(v))


def _ev_shodan(d):
    if d["error"]:
        yield ("line", "   " + d["error"] + "\n", "warn"); return
    yield ("kv", "Open ports", ", ".join(map(str, d["ports"])) or "none")
    for k, v in d["data"].items():
        yield ("kv", k, str(v))
    if d["vulns"]:
        yield ("line", "   ⚠ CVEs: " + ", ".join(d["vulns"][:20]) + "\n", "warn")
    for b in d["banners"]:
        yield ("line", "   " + b + "\n", "val")


def _ev_ipinfo(d):
    if d["error"]:
        yield ("line", "   " + d["error"] + "\n", "warn"); return
    for k, v in d["data"].items():
        yield ("kv", k, str(v))


def _ev_grey(d):
    if d["error"]:
        yield ("line", "   " + d["error"] + "\n", "warn"); return
    for k, v in d["data"].items():
        if v not in (None, ""):
            yield ("kv", k, str(v))


def _ev_hunter(d):
    if d["error"]:
        yield ("line", "   " + d["error"] + "\n", "warn"); return
    if d["organization"]:
        yield ("kv", "Organization", d["organization"])
    yield ("line", f"   {len(d['emails'])} emails found\n", "good")
    for e in d["emails"]:
        extra = f" ({e['position']})" if e["position"] else ""
        yield ("line", f"   {e['value']}  [{e['confidence']}%]{extra}\n", "val")


if __name__ == "__main__":
    # tiny offline self-test
    print("phone:", phone_info("+1 202-456-1111")["valid"])
    print("dorks:", len(dork_generator("example.com")), "queries")
    print("detect:", detect_target_type("a@b.com"), detect_target_type("8.8.8.8"),
          detect_target_type("example.com"), detect_target_type("torvalds"))
