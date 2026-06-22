"""
EZ-OSINT  -  Open-Source Intelligence Multitool
================================================
Pick what you want to look up (a username, domain, IP, email, phone number,
image, or website), type it in, and EZ-OSINT gathers what's PUBLICLY available
about it from public sources.

For security research, CTFs, auditing your OWN footprint, and authorised
testing. Respect privacy and the law.

Run:  python osint_gui.py
"""

import threading
import webbrowser
import tkinter as tk
from tkinter import ttk, filedialog

import osint_engine as E


BG, PANEL, ACCENT, TEXT, MUTED = "#15181f", "#20242e", "#5ad1c0", "#e6e8ee", "#8b93a7"
CODE_BG, GOOD, WARN, DANGER, LINK = "#0f1117", "#5fd68a", "#ffcc66", "#ff7a85", "#6fb4ff"

MODULES = [
    "🚀 Auto-Recon (everything)",
    "Username footprint",
    "Domain / DNS records",
    "Domain WHOIS",
    "Subdomains (cert transparency)",
    "SSL/TLS certificate",
    "Web deep-dive (exposed files)",
    "IP / host intelligence",
    "ASN / BGP info",
    "Open ports & vulns (Shodan)",
    "Reverse IP (shared host)",
    "urlscan.io history",
    "Email recon",
    "GitHub user",
    "Phone number",
    "Image metadata (EXIF)",
    "Website fingerprint",
    "Archived URLs (Wayback)",
    "Search-dork generator",
    "🔑 VirusTotal reputation",
    "🔑 AbuseIPDB (IP abuse)",
    "🔑 Shodan host (full)",
    "🔑 IPinfo (geo / ASN)",
    "🔑 GreyNoise (scanner check)",
    "🔑 Hunter (domain emails)",
]
HINTS = {
    "🚀 Auto-Recon (everything)": "ANYTHING — a domain, IP, email, or username. "
                                  "It figures out the type and runs everything.",
    "Username footprint": "a username / handle  (e.g. torvalds)",
    "Domain / DNS records": "a domain  (e.g. example.com)",
    "Domain WHOIS": "a domain  (e.g. example.com)",
    "Subdomains (cert transparency)": "a domain  (e.g. example.com)",
    "SSL/TLS certificate": "a domain / host  (e.g. example.com)",
    "Web deep-dive (exposed files)": "a website / URL  (e.g. example.com)",
    "IP / host intelligence": "an IP or hostname  (e.g. 8.8.8.8 or github.com)",
    "ASN / BGP info": "an IP, hostname, or ASN  (e.g. 8.8.8.8 or AS15169)",
    "Open ports & vulns (Shodan)": "an IP or hostname  (e.g. 8.8.8.8)",
    "Reverse IP (shared host)": "an IP or hostname  (e.g. example.com)",
    "urlscan.io history": "a domain  (e.g. example.com)",
    "Email recon": "an email address  (e.g. you@example.com)",
    "GitHub user": "a GitHub username  (e.g. torvalds)",
    "Phone number": "a phone number with country code  (e.g. +1 202 456 1111)",
    "Image metadata (EXIF)": "click Browse to pick an image file",
    "Website fingerprint": "a website / URL  (e.g. example.com)",
    "Archived URLs (Wayback)": "a domain  (e.g. example.com)",
    "Search-dork generator": "a domain or name  (e.g. example.com)",
    "🔑 VirusTotal reputation": "an IP, domain, or file hash  (needs free key)",
    "🔑 AbuseIPDB (IP abuse)": "an IP or hostname  (needs free key)",
    "🔑 Shodan host (full)": "an IP or hostname  (needs free key)",
    "🔑 IPinfo (geo / ASN)": "an IP or hostname  (needs free key)",
    "🔑 GreyNoise (scanner check)": "an IP or hostname  (needs free key)",
    "🔑 Hunter (domain emails)": "a domain  (needs free key)",
}


class OsintApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("EZ-OSINT  -  Open-Source Intelligence Multitool")
        self.geometry("1080x740")
        self.minsize(880, 600)
        self.configure(bg=BG)
        self._link_seq = 0
        self.busy = False
        self._report_buffer = []     # [(text, tag, url)] for export
        self._report_title = "EZ-OSINT report"

        self._style()
        self._build_top()
        self._build_controls()
        self._build_results()
        self._build_status()
        self._on_module_change()

    def _style(self):
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except Exception:
            pass
        s.configure("TCombobox", fieldbackground=PANEL, background=PANEL,
                    foreground=TEXT, arrowcolor=ACCENT)

    # ----------------------------------------------------------------- top
    def _build_top(self):
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=16, pady=(12, 2))
        tk.Label(bar, text="🛰  EZ-OSINT", bg=BG, fg=ACCENT,
                 font=("Segoe UI", 18, "bold")).pack(side="left")
        tk.Label(bar, text="Open-Source Intelligence Multitool", bg=BG,
                 fg=MUTED, font=("Segoe UI", 11)).pack(side="left",
                                                       padx=(10, 0), pady=(6, 0))
        tk.Button(bar, text="🔑  API Keys", command=self._open_keys,
                  bg=PANEL, fg=TEXT, relief="flat", cursor="hand2",
                  font=("Segoe UI Semibold", 10), padx=14, pady=6).pack(
            side="right")
        tk.Label(self,
                 text="ℹ  Gathers only PUBLIC information from public sources. "
                      "For security research, CTFs, checking your own footprint, "
                      "and authorised testing — not for harassing, stalking, or "
                      "profiling private individuals.",
                 bg="#1b1f29", fg=MUTED, anchor="w", justify="left",
                 font=("Segoe UI", 9), padx=12, pady=6,
                 wraplength=1030).pack(fill="x", padx=16, pady=(4, 0))

    # ------------------------------------------------------------- controls
    def _build_controls(self):
        f = tk.Frame(self, bg=BG)
        f.pack(fill="x", padx=16, pady=10)
        tk.Label(f, text="Look up:", bg=BG, fg=MUTED,
                 font=("Segoe UI", 10)).pack(side="left")
        self.module_var = tk.StringVar(value=MODULES[0])
        self.module_menu = ttk.Combobox(f, textvariable=self.module_var,
                                        values=MODULES, state="readonly",
                                        width=30, font=("Segoe UI", 10))
        self.module_menu.pack(side="left", padx=(8, 14))
        self.module_menu.bind("<<ComboboxSelected>>",
                              lambda e: self._on_module_change())

        self.query = tk.Entry(f, bg=PANEL, fg=TEXT, insertbackground=TEXT,
                              relief="flat", font=("Cascadia Mono", 11))
        self.query.pack(side="left", fill="x", expand=True, ipady=4, padx=(0, 10))
        self.query.bind("<Return>", lambda e: self.run_search())

        self.browse_btn = tk.Button(f, text="📁 Browse…", command=self._browse,
                                    bg=PANEL, fg=TEXT, relief="flat",
                                    cursor="hand2", padx=12, pady=6)
        self.browse_btn.pack(side="left", padx=(0, 8))
        self.search_btn = tk.Button(f, text="🔎  Search", command=self.run_search,
                                    bg=ACCENT, fg="#0c1116", relief="flat",
                                    cursor="hand2", font=("Segoe UI Semibold", 11),
                                    padx=18, pady=6)
        self.search_btn.pack(side="left")
        self.export_btn = tk.Button(f, text="💾 Export", command=self.export_report,
                                    bg=PANEL, fg=TEXT, relief="flat",
                                    cursor="hand2", font=("Segoe UI Semibold", 10),
                                    padx=12, pady=6, state="disabled")
        self.export_btn.pack(side="left", padx=(8, 0))

        self.hint = tk.Label(self, text="", bg=BG, fg=MUTED,
                             font=("Segoe UI", 9), anchor="w")
        self.hint.pack(fill="x", padx=18)

    def _on_module_change(self):
        mod = self.module_var.get()
        self.hint.config(text="↳ enter " + HINTS.get(mod, ""))
        self.browse_btn.pack_forget()
        if mod == "Image metadata (EXIF)":
            self.browse_btn.pack(side="left", padx=(0, 8),
                                 before=self.search_btn)

    def _browse(self):
        path = filedialog.askopenfilename(
            title="Pick an image",
            filetypes=[("Images", "*.jpg *.jpeg *.png *.tif *.tiff *.heic *.webp"),
                       ("All files", "*.*")])
        if path:
            self.query.delete(0, "end")
            self.query.insert(0, path)

    # -------------------------------------------------------------- results
    def _build_results(self):
        wrap = tk.Frame(self, bg=BG)
        wrap.pack(fill="both", expand=True, padx=16, pady=(4, 6))
        sc = tk.Scrollbar(wrap)
        sc.pack(side="right", fill="y")
        self.out = tk.Text(wrap, bg=CODE_BG, fg=TEXT, relief="flat", wrap="word",
                           font=("Cascadia Mono", 10), padx=14, pady=12,
                           yscrollcommand=sc.set, insertbackground=TEXT)
        self.out.pack(side="left", fill="both", expand=True)
        sc.config(command=self.out.yview)
        self.out.tag_configure("h", foreground=ACCENT,
                               font=("Segoe UI", 13, "bold"))
        self.out.tag_configure("sub", foreground=ACCENT,
                               font=("Segoe UI Semibold", 11))
        self.out.tag_configure("key", foreground=MUTED)
        self.out.tag_configure("val", foreground=TEXT)
        self.out.tag_configure("good", foreground=GOOD,
                               font=("Cascadia Mono", 10, "bold"))
        self.out.tag_configure("bad", foreground=MUTED)
        self.out.tag_configure("warn", foreground=WARN)
        self.out.configure(state="disabled")
        self._welcome()

    def _build_status(self):
        self.progress = ttk.Progressbar(self, mode="determinate", maximum=100)
        self.progress.pack(fill="x", padx=16)
        self.status = tk.Label(self, text="Pick what to look up, type it, and "
                                          "hit Search.", bg=PANEL, fg=MUTED,
                               anchor="w", font=("Segoe UI", 9), padx=12, pady=5)
        self.status.pack(fill="x", side="bottom")

    # ----------------------------------------------------------- text helpers
    def _clear(self):
        self.out.configure(state="normal")
        self.out.delete("1.0", "end")
        self._report_buffer = []

    def _ins(self, text, tag="val"):
        self.out.insert("end", text, tag)
        self._report_buffer.append((text, tag, None))

    def _link(self, text, url):
        tag = f"link{self._link_seq}"
        self._link_seq += 1
        self.out.tag_configure(tag, foreground=LINK, underline=True)
        self.out.tag_bind(tag, "<Button-1>", lambda e, u=url: webbrowser.open(u))
        self.out.tag_bind(tag, "<Enter>", lambda e: self.out.config(cursor="hand2"))
        self.out.tag_bind(tag, "<Leave>", lambda e: self.out.config(cursor=""))
        self.out.insert("end", text, tag)
        self._report_buffer.append((text, "link", url))

    def _done(self):
        self.out.configure(state="disabled")

    def _welcome(self):
        self._clear()
        self._ins("Welcome to EZ-OSINT\n\n", "h")
        self._ins("Choose a lookup type from the dropdown, type your target, and "
                "press Search.\n\n", "val")
        self._ins("What each lookup does:\n", "sub")
        for m in MODULES:
            self._ins(f"   • {m}\n", "key")
        self._ins("\nEverything here comes from public sources. Blue underlined "
                "text is clickable.\n", "key")
        self._done()

    # --------------------------------------------------------------- search
    def run_search(self):
        if self.busy:
            return
        mod = self.module_var.get()
        q = self.query.get().strip()
        if not q:
            self.status.config(text="Type something to look up first.")
            return
        self.busy = True
        self.search_btn.config(state="disabled")
        self.progress["value"] = 0
        self.status.config(text=f"Searching ({mod})…")

        def worker():
            try:
                self._dispatch(mod, q)
            except Exception as e:
                self.after(0, lambda: self._error(str(e)))
            finally:
                self.after(0, self._finish)
        threading.Thread(target=worker, daemon=True).start()

    def _finish(self):
        self.busy = False
        self.search_btn.config(state="normal")
        self.progress["value"] = 100
        if self._report_buffer:
            self.export_btn.config(state="normal")

    def _error(self, msg):
        self._clear(); self._ins("Something went wrong\n\n", "h")
        self._ins(msg, "warn"); self._done()
        self.status.config(text="Error.")

    def _dispatch(self, mod, q):
        self._report_title = f"EZ-OSINT — {mod} — {q}"
        fn = {
            "🚀 Auto-Recon (everything)": self._r_auto,
            "Username footprint": self._r_username,
            "Domain / DNS records": self._r_dns,
            "Domain WHOIS": self._r_whois,
            "Subdomains (cert transparency)": self._r_subs,
            "SSL/TLS certificate": self._r_ssl,
            "Web deep-dive (exposed files)": self._r_webdeep,
            "IP / host intelligence": self._r_ip,
            "ASN / BGP info": self._r_asn,
            "Open ports & vulns (Shodan)": self._r_ports,
            "Reverse IP (shared host)": self._r_revip,
            "urlscan.io history": self._r_urlscan,
            "Email recon": self._r_email,
            "GitHub user": self._r_github,
            "Phone number": self._r_phone,
            "Image metadata (EXIF)": self._r_exif,
            "Website fingerprint": self._r_headers,
            "Archived URLs (Wayback)": self._r_wayback,
            "Search-dork generator": self._r_dorks,
            "🔑 VirusTotal reputation": self._r_vt,
            "🔑 AbuseIPDB (IP abuse)": self._r_abuse,
            "🔑 Shodan host (full)": self._r_shodan,
            "🔑 IPinfo (geo / ASN)": self._r_ipinfo,
            "🔑 GreyNoise (scanner check)": self._r_greynoise,
            "🔑 Hunter (domain emails)": self._r_hunter,
        }[mod]
        fn(q)

    # marshal a render onto the UI thread
    def _render(self, build):
        self.after(0, lambda: (build(), self._done(),
                               self.status.config(text="Done.")))

    # ------------------------------------------------------- module renders
    def _r_username(self, q):
        def prog(done, total):
            self.after(0, lambda: self.progress.config(value=done * 100 / total))
        results = E.username_search(q, progress=prog)
        found = [r for r in results if r["status"] == "found"]
        uncertain = [r for r in results if r["status"] == "uncertain"]
        missing = [r for r in results if r["status"] not in ("found", "uncertain")]

        def build():
            self._clear()
            self._ins(f"Username footprint: ", "h"); self._ins(q + "\n\n", "h")
            self._ins(f"Confirmed on {len(found)} of {len(results)} sites"
                      f"   ·   {len(uncertain)} couldn't be verified.\n", "key")
            self._ins("Each hit below is verified (real 404/redirect/API "
                      "checks), not a bare HTTP 200.\n\n", "key")

            self._ins("CONFIRMED ACCOUNTS\n", "sub")
            if not found:
                self._ins("  (none)\n", "bad")
            for r in found:
                self._ins("  ✓ ", "good"); self._ins(f"{r['site']:14}", "good")
                self._link(r["url"], r["url"]); self._ins("\n")

            if uncertain:
                self._ins("\nCOULDN'T VERIFY (bot-walled / JS-only — check by "
                          "hand)\n", "sub")
                for r in uncertain:
                    self._ins(f"  ? {r['site']:14}", "warn")
                    self._ins("  ", "warn"); self._link(r["url"], r["url"])
                    self._ins(f"  ({r.get('note','')})\n", "warn")

            self._ins("\nNOT FOUND\n", "sub")
            for r in missing:
                self._ins(f"  ✗ {r['site']:14}", "bad")
                self._ins(f"  ({r.get('note','')})\n", "bad")
        self._render(build)

    def _r_dns(self, q):
        d = E.dns_lookup(q)

        def build():
            self._clear()
            self._ins("DNS records: ", "h"); self._ins(d["domain"] + "\n\n", "h")
            if not d["records"]:
                self._ins("No records found (or domain doesn't resolve).\n", "warn")
            for rtype, vals in d["records"].items():
                self._ins(f"{rtype}\n", "sub")
                for v in vals:
                    self._ins(f"   {v}\n", "val")
                self._ins("\n")
            if d.get("email_security"):
                self._ins("Email security posture\n", "sub")
                for k, v in d["email_security"].items():
                    self._ins(f"   {k:8}", "key")
                    self._ins(f"{v}\n", "good" if v != "missing" else "warn")
            for e in d["errors"]:
                self._ins(e + "\n", "warn")
        self._render(build)

    def _r_whois(self, q):
        w = E.whois_lookup(q)

        def build():
            self._clear()
            self._ins("WHOIS: ", "h"); self._ins(w["domain"] + "\n\n", "h")
            if w["error"]:
                self._ins(w["error"] + "\n", "warn")
            for k, v in w["data"].items():
                self._ins(f"  {k:18}", "key")
                self._ins(f"{v}\n", "val")
            if not w["data"] and not w["error"]:
                self._ins("No WHOIS data returned.\n", "warn")
        self._render(build)

    def _r_ip(self, q):
        i = E.ip_info(q)

        def build():
            self._clear()
            self._ins("IP / host intelligence: ", "h"); self._ins(q + "\n\n", "h")
            if i["error"] and not i["ip"]:
                self._ins(i["error"] + "\n", "warn"); return
            self._ins(f"  {'Resolved IP':18}", "key"); self._ins(f"{i['ip']}\n", "val")
            self._ins(f"  {'Reverse DNS':18}", "key")
            self._ins(f"{i['reverse_dns']}\n", "val")
            g = i["geo"]
            if g:
                rows = [("Country", g.get("country")), ("Region", g.get("regionName")),
                        ("City", g.get("city")), ("Postal", g.get("zip")),
                        ("ISP", g.get("isp")), ("Org", g.get("org")),
                        ("ASN", g.get("as")), ("Timezone", g.get("timezone")),
                        ("Mobile", g.get("mobile")), ("Proxy/VPN", g.get("proxy")),
                        ("Hosting", g.get("hosting"))]
                self._ins("\n")
                for k, v in rows:
                    if v not in (None, ""):
                        self._ins(f"  {k:18}", "key"); self._ins(f"{v}\n", "val")
                if g.get("lat") is not None:
                    self._ins(f"  {'Approx. location':18}", "key")
                    self._link(f"{g['lat']}, {g['lon']}  (open in Maps)",
                               f"https://www.google.com/maps?q={g['lat']},{g['lon']}")
                    self._ins("\n")
        self._render(build)

    def _r_email(self, q):
        e = E.email_recon(q)

        def build():
            self._clear()
            self._ins("Email recon: ", "h"); self._ins(q + "\n\n", "h")
            self._ins(f"  {'Valid format':18}", "key")
            self._ins(("yes" if e["valid_format"] else "no") + "\n",
                    "good" if e["valid_format"] else "warn")
            if e["domain"]:
                self._ins(f"  {'Domain':18}", "key"); self._ins(e["domain"] + "\n", "val")
            if e.get("local"):
                self._ins(f"  {'Username part':18}", "key")
                self._ins(e["local"] + "\n", "val")
            self._ins(f"  {'Disposable':18}", "key")
            self._ins(("YES — throwaway" if e.get("disposable") else "no") + "\n",
                      "warn" if e.get("disposable") else "good")
            self._ins(f"  {'Role account':18}", "key")
            self._ins(("yes — team inbox" if e.get("role_account") else "no") + "\n",
                      "warn" if e.get("role_account") else "good")
            if e["mx"]:
                self._ins(f"  {'Mail servers':18}", "key")
                self._ins(", ".join(e["mx"]) + "\n", "val")
            if e["gravatar"]:
                self._ins(f"  {'Gravatar':18}", "key")
                self._link("public avatar found", e["gravatar"]); self._ins("\n")
            if e["hibp_url"]:
                self._ins(f"  {'Breach check':18}", "key")
                self._link("Have I Been Pwned ↗", e["hibp_url"]); self._ins("\n")
            for n in e["notes"]:
                self._ins("  " + n + "\n", "warn")
        self._render(build)

    def _r_phone(self, q):
        p = E.phone_info(q)

        def build():
            self._clear()
            self._ins("Phone number: ", "h"); self._ins(q + "\n\n", "h")
            if p["error"]:
                self._ins("Couldn't parse that number — include the country "
                        "code, e.g. +1 202 456 1111.\n", "warn")
                return
            self._ins(f"  {'Valid number':18}", "key")
            self._ins(("yes" if p["valid"] else "no") + "\n",
                    "good" if p["valid"] else "warn")
            for k, v in p["data"].items():
                self._ins(f"  {k:18}", "key"); self._ins(f"{v}\n", "val")
        self._render(build)

    def _r_exif(self, q):
        x = E.exif_extract(q)

        def build():
            self._clear()
            self._ins("Image metadata: ", "h")
            self._ins(q.split('/')[-1].split('\\')[-1] + "\n\n", "h")
            if x["error"]:
                self._ins(x["error"] + "\n", "warn"); return
            for k, v in x["tags"].items():
                self._ins(f"  {k:22}", "key"); self._ins(f"{v}\n", "val")
            if x.get("notes"):
                self._ins("\n  " + x["notes"] + "\n", "warn")
            if x["gps"]:
                self._ins("\n  📍 GPS location found!\n", "sub")
                self._ins(f"  {'Coordinates':22}", "key")
                self._link(f"{x['gps']['lat']}, {x['gps']['lon']}  (open in Maps)",
                           x["gps"]["maps"]); self._ins("\n")
        self._render(build)

    def _r_headers(self, q):
        h = E.http_headers(q)

        def build():
            self._clear()
            self._ins("Website fingerprint: ", "h"); self._ins(q + "\n\n", "h")
            if h["error"]:
                self._ins(h["error"] + "\n", "warn"); return
            self._ins(f"  {'Status':16}", "key"); self._ins(f"{h['status']}\n", "val")
            self._ins(f"  {'Final URL':16}", "key")
            self._link(h["final_url"], h["final_url"]); self._ins("\n")
            if h["tech"]:
                self._ins(f"  {'Detected tech':16}", "key")
                self._ins(", ".join(h["tech"]) + "\n", "good")
            self._ins("\nKey headers\n", "sub")
            for k in ("Server", "X-Powered-By", "Content-Type", "Set-Cookie",
                      "Strict-Transport-Security", "Content-Security-Policy",
                      "X-Frame-Options"):
                if k in h["headers"]:
                    self._ins(f"  {k:26}", "key")
                    self._ins(f"{h['headers'][k][:90]}\n", "val")
            self._ins("\nrobots.txt\n", "sub")
            self._ins((h["robots"] or "(none)")[:800] + "\n", "val")
        self._render(build)

    def _r_dorks(self, q):
        dorks = E.dork_generator(q)

        def build():
            self._clear()
            self._ins("Search-dork generator: ", "h"); self._ins(q + "\n\n", "h")
            self._ins("Ready-made search queries that surface public info. Click "
                    "to run them:\n\n", "key")
            for d in dorks:
                self._ins(f"  {d['label']}\n", "sub")
                self._ins(f"    {d['query']}\n", "val")
                self._ins("    "); self._link("Google ↗", d["google"])
                self._ins("    "); self._link("Bing ↗", d["bing"]); self._ins("\n\n")
        self._render(build)

    # ---- new modules ----------------------------------------------------
    def _r_subs(self, q):
        s = E.crtsh_subdomains(q)

        def build():
            self._clear()
            self._ins("Subdomains: ", "h"); self._ins(q + "\n\n", "h")
            if s["error"] and not s["subdomains"]:
                self._ins(s["error"] + "\n", "warn"); return
            self._ins(f"{len(s['subdomains'])} found via {s['source']}\n\n", "good")
            for sub in s["subdomains"]:
                self._ins("  • "); self._link(sub, "https://" + sub); self._ins("\n")
        self._render(build)

    def _r_ports(self, q):
        d = E.shodan_internetdb(q)

        def build():
            self._clear()
            self._ins("Open ports & vulns: ", "h"); self._ins(q + "\n\n", "h")
            if d["error"]:
                self._ins(("  " + d["error"]) + "\n", "warn")
                if not d["ip"]:
                    return
            if d["ip"]:
                self._ins(f"  {'IP':14}", "key"); self._ins(d["ip"] + "\n", "val")
            if d["ports"]:
                self._ins(f"  {'Open ports':14}", "key")
                self._ins(", ".join(map(str, d["ports"])) + "\n", "good")
            if d["hostnames"]:
                self._ins(f"  {'Hostnames':14}", "key")
                self._ins(", ".join(d["hostnames"]) + "\n", "val")
            if d["cpes"]:
                self._ins(f"  {'Software':14}", "key")
                self._ins(", ".join(d["cpes"]) + "\n", "val")
            if d["vulns"]:
                self._ins("\n  ⚠ Known vulnerabilities (CVEs):\n", "sub")
                for v in d["vulns"]:
                    self._ins("    " + v + "  ", "warn")
                    self._link("details ↗",
                               f"https://nvd.nist.gov/vuln/detail/{v}")
                    self._ins("\n")
        self._render(build)

    def _r_revip(self, q):
        r = E.reverse_ip(q)

        def build():
            self._clear()
            self._ins("Reverse IP: ", "h"); self._ins(q + "\n\n", "h")
            if r["error"]:
                self._ins("  " + r["error"] + "\n", "warn"); return
            self._ins(f"{len(r['domains'])} domains share IP {r['ip']}\n\n", "good")
            for d in r["domains"]:
                self._ins("  • "); self._link(d, "https://" + d); self._ins("\n")
        self._render(build)

    def _r_github(self, q):
        g = E.github_user(q)

        def build():
            self._clear()
            self._ins("GitHub user: ", "h"); self._ins(q + "\n\n", "h")
            if g["error"]:
                self._ins("  " + g["error"] + "\n", "warn"); return
            for k, v in g["data"].items():
                self._ins(f"  {k:14}", "key")
                if k == "Profile" or (isinstance(v, str) and v.startswith("http")):
                    self._link(str(v), str(v)); self._ins("\n")
                else:
                    self._ins(f"{v}\n", "val")
        self._render(build)

    def _r_wayback(self, q):
        w = E.wayback_urls(q)

        def build():
            self._clear()
            self._ins("Archived URLs (Wayback): ", "h"); self._ins(q + "\n\n", "h")
            if w["error"]:
                self._ins("  " + w["error"] + "\n", "warn"); return
            self._ins(f"{len(w['urls'])} archived URLs\n\n", "good")
            for u in w["urls"]:
                self._ins("  "); self._link(u, u); self._ins("\n")
        self._render(build)

    def _r_ssl(self, q):
        s = E.ssl_cert(q)

        def build():
            self._clear()
            self._ins("SSL/TLS certificate: ", "h"); self._ins(q + "\n\n", "h")
            if s["error"]:
                self._ins("  " + s["error"] + "\n", "warn")
            for k, v in s["data"].items():
                self._ins(f"  {k:16}", "key"); self._ins(f"{v}\n", "val")
            if s["san"]:
                self._ins(f"\n  {len(s['san'])} names on this certificate "
                          "(extra subdomains!):\n", "sub")
                for n in s["san"]:
                    self._ins("    • "); self._link(n, "https://" + n)
                    self._ins("\n")
        self._render(build)

    def _r_webdeep(self, q):
        w = E.web_deep(q)

        def build():
            self._clear()
            self._ins("Web deep-dive: ", "h"); self._ins(q + "\n\n", "h")
            if w["error"]:
                self._ins("  " + w["error"] + "\n", "warn"); return
            self._ins(f"  Security-header grade:  ", "key")
            self._ins(f"{w['grade']}  ({len(w['headers_present'])}/6 present)\n",
                      "good" if w["grade"] in ("A", "A+", "B") else "warn")
            if w["headers_missing"]:
                self._ins("  Missing: " + ", ".join(w["headers_missing"]) + "\n",
                          "warn")
            self._ins("\n  Commonly-exposed paths checked:\n", "sub")
            if not w["paths"]:
                self._ins("    none of the sensitive paths responded — good.\n",
                          "good")
            for p in w["paths"]:
                tag = "warn" if p["status"] == 200 else "val"
                self._ins(f"    {p['status']}  ", tag)
                self._link(p["path"], w["base"] + p["path"])
                self._ins(f"   ({p['size']} bytes)\n", "key")
        self._render(build)

    def _r_asn(self, q):
        a = E.asn_info(q)

        def build():
            self._clear()
            self._ins("ASN / BGP info: ", "h"); self._ins(q + "\n\n", "h")
            if a["error"]:
                self._ins("  " + a["error"] + "\n", "warn"); return
            for k, v in a["data"].items():
                if v:
                    self._ins(f"  {k:14}", "key"); self._ins(f"{v}\n", "val")
            if a["prefixes"]:
                self._ins(f"\n  {len(a['prefixes'])} announced IP ranges:\n", "sub")
                for p in a["prefixes"]:
                    self._ins("    " + p + "\n", "val")
        self._render(build)

    def _r_urlscan(self, q):
        u = E.urlscan_search(q)

        def build():
            self._clear()
            self._ins("urlscan.io history: ", "h"); self._ins(q + "\n\n", "h")
            if u["error"]:
                self._ins("  " + u["error"] + "\n", "warn"); return
            self._ins(f"{len(u['results'])} public scans found\n\n", "good")
            for r in u["results"]:
                self._ins(f"  {r['time']}  ", "key")
                self._link(r["url"] or "(scan)", r["report"])
                self._ins(f"   [{r['ip'] or '?'}]\n", "key")
        self._render(build)

    # ---- the headline: streaming Auto-Recon -----------------------------
    def _r_auto(self, q):
        def prog(done, total):
            self.after(0, lambda: self.progress.config(value=done * 100 / total))
        # clear once on the UI thread, then stream events in
        self.after(0, self._clear)
        for ev in E.auto_recon(q, progress=prog):
            self.after(0, lambda e=ev: self._emit(e))
        self.after(0, self._done)
        self.after(0, lambda: self.status.config(text="Auto-Recon complete."))

    def _emit(self, ev):
        """Render one auto-recon event onto the output."""
        self.out.configure(state="normal")
        kind = ev[0]
        if kind == "h":
            self._ins(ev[1] + "\n", "h")
        elif kind == "sub":
            self._ins("\n" + ev[1] + "\n", "sub")
        elif kind == "kv":
            self._ins(f"   {ev[1]:16}", "key"); self._ins(f"{ev[2]}\n", "val")
        elif kind == "link":
            self._link(ev[1], ev[2]); self._ins("\n")
        elif kind == "line":
            self._ins(ev[1], ev[2] if len(ev) > 2 else "val")
        self.out.see("end")

    # ---- key-powered modules -------------------------------------------
    def _needs_key(self, build, service_id):
        """Render a friendly 'add a key' message instead of results."""
        name = E.KEY_SERVICES[service_id][0]
        what = E.KEY_SERVICES[service_id][2]

        def b():
            self._clear()
            self._ins(f"{name} lookup\n\n", "h")
            self._ins(f"🔑 This lookup needs a free {name} API key — it adds "
                      f"{what}.\n\n", "warn")
            self._ins("Click  🔑 API Keys  (top-right), paste your key, and "
                      "Save. It's free and the key doesn't expire.\n\n", "val")
            self._ins("Get one here: ", "key")
            self._link(E.KEY_SERVICES[service_id][1], E.KEY_SERVICES[service_id][1])
            self._ins("\n")
        return b

    def _kv_render(self, title, data, error, service_id, extra=None):
        """Generic renderer for the simple key modules."""
        if error == "needs_key":
            return self._needs_key(None, service_id)

        def build():
            self._clear()
            self._ins(title + "\n\n", "h")
            if error:
                self._ins("  " + str(error) + "\n", "warn"); return
            if extra:
                extra()
            for k, v in data.items():
                if v not in (None, ""):
                    self._ins(f"  {k:22}", "key"); self._ins(f"{v}\n", "val")
        return build

    def _r_vt(self, q):
        d = E.vt_lookup(q)
        if d["error"] == "needs_key":
            self._render(self._needs_key(None, "virustotal")); return

        def build():
            self._clear()
            self._ins(f"VirusTotal ({d['kind'] or '?'}): ", "h")
            self._ins(q + "\n\n", "h")
            if d["error"]:
                self._ins("  " + d["error"] + "\n", "warn"); return
            s = d["stats"]
            mal = s.get("malicious", 0) + s.get("suspicious", 0)
            self._ins(f"  {mal} security vendors flagged this  ",
                      "warn" if mal else "good")
            self._ins(f"(harmless: {s.get('harmless', 0)}, "
                      f"undetected: {s.get('undetected', 0)})\n\n", "key")
            for k, v in d["data"].items():
                self._ins(f"  {k:18}", "key"); self._ins(f"{str(v)[:300]}\n", "val")
        self._render(build)

    def _r_abuse(self, q):
        d = E.abuseipdb_lookup(q)
        self._render(self._kv_render(f"AbuseIPDB: {q}", d["data"], d["error"],
                                     "abuseipdb"))

    def _r_shodan(self, q):
        d = E.shodan_host(q)
        if d["error"] == "needs_key":
            self._render(self._needs_key(None, "shodan")); return

        def build():
            self._clear()
            self._ins("Shodan host: ", "h"); self._ins(q + "\n\n", "h")
            if d["error"]:
                self._ins("  " + d["error"] + "\n", "warn"); return
            self._ins(f"  {'Open ports':16}", "key")
            self._ins(", ".join(map(str, d["ports"])) + "\n", "good")
            for k, v in d["data"].items():
                self._ins(f"  {k:16}", "key"); self._ins(f"{v}\n", "val")
            if d["vulns"]:
                self._ins("\n  ⚠ Known CVEs:\n", "sub")
                for v in d["vulns"]:
                    self._ins("    " + v + "  ", "warn")
                    self._link("details ↗", f"https://nvd.nist.gov/vuln/detail/{v}")
                    self._ins("\n")
            if d["banners"]:
                self._ins("\n  Service banners:\n", "sub")
                for b in d["banners"]:
                    self._ins("    " + b + "\n", "val")
        self._render(build)

    def _r_ipinfo(self, q):
        d = E.ipinfo_lookup(q)
        self._render(self._kv_render(f"IPinfo: {q}", d["data"], d["error"],
                                     "ipinfo"))

    def _r_greynoise(self, q):
        d = E.greynoise_lookup(q)
        self._render(self._kv_render(f"GreyNoise: {q}", d["data"], d["error"],
                                     "greynoise"))

    def _r_hunter(self, q):
        d = E.hunter_domain(q)
        if d["error"] == "needs_key":
            self._render(self._needs_key(None, "hunter")); return

        def build():
            self._clear()
            self._ins("Hunter — domain emails: ", "h"); self._ins(q + "\n\n", "h")
            if d["error"]:
                self._ins("  " + d["error"] + "\n", "warn"); return
            if d["organization"]:
                self._ins(f"  Organization: {d['organization']}\n\n", "val")
            self._ins(f"{len(d['emails'])} emails found\n\n", "good")
            for e in d["emails"]:
                pos = f"  — {e['position']}" if e["position"] else ""
                self._ins(f"  {e['value']}  ", "val")
                self._ins(f"[{e['confidence']}% confidence{pos}]\n", "key")
        self._render(build)

    # ---- API-keys dialog ------------------------------------------------
    def _open_keys(self):
        win = tk.Toplevel(self)
        win.title("API Keys — all free, permanent")
        win.configure(bg=BG)
        win.geometry("640x520")
        win.transient(self)
        win.grab_set()
        tk.Label(win, text="🔑  Free API keys", bg=BG, fg=ACCENT,
                 font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=18,
                                                     pady=(16, 2))
        tk.Label(win, text="All of these have a permanent free tier. Paste a "
                           "key to unlock that source — leave blank to skip. "
                           "Keys are saved locally on this PC only.",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9), justify="left",
                 wraplength=600).pack(anchor="w", padx=18, pady=(0, 10))
        entries = {}
        cur = E.load_keys()
        body = tk.Frame(win, bg=BG)
        body.pack(fill="both", expand=True, padx=18)
        for sid, (name, url, what) in E.KEY_SERVICES.items():
            row = tk.Frame(body, bg=BG)
            row.pack(fill="x", pady=5)
            top = tk.Frame(row, bg=BG)
            top.pack(fill="x")
            tk.Label(top, text=name, bg=BG, fg=TEXT,
                     font=("Segoe UI Semibold", 10), width=12, anchor="w").pack(
                side="left")
            tk.Label(top, text="— " + what, bg=BG, fg=MUTED,
                     font=("Segoe UI", 8)).pack(side="left")
            link = tk.Label(top, text="get free key ↗", bg=BG, fg=LINK,
                            font=("Segoe UI", 8, "underline"), cursor="hand2")
            link.pack(side="right")
            link.bind("<Button-1>", lambda e, u=url: webbrowser.open(u))
            ent = tk.Entry(row, bg=PANEL, fg=TEXT, insertbackground=TEXT,
                           relief="flat", font=("Cascadia Mono", 10), show="•")
            ent.pack(fill="x", ipady=3, pady=(2, 0))
            ent.insert(0, cur.get(sid, ""))
            entries[sid] = ent

        bf = tk.Frame(win, bg=BG)
        bf.pack(fill="x", padx=18, pady=14)

        def save():
            E.set_keys({sid: e.get().strip() for sid, e in entries.items()})
            win.destroy()
            self.status.config(text="API keys saved. Key-powered lookups are "
                                    "now enabled where you added a key.")
        tk.Button(bf, text="Cancel", command=win.destroy, bg=PANEL, fg=TEXT,
                  relief="flat", padx=14, pady=6).pack(side="right", padx=(8, 0))
        tk.Button(bf, text="💾 Save keys", command=save, bg=ACCENT, fg="#0c1116",
                  relief="flat", font=("Segoe UI Semibold", 10), padx=18,
                  pady=6).pack(side="right")

    # ---- export ---------------------------------------------------------
    def export_report(self):
        if not self._report_buffer:
            return
        from tkinter import filedialog, messagebox
        import os, html, datetime
        path = filedialog.asksaveasfilename(
            title="Save OSINT report", defaultextension=".html",
            initialfile="osint_report.html",
            filetypes=[("HTML report", "*.html"), ("Text report", "*.txt")])
        if not path:
            return
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            if path.lower().endswith(".txt"):
                content = (self._report_title + "\n" + now + "\n" +
                           "=" * 60 + "\n\n")
                for text, tag, url in self._report_buffer:
                    if url:
                        content += f"{text}  <{url}>"
                    else:
                        content += text
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
            else:
                body = []
                for text, tag, url in self._report_buffer:
                    esc = html.escape(text).replace("\n", "<br>")
                    if url:
                        body.append(f'<a href="{html.escape(url)}">{esc}</a>')
                    else:
                        cls = {"h": "h", "sub": "sub", "key": "key",
                               "good": "good", "warn": "warn"}.get(tag, "")
                        body.append(f'<span class="{cls}">{esc}</span>')
                page = _HTML_TMPL.format(title=html.escape(self._report_title),
                                        now=now, body="".join(body))
                with open(path, "w", encoding="utf-8") as f:
                    f.write(page)
        except Exception as e:
            messagebox.showerror("Export failed", str(e))
            return
        self.status.config(text=f"Report saved to {path}")
        if messagebox.askyesno("Saved", f"Saved to:\n{path}\n\nOpen it now?"):
            try:
                os.startfile(path)
            except Exception:
                pass


_HTML_TMPL = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>{title}</title><style>
body{{background:#15181f;color:#e6e8ee;font-family:Consolas,monospace;
margin:0;padding:24px;line-height:1.5;}}
h1{{color:#5ad1c0;font-family:Segoe UI,sans-serif;}}
.meta{{color:#8b93a7;margin-bottom:18px;}}
.wrap{{white-space:pre-wrap;word-break:break-word;}}
.h{{color:#5ad1c0;font-weight:bold;font-size:16px;}}
.sub{{color:#5ad1c0;font-weight:bold;}}
.key{{color:#8b93a7;}}
.good{{color:#5fd68a;}}
.warn{{color:#ffcc66;}}
a{{color:#6fb4ff;}}
</style></head><body>
<h1>🛰 EZ-OSINT Report</h1>
<div class="meta">{title} &nbsp;•&nbsp; generated {now}</div>
<div class="wrap">{body}</div>
</body></html>"""


def main():
    OsintApp().mainloop()


if __name__ == "__main__":
    main()
