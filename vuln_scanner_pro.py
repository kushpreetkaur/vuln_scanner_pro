#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         VulnHawk PRO — Advanced Vulnerability Scanner            ║
║         With Professional PDF Report Generation                  ║
║         For Authorized/Ethical Security Testing ONLY             ║
╚══════════════════════════════════════════════════════════════════╝
Usage:
  python3 vuln_scanner_pro.py -u https://example.com -m all
  python3 vuln_scanner_pro.py -u https://example.com -m headers ssl files ports
"""

import argparse
import requests
import socket
import ssl
import json
import re
import sys
import time
import concurrent.futures
from urllib.parse import urljoin, urlparse
from datetime import datetime

# ── ReportLab imports ─────────────────────────────────────────────────────────
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable, PageBreak, KeepTogether)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.pdfgen import canvas as pdfcanvas

import urllib3
urllib3.disable_warnings()

# ── Colors for terminal ────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"; GREEN  = "\033[92m"; YELLOW = "\033[93m"
    CYAN   = "\033[96m"; BOLD   = "\033[1m";  RESET  = "\033[0m"
    PURPLE = "\033[95m"; WHITE  = "\033[97m"

BANNER = f"""
{C.RED}{C.BOLD}
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██╔══██╗██║    ██║██║ ██╔╝
 ██║   ██║██║   ██║██║     ██╔██╗ ██║███████║███████║██║ █╗ ██║█████╔╝
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██╔══██║██║███╗██║██╔═██╗
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝
{C.RESET}{C.CYAN}        VulnHawk PRO — Ethical Web Vulnerability Scanner + PDF Report{C.RESET}
{C.YELLOW}        ⚠  Only use on websites you own or have written permission  ⚠{C.RESET}
"""

# ── Data ───────────────────────────────────────────────────────────────────────
COMMON_SUBDOMAINS = [
    "www","mail","ftp","admin","portal","api","dev","test","staging",
    "app","secure","login","vpn","remote","shop","blog","support",
    "cdn","static","img","media","assets","docs","help","forum",
    "dashboard","panel","cpanel","webmail","mx","smtp","pop","imap",
    "m","mobile","beta","demo","sandbox","uat","qa","old","new",
    "backup","db","database","sql","mysql","phpmyadmin","git","svn",
    "jenkins","jira","wiki","intranet","internal","corp","crm",
    "api2","v1","v2","v3","graphql","rest","webhook","monitor",
    "status","health","metrics","logs","analytics","auth","sso"
]

SENSITIVE_PATHS = [
    "/.env","/.git/config","/.git/HEAD","/config.php","/wp-config.php",
    "/admin/","/administrator/","/phpmyadmin/","/phpinfo.php",
    "/robots.txt","/sitemap.xml","/.htaccess","/web.config",
    "/backup.sql","/backup.zip","/dump.sql","/database.sql",
    "/config.js","/config.json","/settings.json","/secrets.json",
    "/api/v1/users","/api/users","/api/admin","/api/config",
    "/server-status","/server-info","/.DS_Store","/error_log",
    "/wp-login.php","/xmlrpc.php","/wp-json/wp/v2/users",
    "/.svn/entries","/composer.json","/package.json",
    "/Dockerfile","/docker-compose.yml","/.travis.yml",
    "/crossdomain.xml","/swagger.json","/swagger-ui.html",
    "/openapi.json","/.well-known/security.txt","/elmah.axd",
    "/trace.axd","/.bash_history","/.ssh/id_rsa","/id_rsa.pub"
]

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><script>alert(1)</script>',
    "';alert('XSS')//",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
]

SQLI_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--",
    "\" OR 1=1--", "' AND 1=2--", "1' ORDER BY 1--",
    "1 UNION SELECT NULL--",
]

SQLI_ERRORS = [
    "sql syntax","mysql_fetch","ora-01","postgresql","sqlite_",
    "warning: mysql","unclosed quotation","you have an error in your sql",
    "supplied argument is not","invalid query","syntax error",
    "microsoft ole db","odbc drivers error","jdbc"
]

SECURITY_HEADERS = {
    "X-Frame-Options":           ("Clickjacking Protection",     "Medium"),
    "X-Content-Type-Options":    ("MIME Sniffing Protection",    "Low"),
    "Content-Security-Policy":   ("XSS / Injection Protection",  "High"),
    "Strict-Transport-Security": ("HTTPS Enforcement (HSTS)",    "High"),
    "X-XSS-Protection":          ("Browser XSS Filter",         "Low"),
    "Referrer-Policy":           ("Referrer Info Control",       "Low"),
    "Permissions-Policy":        ("Feature Policy Control",      "Low"),
}

COMMON_PORTS = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",
    3306:"MySQL",5432:"PostgreSQL",6379:"Redis",
    27017:"MongoDB",8080:"HTTP-Alt",8443:"HTTPS-Alt",
    9200:"Elasticsearch",3389:"RDP",2181:"Zookeeper",
    11211:"Memcached",5984:"CouchDB",9042:"Cassandra"
}

RISKY_PORTS = {23,6379,27017,11211,9200,5984,9042,2181,3306,5432}

RISK_INFO = {
    "Missing Security Header": {
        "X-Frame-Options":
            "Attacker can embed your site in an iframe on another domain. "
            "Users can be tricked into clicking hidden buttons (Clickjacking). "
            "FIX: Add header → X-Frame-Options: DENY",
        "Content-Security-Policy":
            "No policy means attacker can inject malicious scripts. "
            "Cross-Site Scripting (XSS) attacks become very easy. "
            "FIX: Add strict CSP policy in server config.",
        "Strict-Transport-Security":
            "Users can be downgraded from HTTPS to HTTP by attacker (MITM). "
            "Login credentials can be stolen over plain HTTP. "
            "FIX: Add header → Strict-Transport-Security: max-age=31536000",
        "X-Content-Type-Options":
            "Browser may misinterpret file types and execute malicious content. "
            "FIX: Add header → X-Content-Type-Options: nosniff",
    },
    "XSS (Reflected)":
        "Attacker sends a malicious link to victim. When victim clicks it, "
        "JavaScript runs in their browser. Attacker can steal session cookies, "
        "redirect to phishing pages, or take over the account. "
        "IMPACT: Account takeover, credential theft, malware distribution.",
    "SQL Injection":
        "Attacker can read, modify, or delete your entire database. "
        "User credentials, personal data, payment info — all exposed. "
        "Attacker may also gain OS-level command execution on database server. "
        "IMPACT: Complete data breach, database destruction, server takeover.",
    "Sensitive File Exposed":
        "Configuration files, database credentials, API keys, or source code "
        "are publicly accessible. Attacker gains direct access to secrets. "
        "IMPACT: Credential theft, full system compromise.",
    "SSL Certificate Issue":
        "Users cannot verify your site's identity. Man-in-the-Middle attacks "
        "become possible — attacker can intercept all traffic including passwords. "
        "IMPACT: Data interception, credential theft.",
    "No SSL/TLS":
        "All traffic between user and server is in plain text. "
        "Anyone on the same network can read passwords, session tokens, "
        "and personal data using simple packet sniffing tools. "
        "IMPACT: Complete traffic interception.",
    "Exposed Service":
        "Database or internal service is directly reachable from the internet. "
        "Brute force, default credentials, or known CVEs can give attacker "
        "direct access to your data without touching the web app. "
        "IMPACT: Direct database access, full server compromise.",
    "Directory Listing Enabled":
        "Attacker can browse your server directories like a file manager. "
        "Source code, config files, backups, and private uploads become visible. "
        "IMPACT: Information disclosure, path to deeper compromise.",
    "Server Version Disclosure":
        "Attacker knows exact server software and version. "
        "They can look up known CVEs for that exact version and exploit them. "
        "IMPACT: Targeted exploitation using known vulnerabilities.",
}


# ══════════════════════════════════════════════════════════════════════════════
class VulnScannerPro:
    def __init__(self, target, timeout=10, threads=25, verbose=False):
        self.target  = target.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({"User-Agent":
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "Chrome/120.0 Safari/537.36"})
        parsed      = urlparse(target)
        self.domain = parsed.netloc or parsed.path
        self.scheme = parsed.scheme or "https"
        self.start  = datetime.now()
        self.results = {
            "target": target, "domain": self.domain,
            "scan_start": str(self.start),
            "subdomains": [], "vulnerabilities": [],
            "sensitive_files": [], "headers_found": {},
            "headers_missing": [], "ssl_info": {},
            "open_ports": [], "risk_summary": {}
        }

    # ── Helpers ───────────────────────────────────────────────────────────────
    def log(self, msg, level="info"):
        icons = {
            "info": f"{C.CYAN}[*]{C.RESET}",
            "ok":   f"{C.GREEN}[+]{C.RESET}",
            "warn": f"{C.YELLOW}[!]{C.RESET}",
            "err":  f"{C.RED}[-]{C.RESET}",
            "vuln": f"{C.RED}{C.BOLD}[VULN]{C.RESET}",
        }
        print(f"  {icons.get(level,'[?]')} {msg}")

    def get(self, url, **kw):
        try:
            return self.session.get(url, timeout=self.timeout,
                                    allow_redirects=True, verify=False, **kw)
        except Exception:
            return None

    def section(self, title):
        print(f"\n{C.PURPLE}{'─'*60}{C.RESET}")
        print(f"  {C.BOLD}{C.WHITE}{title}{C.RESET}")
        print(f"{C.PURPLE}{'─'*60}{C.RESET}")

    # ── Modules ───────────────────────────────────────────────────────────────
    def check_headers(self):
        self.section("SECURITY HEADERS CHECK")
        r = self.get(self.target)
        if not r:
            self.log("Cannot reach target", "err"); return
        for h, (desc, sev) in SECURITY_HEADERS.items():
            val = r.headers.get(h)
            if val:
                self.log(f"Present  → {h}: {val[:55]}", "ok")
                self.results["headers_found"][h] = val
            else:
                self.log(f"MISSING  → {h} ({desc})", "warn")
                self.results["headers_missing"].append(h)
                self.results["vulnerabilities"].append({
                    "type": "Missing Security Header", "detail": h,
                    "severity": sev, "url": self.target,
                    "description": RISK_INFO["Missing Security Header"].get(
                        h, f"Header {h} is missing.")
                })
        server = r.headers.get("Server", "")
        if server and re.search(r"\d", server):
            self.log(f"Server version exposed: {server}", "warn")
            self.results["vulnerabilities"].append({
                "type": "Server Version Disclosure", "detail": server,
                "severity": "Low", "url": self.target,
                "description": RISK_INFO["Server Version Disclosure"]
            })

    def check_ssl(self):
        self.section("SSL / TLS CHECK")
        if "https" not in self.scheme:
            self.log("HTTP only — no encryption!", "vuln")
            self.results["vulnerabilities"].append({
                "type": "No SSL/TLS", "detail": "Site uses plain HTTP",
                "severity": "High", "url": self.target,
                "description": RISK_INFO["No SSL/TLS"]
            }); return
        try:
            ctx  = ssl.create_default_context()
            host = self.domain.split(":")[0]
            with socket.create_connection((host, 443), timeout=self.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    cert    = ss.getpeercert()
                    expires = cert.get("notAfter", "Unknown")
                    issuer  = dict(x[0] for x in cert.get("issuer", []))
                    subj    = dict(x[0] for x in cert.get("subject", []))
                    self.log(f"SSL Valid | Expires: {expires}", "ok")
                    self.log(f"Issuer: {issuer.get('organizationName','?')}", "ok")
                    self.results["ssl_info"] = {
                        "expires": expires,
                        "issuer":  issuer.get("organizationName","Unknown"),
                        "subject": subj.get("commonName","Unknown"),
                        "valid":   True
                    }
        except ssl.SSLCertVerificationError as e:
            self.log(f"SSL Error: {e}", "vuln")
            self.results["ssl_info"] = {"valid": False, "error": str(e)}
            self.results["vulnerabilities"].append({
                "type": "SSL Certificate Issue", "detail": str(e)[:80],
                "severity": "High", "url": self.target,
                "description": RISK_INFO["SSL Certificate Issue"]
            })
        except Exception as e:
            self.log(f"SSL check error: {e}", "err")

    def check_subdomains(self):
        self.section("SUBDOMAIN ENUMERATION")
        found = []
        base  = self.domain.split(":")[0]
        def probe(sub):
            fqdn = f"{sub}.{base}"
            url  = f"{self.scheme}://{fqdn}"
            r    = self.get(url)
            if r and r.status_code < 500:
                self.log(f"Found: {fqdn} [{r.status_code}]", "ok")
                found.append({"subdomain": fqdn, "status": r.status_code, "url": url})
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            ex.map(probe, COMMON_SUBDOMAINS)
        self.results["subdomains"] = found
        self.log(f"Total subdomains found: {len(found)}", "info")

    def check_sensitive_files(self):
        self.section("SENSITIVE FILES / PATHS")
        found = []
        def probe(path):
            url = urljoin(self.target + "/", path.lstrip("/"))
            r   = self.get(url)
            if r and r.status_code in [200, 301, 302, 403]:
                sev  = "Critical" if r.status_code == 200 else "Low"
                icon = "vuln" if r.status_code == 200 else "warn"
                self.log(f"[{r.status_code}] {sev:8} → {path}", icon)
                found.append({"path": path, "url": url,
                              "status": r.status_code, "severity": sev})
                if r.status_code == 200:
                    self.results["vulnerabilities"].append({
                        "type": "Sensitive File Exposed", "detail": path,
                        "severity": "Critical", "url": url,
                        "description": RISK_INFO["Sensitive File Exposed"]
                    })
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            ex.map(probe, SENSITIVE_PATHS)
        self.results["sensitive_files"] = found
        self.log(f"Total exposed paths: {len(found)}", "info")

    def check_xss(self):
        self.section("XSS DETECTION")
        parsed = urlparse(self.target)
        params = {}
        if parsed.query:
            for kv in parsed.query.split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    params[k] = v
        if not params:
            self.log("No URL parameters found — add ?param=value to URL for XSS test", "warn")
            return
        base = self.target.split("?")[0]
        for param in params:
            for payload in XSS_PAYLOADS:
                tp = dict(params); tp[param] = payload
                r  = self.get(base, params=tp)
                if r and payload in r.text:
                    self.log(f"XSS FOUND! param={param}", "vuln")
                    self.results["vulnerabilities"].append({
                        "type": "XSS (Reflected)", "detail": f"Parameter: {param}",
                        "severity": "High", "url": self.target,
                        "description": RISK_INFO["XSS (Reflected)"]
                    }); break

    def check_sqli(self):
        self.section("SQL INJECTION DETECTION")
        parsed = urlparse(self.target)
        params = {}
        if parsed.query:
            for kv in parsed.query.split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    params[k] = v
        if not params:
            self.log("No URL parameters found — add ?id=1 to URL for SQLi test", "warn")
            return
        base = self.target.split("?")[0]
        for param in params:
            for payload in SQLI_PAYLOADS:
                tp = dict(params); tp[param] = payload
                r  = self.get(base, params=tp)
                if r:
                    bl = r.text.lower()
                    for err in SQLI_ERRORS:
                        if err in bl:
                            self.log(f"SQLi FOUND! param={param} sig='{err}'", "vuln")
                            self.results["vulnerabilities"].append({
                                "type": "SQL Injection",
                                "detail": f"Parameter: {param} | Error: {err}",
                                "severity": "Critical", "url": self.target,
                                "description": RISK_INFO["SQL Injection"]
                            }); return

    def check_ports(self):
        self.section("PORT SCAN")
        host      = self.domain.split(":")[0]
        open_ports = []
        def probe(port):
            try:
                with socket.create_connection((host, port), timeout=2):
                    svc = COMMON_PORTS.get(port, "Unknown")
                    self.log(f"OPEN  port {port:5d}/tcp  [{svc}]", "ok")
                    open_ports.append({"port": port, "service": svc})
                    if port in RISKY_PORTS:
                        self.log(f"⚠  {svc} on port {port} is publicly exposed!", "vuln")
                        self.results["vulnerabilities"].append({
                            "type": "Exposed Service",
                            "detail": f"Port {port} ({svc}) open to internet",
                            "severity": "High", "url": f"{host}:{port}",
                            "description": RISK_INFO["Exposed Service"]
                        })
            except Exception:
                pass
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            ex.map(probe, COMMON_PORTS.keys())
        self.results["open_ports"] = open_ports
        self.log(f"Open ports found: {len(open_ports)}", "info")

    def check_directory_listing(self):
        self.section("DIRECTORY LISTING CHECK")
        dirs = ["/images/","/uploads/","/files/","/backup/",
                "/assets/","/static/","/media/","/temp/","/tmp/"]
        for d in dirs:
            url = urljoin(self.target + "/", d.lstrip("/"))
            r   = self.get(url)
            if r and r.status_code == 200:
                if any(x in r.text.lower() for x in ["index of","parent directory","last modified"]):
                    self.log(f"Directory listing ENABLED: {url}", "vuln")
                    self.results["vulnerabilities"].append({
                        "type": "Directory Listing Enabled",
                        "detail": url, "severity": "Medium", "url": url,
                        "description": RISK_INFO["Directory Listing Enabled"]
                    })

    # ── Risk Summary ──────────────────────────────────────────────────────────
    def build_risk_summary(self):
        counts = {"Critical":0,"High":0,"Medium":0,"Low":0}
        for v in self.results["vulnerabilities"]:
            sev = v.get("severity","Low")
            counts[sev] = counts.get(sev, 0) + 1
        self.results["risk_summary"] = counts

        total = sum(counts.values())
        score = (counts["Critical"]*10 + counts["High"]*7 +
                 counts["Medium"]*4  + counts["Low"]*1)
        if   score == 0:         rating = ("SECURE",   colors.HexColor("#27ae60"))
        elif score <= 10:        rating = ("LOW RISK", colors.HexColor("#f39c12"))
        elif score <= 25:        rating = ("MEDIUM",   colors.HexColor("#e67e22"))
        elif score <= 50:        rating = ("HIGH RISK",colors.HexColor("#c0392b"))
        else:                    rating = ("CRITICAL", colors.HexColor("#7b241c"))
        self.results["risk_rating"] = rating[0]
        self.results["risk_score"]  = score
        self.results["risk_color"]  = rating[1]
        return counts, score, rating

    # ══════════════════════════════════════════════════════════════════════════
    # PDF REPORT GENERATOR
    # ══════════════════════════════════════════════════════════════════════════
    def generate_pdf_report(self, filename=None):
        if not filename:
            safe     = re.sub(r"[^\w]", "_", self.domain)
            filename = f"VulnReport_{safe}_{int(time.time())}.pdf"

        counts, score, rating = self.build_risk_summary()

        # ── Styles ────────────────────────────────────────────────────────────
        styles = getSampleStyleSheet()
        RED    = colors.HexColor("#c0392b")
        DARK   = colors.HexColor("#1a1a2e")
        ACCENT = colors.HexColor("#16213e")
        ORANGE = colors.HexColor("#e67e22")
        GREEN  = colors.HexColor("#27ae60")
        LGRAY  = colors.HexColor("#f4f6f8")
        MGRAY  = colors.HexColor("#bdc3c7")

        SEV_COLORS = {
            "Critical": colors.HexColor("#7b241c"),
            "High":     colors.HexColor("#c0392b"),
            "Medium":   colors.HexColor("#e67e22"),
            "Low":      colors.HexColor("#f1c40f"),
        }
        SEV_BG = {
            "Critical": colors.HexColor("#fadbd8"),
            "High":     colors.HexColor("#fdecea"),
            "Medium":   colors.HexColor("#fef5e7"),
            "Low":      colors.HexColor("#fefde7"),
        }

        def sty(name, **kw):
            s = ParagraphStyle(name, parent=styles["Normal"], **kw)
            return s

        cover_title  = sty("ct", fontSize=28, textColor=colors.white,
                           fontName="Helvetica-Bold", alignment=TA_CENTER,
                           spaceAfter=6)
        cover_sub    = sty("cs", fontSize=13, textColor=colors.HexColor("#bdc3c7"),
                           fontName="Helvetica", alignment=TA_CENTER, spaceAfter=4)
        cover_domain = sty("cd", fontSize=16, textColor=colors.HexColor("#3498db"),
                           fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=2)
        sec_head     = sty("sh", fontSize=14, textColor=DARK,
                           fontName="Helvetica-Bold", spaceAfter=8, spaceBefore=14,
                           borderPad=4)
        body_txt     = sty("bt", fontSize=9, textColor=colors.HexColor("#2c3e50"),
                           fontName="Helvetica", leading=14, spaceAfter=4)
        vuln_title   = sty("vt", fontSize=10, textColor=colors.white,
                           fontName="Helvetica-Bold")
        small_gray   = sty("sg", fontSize=8, textColor=colors.HexColor("#7f8c8d"),
                           fontName="Helvetica")
        desc_txt     = sty("dt", fontSize=8.5, textColor=colors.HexColor("#2c3e50"),
                           fontName="Helvetica", leading=13)
        fix_txt      = sty("ft", fontSize=8.5, textColor=colors.HexColor("#1a6b3c"),
                           fontName="Helvetica-Bold")

        story = []

        # ══ PAGE 1 — COVER ════════════════════════════════════════════════════
        def cover_bg(canvas, doc):
            canvas.saveState()
            w, h = A4
            # Dark background
            canvas.setFillColor(DARK)
            canvas.rect(0, 0, w, h, fill=1, stroke=0)
            # Top accent bar
            canvas.setFillColor(RED)
            canvas.rect(0, h-8*mm, w, 8*mm, fill=1, stroke=0)
            # Bottom bar
            canvas.setFillColor(ACCENT)
            canvas.rect(0, 0, w, 22*mm, fill=1, stroke=0)
            # Watermark text
            canvas.setFillColor(colors.HexColor("#ffffff10"))
            canvas.setFont("Helvetica-Bold", 90)
            canvas.saveState()
            canvas.translate(w/2, h/2)
            canvas.rotate(35)
            canvas.drawCentredString(0, 0, "CONFIDENTIAL")
            canvas.restoreState()
            canvas.restoreState()

        def normal_bg(canvas, doc):
            canvas.saveState()
            w, h = A4
            canvas.setFillColor(colors.HexColor("#f8f9fa"))
            canvas.rect(0, 0, w, h, fill=1, stroke=0)
            # Top stripe
            canvas.setFillColor(DARK)
            canvas.rect(0, h-14*mm, w, 14*mm, fill=1, stroke=0)
            canvas.setFont("Helvetica-Bold", 9)
            canvas.setFillColor(colors.white)
            canvas.drawString(15*mm, h-9*mm, "VulnHawk PRO — Security Assessment Report")
            canvas.drawRightString(w-15*mm, h-9*mm, self.domain)
            # Bottom
            canvas.setFillColor(DARK)
            canvas.rect(0, 0, w, 10*mm, fill=1, stroke=0)
            canvas.setFillColor(MGRAY)
            canvas.setFont("Helvetica", 8)
            canvas.drawCentredString(w/2, 3.5*mm,
                f"CONFIDENTIAL — For Authorized Security Review Only  |  Page {doc.page}")
            canvas.restoreState()

        # Cover page
        doc_cover = SimpleDocTemplate(
            "/tmp/_cover.pdf", pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=3*cm, bottomMargin=2*cm
        )
        cover_story = []
        cover_story.append(Spacer(1, 3.5*cm))
        cover_story.append(Paragraph("🔒 SECURITY ASSESSMENT", cover_sub))
        cover_story.append(Spacer(1, 0.3*cm))
        cover_story.append(Paragraph("VULNERABILITY REPORT", cover_title))
        cover_story.append(Spacer(1, 0.5*cm))
        cover_story.append(HRFlowable(width="80%", thickness=2,
                                       color=RED, hAlign="CENTER"))
        cover_story.append(Spacer(1, 0.5*cm))
        cover_story.append(Paragraph(self.target, cover_domain))
        cover_story.append(Spacer(1, 0.3*cm))
        cover_story.append(Paragraph(
            f"Scan Date: {self.start.strftime('%B %d, %Y  %H:%M')}",
            sty("d2", fontSize=10, textColor=MGRAY,
                fontName="Helvetica", alignment=TA_CENTER)))
        cover_story.append(Spacer(1, 1.5*cm))

        # Risk rating box
        rc = self.results.get("risk_color", RED)
        risk_table = Table([[
            Paragraph("OVERALL RISK RATING", sty("rl",fontSize=9,
                      textColor=colors.white, fontName="Helvetica",
                      alignment=TA_CENTER)),
            Paragraph(rating[0], sty("rv", fontSize=22,
                      textColor=colors.white, fontName="Helvetica-Bold",
                      alignment=TA_CENTER)),
            Paragraph(f"Score: {score}", sty("rs", fontSize=11,
                      textColor=colors.white, fontName="Helvetica",
                      alignment=TA_CENTER)),
        ]], colWidths=[5*cm, 7*cm, 5*cm])
        risk_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,-1), rc),
            ("ROWBACKGROUNDS",(0,0),(-1,-1),[rc]),
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
            ("TOPPADDING",(0,0),(-1,-1),14),
            ("BOTTOMPADDING",(0,0),(-1,-1),14),
            ("ROUNDEDCORNERS",[6]),
        ]))
        cover_story.append(risk_table)
        cover_story.append(Spacer(1, 1.2*cm))

        # Summary counts
        sum_data = [["CRITICAL","HIGH","MEDIUM","LOW"]]
        sum_data.append([
            str(counts.get("Critical",0)), str(counts.get("High",0)),
            str(counts.get("Medium",0)),   str(counts.get("Low",0))
        ])
        sum_tbl = Table(sum_data, colWidths=[4.25*cm]*4)
        sum_tbl.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(0,0),colors.HexColor("#7b241c")),
            ("BACKGROUND",(1,0),(1,0),colors.HexColor("#c0392b")),
            ("BACKGROUND",(2,0),(2,0),colors.HexColor("#e67e22")),
            ("BACKGROUND",(3,0),(3,0),colors.HexColor("#f39c12")),
            ("BACKGROUND",(0,1),(0,1),colors.HexColor("#fadbd8")),
            ("BACKGROUND",(1,1),(1,1),colors.HexColor("#fdecea")),
            ("BACKGROUND",(2,1),(2,1),colors.HexColor("#fef5e7")),
            ("BACKGROUND",(3,1),(3,1),colors.HexColor("#fefde7")),
            ("TEXTCOLOR",(0,0),(3,0),colors.white),
            ("TEXTCOLOR",(0,1),(0,1),colors.HexColor("#7b241c")),
            ("TEXTCOLOR",(1,1),(1,1),colors.HexColor("#c0392b")),
            ("TEXTCOLOR",(2,1),(2,1),colors.HexColor("#e67e22")),
            ("TEXTCOLOR",(3,1),(3,1),colors.HexColor("#b7950b")),
            ("FONTNAME",(0,0),(-1,-1),"Helvetica-Bold"),
            ("FONTSIZE",(0,0),(3,0),9),
            ("FONTSIZE",(0,1),(3,1),24),
            ("ALIGN",(0,0),(-1,-1),"CENTER"),
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
            ("TOPPADDING",(0,0),(-1,0),8),
            ("BOTTOMPADDING",(0,0),(-1,0),8),
            ("TOPPADDING",(0,1),(-1,1),10),
            ("BOTTOMPADDING",(0,1),(-1,1),10),
            ("GRID",(0,0),(-1,-1),0.5,colors.white),
        ]))
        cover_story.append(sum_tbl)
        cover_story.append(Spacer(1, 1*cm))
        cover_story.append(Paragraph(
            "⚠  This report is CONFIDENTIAL. Intended for authorized security "
            "review only. Unauthorized use or distribution is prohibited.",
            sty("disc", fontSize=8, textColor=MGRAY,
                fontName="Helvetica", alignment=TA_CENTER)))
        doc_cover.build(cover_story, onFirstPage=cover_bg, onLaterPages=cover_bg)

        # ══ MAIN REPORT ═══════════════════════════════════════════════════════
        doc_main = SimpleDocTemplate(
            "/tmp/_main.pdf", pagesize=A4,
            leftMargin=1.8*cm, rightMargin=1.8*cm,
            topMargin=2.2*cm, bottomMargin=1.8*cm
        )
        story = []

        # ── Section: Executive Summary ─────────────────────────────────────
        story.append(Paragraph("1.  Executive Summary", sec_head))
        story.append(HRFlowable(width="100%", thickness=1.5,
                                 color=RED, spaceAfter=8))
        total_v = len(self.results["vulnerabilities"])
        story.append(Paragraph(
            f"A security assessment was performed on <b>{self.domain}</b> on "
            f"{self.start.strftime('%B %d, %Y')}. The scan identified "
            f"<b>{total_v} vulnerability/vulnerabilities</b> across "
            f"{counts.get('Critical',0)} critical, {counts.get('High',0)} high, "
            f"{counts.get('Medium',0)} medium, and {counts.get('Low',0)} low severity levels. "
            f"The overall risk rating is <b>{rating[0]}</b> with a risk score of <b>{score}</b>.",
            body_txt))
        story.append(Spacer(1, 0.3*cm))

        # Scan info table
        scan_info = [
            ["Target URL",    self.target],
            ["Domain",        self.domain],
            ["Scan Date",     self.start.strftime("%Y-%m-%d %H:%M:%S")],
            ["Total Issues",  str(total_v)],
            ["Subdomains Found", str(len(self.results["subdomains"]))],
            ["Open Ports",    str(len(self.results["open_ports"]))],
            ["Exposed Files", str(len([f for f in self.results["sensitive_files"]
                                        if f["status"]==200]))],
        ]
        si_tbl = Table(scan_info, colWidths=[5*cm, 12.6*cm])
        si_tbl.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR",(0,0),(0,-1),colors.white),
            ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
            ("FONTNAME",(1,0),(1,-1),"Helvetica"),
            ("FONTSIZE",(0,0),(-1,-1),8.5),
            ("ROWBACKGROUNDS",(1,0),(1,-1),
             [colors.white, colors.HexColor("#f4f6f8")]),
            ("TOPPADDING",(0,0),(-1,-1),6),
            ("BOTTOMPADDING",(0,0),(-1,-1),6),
            ("LEFTPADDING",(0,0),(-1,-1),8),
            ("GRID",(0,0),(-1,-1),0.5,MGRAY),
        ]))
        story.append(si_tbl)
        story.append(Spacer(1, 0.5*cm))

        # ── Section: Vulnerabilities ───────────────────────────────────────
        story.append(Paragraph("2.  Vulnerabilities Detected", sec_head))
        story.append(HRFlowable(width="100%", thickness=1.5,
                                 color=RED, spaceAfter=8))

        sev_order = {"Critical":0,"High":1,"Medium":2,"Low":3}
        sorted_vulns = sorted(self.results["vulnerabilities"],
                              key=lambda x: sev_order.get(x.get("severity","Low"),3))

        if not sorted_vulns:
            story.append(Paragraph(
                "✅  No significant vulnerabilities were detected during this scan.",
                sty("nv", fontSize=10, textColor=GREEN, fontName="Helvetica-Bold")))
        else:
            for i, v in enumerate(sorted_vulns, 1):
                sev   = v.get("severity","Low")
                sc    = SEV_COLORS.get(sev, colors.gray)
                sbg   = SEV_BG.get(sev, LGRAY)
                vtype = v.get("type","Unknown")
                vdet  = v.get("detail","")
                vurl  = v.get("url","")
                vdesc = v.get("description","")

                # Vulnerability card
                card_data = [[
                    Paragraph(f"#{i:02d}  {vtype}", vuln_title),
                    Paragraph(sev, sty("sv", fontSize=10, textColor=colors.white,
                                       fontName="Helvetica-Bold", alignment=TA_RIGHT))
                ]]
                card_hdr = Table(card_data, colWidths=[12.5*cm, 5.1*cm])
                card_hdr.setStyle(TableStyle([
                    ("BACKGROUND",(0,0),(-1,-1), sc),
                    ("TOPPADDING",(0,0),(-1,-1),7),
                    ("BOTTOMPADDING",(0,0),(-1,-1),7),
                    ("LEFTPADDING",(0,0),(0,-1),10),
                    ("RIGHTPADDING",(-1,0),(-1,-1),10),
                    ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                ]))

                body_rows = []
                if vdet:
                    body_rows.append([
                        Paragraph("<b>Detail:</b>", desc_txt),
                        Paragraph(vdet[:120], desc_txt)
                    ])
                if vurl:
                    body_rows.append([
                        Paragraph("<b>URL:</b>", desc_txt),
                        Paragraph(vurl[:100], desc_txt)
                    ])
                if vdesc:
                    body_rows.append([
                        Paragraph("<b>Risk:</b>", desc_txt),
                        Paragraph(vdesc[:400], desc_txt)
                    ])

                if body_rows:
                    body_tbl = Table(body_rows, colWidths=[2.5*cm, 15.1*cm])
                    body_tbl.setStyle(TableStyle([
                        ("BACKGROUND",(0,0),(-1,-1), sbg),
                        ("TOPPADDING",(0,0),(-1,-1),5),
                        ("BOTTOMPADDING",(0,0),(-1,-1),5),
                        ("LEFTPADDING",(0,0),(0,-1),10),
                        ("LEFTPADDING",(1,0),(1,-1),4),
                        ("VALIGN",(0,0),(-1,-1),"TOP"),
                        ("LINEBELOW",(0,0),(-1,-2),0.3,MGRAY),
                    ]))
                    story.append(KeepTogether([card_hdr, body_tbl]))
                else:
                    story.append(card_hdr)
                story.append(Spacer(1, 0.3*cm))

        # ── Section: Subdomains ────────────────────────────────────────────
        story.append(PageBreak())
        story.append(Paragraph("3.  Subdomain Enumeration", sec_head))
        story.append(HRFlowable(width="100%", thickness=1.5,
                                 color=RED, spaceAfter=8))
        subs = self.results["subdomains"]
        if subs:
            tdata = [["#", "Subdomain", "Status Code", "URL"]]
            for i, s in enumerate(subs, 1):
                sc = s["status"]
                tdata.append([str(i), s["subdomain"], str(sc), s["url"][:55]])
            tbl = Table(tdata, colWidths=[1*cm, 5.5*cm, 3*cm, 8.1*cm])
            tbl.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),DARK),
                ("TEXTCOLOR",(0,0),(-1,0),colors.white),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
                ("FONTSIZE",(0,0),(-1,-1),8),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, LGRAY]),
                ("GRID",(0,0),(-1,-1),0.4,MGRAY),
                ("TOPPADDING",(0,0),(-1,-1),5),
                ("BOTTOMPADDING",(0,0),(-1,-1),5),
                ("LEFTPADDING",(0,0),(-1,-1),6),
                ("ALIGN",(2,0),(2,-1),"CENTER"),
            ]))
            story.append(tbl)
        else:
            story.append(Paragraph("No subdomains found.", body_txt))

        # ── Section: Open Ports ────────────────────────────────────────────
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph("4.  Open Ports", sec_head))
        story.append(HRFlowable(width="100%", thickness=1.5,
                                 color=RED, spaceAfter=8))
        ports = self.results["open_ports"]
        if ports:
            pdata = [["Port", "Service", "Risk Level", "Notes"]]
            for p in ports:
                risk  = "HIGH" if p["port"] in RISKY_PORTS else "Low"
                note  = ("Publicly exposed! Should be firewalled."
                         if p["port"] in RISKY_PORTS else "Standard")
                pdata.append([str(p["port"]), p["service"], risk, note])
            ptbl = Table(pdata, colWidths=[2.5*cm, 4*cm, 3.5*cm, 7.6*cm])
            ptbl.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),DARK),
                ("TEXTCOLOR",(0,0),(-1,0),colors.white),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
                ("FONTSIZE",(0,0),(-1,-1),8.5),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, LGRAY]),
                ("GRID",(0,0),(-1,-1),0.4,MGRAY),
                ("TOPPADDING",(0,0),(-1,-1),5),
                ("BOTTOMPADDING",(0,0),(-1,-1),5),
                ("LEFTPADDING",(0,0),(-1,-1),7),
                ("ALIGN",(0,0),(0,-1),"CENTER"),
            ]))
            story.append(ptbl)
        else:
            story.append(Paragraph("No common ports found open.", body_txt))

        # ── Section: Sensitive Files ───────────────────────────────────────
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph("5.  Sensitive Files & Paths", sec_head))
        story.append(HRFlowable(width="100%", thickness=1.5,
                                 color=RED, spaceAfter=8))
        files = self.results["sensitive_files"]
        if files:
            fdata = [["Status", "Severity", "Path", "URL"]]
            for f in files:
                fdata.append([str(f["status"]), f["severity"],
                              f["path"][:30], f["url"][:55]])
            ftbl = Table(fdata, colWidths=[2*cm, 2.5*cm, 5*cm, 8.1*cm])
            ftbl.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),DARK),
                ("TEXTCOLOR",(0,0),(-1,0),colors.white),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
                ("FONTSIZE",(0,0),(-1,-1),7.5),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, LGRAY]),
                ("GRID",(0,0),(-1,-1),0.4,MGRAY),
                ("TOPPADDING",(0,0),(-1,-1),4),
                ("BOTTOMPADDING",(0,0),(-1,-1),4),
                ("LEFTPADDING",(0,0),(-1,-1),6),
                ("ALIGN",(0,0),(0,-1),"CENTER"),
                ("ALIGN",(1,0),(1,-1),"CENTER"),
            ]))
            story.append(ftbl)
        else:
            story.append(Paragraph("No sensitive files were found exposed.", body_txt))

        # ── Section: Recommendations ───────────────────────────────────────
        story.append(PageBreak())
        story.append(Paragraph("6.  Recommendations", sec_head))
        story.append(HRFlowable(width="100%", thickness=1.5,
                                 color=RED, spaceAfter=8))

        recs = [
            ("Add Security Headers",
             "Add X-Frame-Options, Content-Security-Policy, HSTS, and other "
             "security headers in your web server config (nginx/apache)."),
            ("Enable HTTPS / Fix SSL",
             "Use a valid SSL certificate (Let's Encrypt is free). "
             "Redirect all HTTP traffic to HTTPS."),
            ("Block Sensitive Files",
             "Restrict access to .env, .git, config files via .htaccess or "
             "nginx rules. Never deploy with debug files on production."),
            ("Firewall Database Ports",
             "Never expose ports 3306 (MySQL), 6379 (Redis), 27017 (MongoDB) "
             "to the public internet. Use firewall rules."),
            ("Patch & Update Regularly",
             "Keep web server, CMS, plugins, and frameworks up to date. "
             "Subscribe to CVE alerts for your stack."),
            ("Input Validation",
             "Validate and sanitize ALL user inputs. Use parameterized queries "
             "to prevent SQL injection. Use CSP to prevent XSS."),
            ("Disable Directory Listing",
             "Add 'Options -Indexes' in Apache or 'autoindex off' in nginx."),
            ("Penetration Test Regularly",
             "Run security scans quarterly. Consider professional pentest "
             "for critical applications."),
        ]
        for i, (title, body) in enumerate(recs, 1):
            story.append(Paragraph(
                f"<b>{i}. {title}</b>", sty("rh", fontSize=10,
                textColor=DARK, fontName="Helvetica-Bold", spaceAfter=2)))
            story.append(Paragraph(body, desc_txt))
            story.append(Spacer(1, 0.2*cm))

        # ── Disclaimer ─────────────────────────────────────────────────────
        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width="100%", thickness=1, color=MGRAY))
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(
            "DISCLAIMER: This report was generated by VulnHawk PRO for authorized "
            "security assessment purposes only. Unauthorized use of this tool or "
            "report against systems you do not own or have explicit permission to "
            "test is illegal and may result in criminal prosecution.",
            sty("dis", fontSize=7.5, textColor=colors.HexColor("#95a5a6"),
                fontName="Helvetica", alignment=TA_CENTER)))

        doc_main.build(story, onFirstPage=normal_bg, onLaterPages=normal_bg)

        # ── Merge cover + main ────────────────────────────────────────────
        from pypdf import PdfWriter, PdfReader
        writer = PdfWriter()
        for pf in ["/tmp/_cover.pdf", "/tmp/_main.pdf"]:
            rdr = PdfReader(pf)
            for page in rdr.pages:
                writer.add_page(page)
        with open(filename, "wb") as f:
            writer.write(f)

        self.log(f"PDF Report saved → {filename}", "ok")
        return filename

    # ══════════════════════════════════════════════════════════════════════════
    # TERMINAL REPORT
    # ══════════════════════════════════════════════════════════════════════════
    def print_terminal_report(self):
        counts, score, rating = self.build_risk_summary()
        rc = {"SECURE":C.GREEN,"LOW RISK":C.YELLOW,"MEDIUM":C.YELLOW,
              "HIGH RISK":C.RED,"CRITICAL":C.RED}.get(rating[0], C.RED)
        print(f"\n{C.BOLD}{C.CYAN}{'═'*65}{C.RESET}")
        print(f"  {C.BOLD}SCAN COMPLETE — {self.target}{C.RESET}")
        print(f"  Risk Rating : {rc}{C.BOLD}{rating[0]}{C.RESET}  (Score: {score})")
        print(f"  Critical:{counts['Critical']}  High:{counts['High']}  "
              f"Medium:{counts['Medium']}  Low:{counts['Low']}")
        print(f"{C.CYAN}{'═'*65}{C.RESET}\n")

        sev_order = {"Critical":0,"High":1,"Medium":2,"Low":3}
        for v in sorted(self.results["vulnerabilities"],
                        key=lambda x: sev_order.get(x.get("severity","Low"),3)):
            sev = v.get("severity","?")
            col = {"Critical":C.RED,"High":C.RED,
                   "Medium":C.YELLOW,"Low":C.CYAN}.get(sev, C.RESET)
            print(f"  {col}[{sev:8}]{C.RESET} {C.BOLD}{v['type']}{C.RESET}")
            if v.get("detail"):
                print(f"            Detail : {v['detail'][:80]}")

    # ══════════════════════════════════════════════════════════════════════════
    # MAIN RUN
    # ══════════════════════════════════════════════════════════════════════════
    def run(self, modules):
        print(BANNER)
        self.log(f"Target  : {self.target}", "info")
        self.log(f"Modules : {', '.join(modules)}", "info")
        self.log(f"Started : {self.start.strftime('%Y-%m-%d %H:%M:%S')}\n", "info")

        mapping = {
            "headers":    self.check_headers,
            "ssl":        self.check_ssl,
            "subdomains": self.check_subdomains,
            "files":      self.check_sensitive_files,
            "xss":        self.check_xss,
            "sqli":       self.check_sqli,
            "ports":      self.check_ports,
            "dirlist":    self.check_directory_listing,
        }
        all_mods = list(mapping.keys())
        run_list = all_mods if "all" in modules else modules

        for mod in run_list:
            fn = mapping.get(mod)
            if fn:
                fn()
            else:
                self.log(f"Unknown module: {mod}", "warn")

        self.print_terminal_report()
        pdf = self.generate_pdf_report()
        json_file = pdf.replace(".pdf", ".json")
        with open(json_file, "w") as f:
            data = dict(self.results)
            data.pop("risk_color", None)
            json.dump(data, f, indent=2)
        self.log(f"JSON data saved → {json_file}", "ok")
        return pdf


# ── CLI ────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="VulnHawk PRO — Vulnerability Scanner + PDF Report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 vuln_scanner_pro.py -u https://example.com
  python3 vuln_scanner_pro.py -u https://example.com -m all
  python3 vuln_scanner_pro.py -u https://example.com -m headers ssl files ports
  python3 vuln_scanner_pro.py -u "https://example.com?id=1" -m xss sqli
  python3 vuln_scanner_pro.py -u https://example.com -m all --threads 50

Modules: headers  ssl  subdomains  files  xss  sqli  ports  dirlist  all
        """
    )
    parser.add_argument("-u","--url",     required=True,  help="Target URL")
    parser.add_argument("-m","--modules", nargs="+",
        default=["headers","ssl","files","ports","dirlist"],
        help="Modules to run")
    parser.add_argument("-t","--timeout", type=int, default=10)
    parser.add_argument("--threads",      type=int, default=25)
    parser.add_argument("-o","--output",  help="PDF output filename")
    args    = parser.parse_args()
    scanner = VulnScannerPro(args.url, args.timeout, args.threads)
    scanner.run(args.modules)

if __name__ == "__main__":
    main()
