#!/usr/bin/env python3
"""
safe_vapt.py - Scope-guarded, non-destructive web security assessment helper.

Implements the automated parts of the "Authorized Web VAPT Workflow" template:
  Module 1  Scope & connectivity   (allowlist check, DNS, HTTP status/headers)
  Module 2  TLS & security headers (HTTPS enforcement, HSTS, CSP, XCTO, cookies, TLS)
  Module 3  Safe discovery         (header/body fingerprinting, robots/sitemap/security.txt,
                                    optional fixed-list exposure checks)
  Module 4  Evidence & reporting   (engagement tree, findings JSON/Markdown, SHA-256 sums)

What this tool will NEVER do: fuzz, brute-force, send attack payloads, follow links
outside the scope file, use POST/PUT/DELETE, or save response bodies as evidence.
Only GET requests (and TLS handshakes) are sent. Manual verification (Burp, IDOR,
XSS, injection, business logic) is intentionally NOT automated.

Use ONLY against assets covered by written authorization.
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import datetime as dt
import hashlib
import ipaddress
import json
import logging
import math
import re
import secrets
import shutil
import socket
import ssl
import sys
import textwrap
import time
import warnings
from pathlib import Path
from urllib.parse import urljoin, urlsplit

try:
    import dns.exception
    import dns.resolver
    import dns.version
    import requests
    import urllib3
    from requests.structures import CaseInsensitiveDict
except ImportError as exc:  # pragma: no cover
    sys.exit(f"Missing dependency: {exc.name}. Install with:  pip install requests dnspython")

__version__ = "1.2.0"
TOOL_NAME = "safe_vapt"
EXIT_OK, EXIT_USAGE, EXIT_SCOPE, EXIT_RUNTIME = 0, 1, 2, 3
DEFAULT_PORTS = (80, 443)  # ports allowed for a scope entry that names no port
log = logging.getLogger(TOOL_NAME)


class ScopeError(Exception):
    """Target or redirect is outside the approved scope (or scope file invalid)."""


class BudgetExceeded(Exception):
    """The --max-requests ceiling was reached."""


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Scope allowlist
# --------------------------------------------------------------------------- #
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$")


@dataclasses.dataclass(frozen=True)
class ScopeEntry:
    kind: str  # host | wildcard | ip | network
    value: str
    ports: tuple

    def matches(self, host: str, port: int) -> bool:
        if port not in self.ports:
            return False
        if self.kind == "host":
            return host == self.value
        if self.kind == "wildcard":  # *.example.com matches subdomains only
            return host.endswith("." + self.value)
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        if self.kind == "ip":
            return ip == ipaddress.ip_address(self.value)
        return ip in ipaddress.ip_network(self.value, strict=False)


def parse_scope_line(line: str) -> ScopeEntry | None:
    line = line.split("#", 1)[0].strip()
    if not line:
        return None
    port = None
    try:  # bare IP or CIDR
        net = ipaddress.ip_network(line, strict=False)
        kind = "ip" if net.num_addresses == 1 else "network"
        value = str(net.network_address) if kind == "ip" else str(net)
        return ScopeEntry(kind, value, DEFAULT_PORTS)
    except ValueError:
        pass
    if "://" in line:
        parts = urlsplit(line)
        host, port = parts.hostname or "", parts.port
    else:
        host = line
        m = re.match(r"^(.*):(\d{1,5})$", line)
        if m:
            host, port = m.group(1), int(m.group(2))
    host = host.strip().lower().rstrip(".")
    ports = (port,) if port else DEFAULT_PORTS
    try:
        return ScopeEntry("ip", str(ipaddress.ip_address(host)), ports)
    except ValueError:
        pass
    kind = "host"
    if host.startswith("*."):
        kind, host = "wildcard", host[2:]
    if not HOST_RE.match(host):
        raise ScopeError(f"Invalid scope entry: {line!r}")
    return ScopeEntry(kind, host, ports)


class Scope:
    def __init__(self, entries, path: Path):
        self.entries, self.path = entries, path
        self.sha256 = hashlib.sha256(path.read_bytes()).hexdigest()

    @classmethod
    def load(cls, path: Path) -> "Scope":
        if not path.is_file():
            raise ScopeError(f"Scope file not found: {path}")
        entries = [e for e in (parse_scope_line(l) for l in path.read_text(encoding="utf-8").splitlines()) if e]
        if not entries:
            raise ScopeError(f"Scope file {path} contains no entries.")
        return cls(entries, path)

    def allows(self, host: str, port: int) -> bool:
        host = (host or "").lower().rstrip(".")
        return any(e.matches(host, port) for e in self.entries)

    def require(self, host: str, port: int) -> None:
        if not self.allows(host, port):
            raise ScopeError(f"{host}:{port} is NOT in the scope file. Nothing was sent.")


@dataclasses.dataclass
class Target:
    scheme: str
    host: str
    port: int

    @property
    def origin(self) -> str:
        return make_origin(self.scheme, self.host, self.port)


def make_origin(scheme: str, host: str, port: int) -> str:
    h = f"[{host}]" if ":" in host else host
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{h}" + ("" if port == default else f":{port}")


def parse_target(raw: str) -> Target:
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise ScopeError("Only http:// and https:// targets are supported.")
    if parts.username or parts.password:
        raise ScopeError("Credentials inside the target URL are not allowed.")
    if not parts.hostname:
        raise ScopeError("Could not read a hostname from --target.")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        raise ScopeError("Invalid port in --target.")
    host = parts.hostname.lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ScopeError("Invalid hostname in --target.")
    return Target(parts.scheme, host, port)


# --------------------------------------------------------------------------- #
# Rate limiting / request budget
# --------------------------------------------------------------------------- #
class Throttle:
    """Enforces a minimum delay between ALL outbound requests and a hard ceiling."""

    def __init__(self, delay: float, max_requests: int):
        self.delay, self.max, self.count, self._last = delay, max_requests, 0, 0.0

    def wait(self) -> None:
        if self.count >= self.max:
            raise BudgetExceeded(f"Request ceiling reached ({self.max}).")
        gap = time.monotonic() - self._last
        if self._last and gap < self.delay:
            time.sleep(self.delay - gap)
        self._last = time.monotonic()
        self.count += 1


# --------------------------------------------------------------------------- #
# Safe HTTP client (GET only, manual redirects, every hop scope-checked)
# --------------------------------------------------------------------------- #
SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "x-api-key", "x-auth-token"}


def redact_set_cookie(value: str) -> str:
    first, _, rest = value.partition(";")
    return f"{first.split('=', 1)[0]}=[REDACTED]" + (";" + rest if rest else "")


@dataclasses.dataclass
class FetchResult:
    url: str
    final_url: str = ""
    status: int | None = None
    headers: CaseInsensitiveDict = dataclasses.field(default_factory=CaseInsensitiveDict)
    set_cookies: list = dataclasses.field(default_factory=list)
    body: bytes = b""
    chain: list = dataclasses.field(default_factory=list)  # (url, status, location)
    error: str = ""
    tls_error: bool = False
    blocked: str = ""  # reason a redirect hop was refused
    verified: bool = True

    @property
    def ok(self) -> bool:
        return self.status is not None


class SafeHttp:
    MAX_BODY, MAX_REDIRECTS = 262_144, 5

    def __init__(self, scope: Scope, throttle: Throttle, timeout: float, ua: str):
        self.scope, self.throttle, self.timeout = scope, throttle, timeout
        self.session = requests.Session()
        self.session.trust_env = False  # ignore proxy env vars (no accidental routing)
        self.session.headers.update({"User-Agent": ua, "Accept": "*/*"})

    def get(self, url: str, follow: bool = True, verify: bool = True) -> FetchResult:
        res, current = FetchResult(url=url, verified=verify), url
        for _ in range(self.MAX_REDIRECTS + 1):
            p = urlsplit(current)
            port = p.port or (443 if p.scheme == "https" else 80)
            if p.scheme not in ("http", "https") or not self.scope.allows(p.hostname or "", port):
                res.blocked = f"Redirect to out-of-scope location refused: {current}"
                log.warning(res.blocked)
                return res
            self.throttle.wait()
            try:
                resp = self.session.get(current, allow_redirects=False, timeout=self.timeout,
                                        stream=True, verify=verify)
            except requests.exceptions.SSLError as exc:
                res.error, res.tls_error = f"TLS error: {exc}", True
                return res
            except requests.exceptions.RequestException as exc:
                res.error = f"{type(exc).__name__}: {exc}"
                return res
            try:
                res.body = resp.raw.read(self.MAX_BODY, decode_content=True) or b""
                res.status, res.headers = resp.status_code, CaseInsensitiveDict(resp.headers)
                try:
                    res.set_cookies = list(resp.raw.headers.getlist("Set-Cookie"))
                except Exception:
                    res.set_cookies = [resp.headers["Set-Cookie"]] if "Set-Cookie" in resp.headers else []
                res.final_url = current
                loc = resp.headers.get("Location", "")
                res.chain.append((current, resp.status_code, loc))
            except Exception as exc:  # truncated/odd response
                res.error = f"Read error: {exc}"
                return res
            finally:
                resp.close()
            if follow and 300 <= res.status < 400 and loc:
                current = urljoin(current, loc)
                continue
            return res
        res.error = "Too many redirects"
        return res


# --------------------------------------------------------------------------- #
# Findings + evidence
# --------------------------------------------------------------------------- #
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


@dataclasses.dataclass
class Finding:
    id: str
    title: str
    severity: str  # PRELIMINARY - analyst must score with CVSS after manual validation
    status: str    # Confirmed | Likely / needs client validation | Not tested | Informational
    asset: str
    description: str
    impact: str
    recommendation: str
    reproduction: list
    references: list
    evidence_files: list
    cvss: str = "Not scored (score verified issue manually)"
    retest: str = "Not retested"
    cvss_score: float = 0.0
    cvss_vector: str = ""
    link: str = ""
    port_service: str = ""
    remarks: str = ""
    poc_image: str = ""


class Engagement:
    SUBDIRS = ("scope", "recon", "scans", "evidence", "notes", "reports")

    def __init__(self, root: Path, run_id: str):
        self.root, self.run_id = root, run_id
        for d in self.SUBDIRS:
            (root / d).mkdir(parents=True, exist_ok=True)

    def write(self, sub: str, name: str, content) -> str:
        path = self.root / sub / name
        text = content if isinstance(content, str) else json.dumps(content, indent=2, default=str)
        path.write_text(text, encoding="utf-8")
        return f"{sub}/{name}"

    def save_http_evidence(self, label: str, res: FetchResult) -> str:
        lines = [f"# Captured {now_iso()}", f"# Request: GET {res.url} (no body stored)",
                 f"# Final URL: {res.final_url or res.url}", f"# Status: {res.status}",
                 f"# Redirect chain: {res.chain}", ""]
        for k, v in res.headers.items():
            if k.lower() == "set-cookie":
                continue
            lines.append(f"{k}: {'[REDACTED]' if k.lower() in SENSITIVE_HEADERS else v}")
        lines += [f"Set-Cookie: {redact_set_cookie(c)}" for c in res.set_cookies]
        return self.write("evidence", f"http_{label}_{self.run_id}_headers_redacted.txt", "\n".join(lines) + "\n")


class Registry:
    def __init__(self, eng: Engagement, ctx_meta: dict):
        self.eng, self.meta, self.items = eng, ctx_meta, []

    def add(self, title, severity, status, asset, description, impact, recommendation,
            reproduction=None, references=None, evidence_files=None, observed=None) -> Finding:
        fid = f"VAPT-{len(self.items) + 1:03d}"
        slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:40]
        record = {"finding_id": fid, "timestamp": now_iso(), "tester": self.meta["tester"],
                  "target": self.meta["target"], "tool": f"{TOOL_NAME} {__version__}",
                  "title": title, "observed": observed or {}}
        ev = list(evidence_files or [])
        ev.append(self.eng.write("evidence", f"{fid}_{self.eng.run_id}_{slug}.json", record))
        f = Finding(fid, title, severity, status, asset, description, impact, recommendation,
                    reproduction or [], references or [], ev)
        enrich_finding(f)  # CVSS (preliminary), article link, port/service, remarks
        self.items.append(f)
        log.info("[%s] %s | %s | %s", fid, f.severity, status, title)
        return f


@dataclasses.dataclass
class Ctx:
    args: argparse.Namespace
    target: Target
    scope: Scope
    throttle: Throttle
    http: SafeHttp
    eng: Engagement
    reg: Registry
    primary: FetchResult | None = None
    dns: dict = dataclasses.field(default_factory=dict)
    reachable: bool = False


# --------------------------------------------------------------------------- #
# Module 1 - scope & connectivity
# --------------------------------------------------------------------------- #
def resolve_dns(host: str, timeout: float) -> dict:
    out = {"host": host, "A": [], "AAAA": [], "CNAME": [], "errors": {}}
    try:
        ipaddress.ip_address(host)
        out["A" if ":" not in host else "AAAA"].append(host)
        return out
    except ValueError:
        pass
    resolver = dns.resolver.Resolver()
    resolver.lifetime = resolver.timeout = timeout
    for rtype in ("A", "AAAA", "CNAME"):
        try:
            out[rtype] = sorted(str(r) for r in resolver.resolve(host, rtype))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except (dns.exception.DNSException, OSError) as exc:
            out["errors"][rtype] = f"{type(exc).__name__}: {exc}"
    return out


def module1_scope_connectivity(ctx: Ctx) -> None:
    log.info("== Module 1: scope & connectivity ==")
    t = ctx.target
    ctx.dns = resolve_dns(t.host, ctx.args.timeout)
    ctx.eng.write("recon", f"dns_{ctx.eng.run_id}.json", ctx.dns)
    log.info("DNS A=%s AAAA=%s CNAME=%s", ctx.dns["A"], ctx.dns["AAAA"], ctx.dns["CNAME"])
    if not (ctx.dns["A"] or ctx.dns["AAAA"]):
        log.warning("No DNS records found by dnspython; will still try the system resolver.")
    for ip in ctx.dns["A"] + ctx.dns["AAAA"]:
        addr = ipaddress.ip_address(ip)
        if (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved) \
                and not ctx.args.allow_private_ips:
            raise ScopeError(f"{t.host} resolves to non-public address {ip}. If this internal asset is "
                             "approved, re-run with --allow-private-ips. Stopped before any HTTP traffic.")

    res = ctx.http.get(t.origin + "/", follow=True)
    if res.tls_error:
        log.warning("Certificate validation failed; retrying without verification to read headers only.")
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        res = ctx.http.get(t.origin + "/", follow=True, verify=False)
    ctx.primary = res
    if res.blocked:
        ctx.reg.add("Redirect to out-of-scope host (not followed)", "Informational", "Confirmed", t.origin,
                    f"The target redirected outside the approved scope. {res.blocked}. The tool refused to follow it.",
                    "None directly; confirm with the client whether the destination should be added to scope.",
                    "Ask the client to approve additional assets in writing before testing them.",
                    [f"curl -sS -I {t.origin}/"], [], [ctx.eng.save_http_evidence("primary", res)],
                    {"chain": res.chain})
    if not res.ok:
        log.error("Target unreachable: %s", res.error or res.blocked)
        ctx.reg.add("Target not reachable - checks not performed", "Informational", "Not tested", t.origin,
                    f"No HTTP response was received. Detail: {res.error or res.blocked}",
                    "No assessment possible.", "Verify the URL, test window, source-IP allowlisting and network path.",
                    [f"curl -sS -I --max-time 15 {t.origin}/"], [], [], {"error": res.error})
        return
    ctx.reachable = True
    path = ctx.eng.save_http_evidence("primary", res)
    ctx.eng.write("recon", f"http-headers_{ctx.eng.run_id}.txt", Path(ctx.eng.root / path).read_text())
    log.info("HTTP %s from %s (redirect hops: %d)", res.status, res.final_url, len(res.chain) - 1)


# --------------------------------------------------------------------------- #
# Module 2 - TLS & security headers
# --------------------------------------------------------------------------- #
def tls_inspect(host: str, port: int, timeout: float) -> dict:
    out = {"host": host, "port": port}

    def handshake(verify: bool):
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                return t.version(), t.cipher(), t.getpeercert()

    try:
        ver, cipher, cert = handshake(True)
        out.update(verified=True, protocol=ver, cipher=cipher and cipher[0])
        if cert:
            out["subject"] = dict(x[0] for x in cert.get("subject", ()))
            out["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
            out["san"] = [v for _, v in cert.get("subjectAltName", ())]
            out["not_after"] = cert.get("notAfter")
            if out["not_after"]:
                out["days_to_expiry"] = int((ssl.cert_time_to_seconds(out["not_after"]) - time.time()) // 86400)
    except ssl.SSLCertVerificationError as exc:
        out.update(verified=False, verify_error=str(getattr(exc, "verify_message", "") or exc))
        try:
            ver, cipher, _ = handshake(False)
            out.update(protocol=ver, cipher=cipher and cipher[0])
        except (ssl.SSLError, OSError) as exc2:
            out["error"] = str(exc2)
    except (ssl.SSLError, OSError) as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def probe_legacy_protocol(host: str, port: int, version, timeout: float) -> str:
    """accepted | rejected_or_untestable | untestable | error"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ctx.minimum_version = ctx.maximum_version = version
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    except (ValueError, ssl.SSLError):
        return "untestable"
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                return "accepted"
    except ssl.SSLError:
        return "rejected_or_untestable"
    except OSError:
        return "error"


def analyze_headers(res: FetchResult, https: bool) -> list:
    """Return (title, severity, status, description, impact, recommendation, observed) tuples."""
    h, out = res.headers, []
    rec_ref = "https://owasp.org/www-project-secure-headers/"
    if https:
        hsts = h.get("Strict-Transport-Security")
        if not hsts:
            out.append(("HSTS header missing", "Low", "Confirmed",
                        "The HTTPS response has no Strict-Transport-Security header.",
                        "Users may be exposed to SSL-stripping on first or downgraded visits.",
                        "Send Strict-Transport-Security: max-age=31536000; includeSubDomains (after validating subdomains).",
                        {"header": None}))
        else:
            m = re.search(r"max-age=(\d+)", hsts, re.I)
            if not m or int(m.group(1)) < 15_552_000:
                out.append(("HSTS max-age is short or invalid", "Low", "Confirmed",
                            f"Strict-Transport-Security is '{hsts}'.", "Reduced downgrade protection.",
                            "Use max-age of at least 15552000 (180 days); 31536000 recommended.", {"header": hsts}))
    csp = h.get("Content-Security-Policy")
    if not csp:
        out.append(("Content-Security-Policy header missing", "Low", "Confirmed",
                    "No CSP header was returned on this response (context-dependent: review per page/app).",
                    "Reduced defence-in-depth against XSS and data injection.",
                    "Define a restrictive CSP and deploy in report-only mode first.", {"header": None}))
    else:
        weak = [w for w in ("'unsafe-inline'", "'unsafe-eval'") if w in csp]
        if re.search(r"(script-src|default-src)[^;]*(\s\*|\sdata:|\shttps?:(\s|;|$))", csp):
            weak.append("wildcard/broad source in script-src or default-src")
        if weak:
            out.append(("Weak Content-Security-Policy", "Low", "Likely / needs client validation",
                        f"The CSP contains permissive directives: {', '.join(weak)}.",
                        "May allow script injection to bypass CSP protections.",
                        "Remove unsafe-inline/unsafe-eval; use nonces or hashes and explicit hosts.", {"csp": csp}))
    if (h.get("X-Content-Type-Options") or "").lower() != "nosniff":
        out.append(("X-Content-Type-Options: nosniff missing", "Low", "Confirmed",
                    "The header is absent or not set to 'nosniff'.", "Browsers may MIME-sniff responses.",
                    "Add X-Content-Type-Options: nosniff.", {"header": h.get("X-Content-Type-Options")}))
    if not h.get("X-Frame-Options") and "frame-ancestors" not in (csp or ""):
        out.append(("Clickjacking protection missing", "Low", "Confirmed",
                    "Neither X-Frame-Options nor CSP frame-ancestors was returned.",
                    "Pages may be framed by third-party sites (UI redressing).",
                    "Add CSP frame-ancestors 'self' (or X-Frame-Options: SAMEORIGIN).", {}))
    for name in ("Referrer-Policy", "Permissions-Policy"):
        if not h.get(name):
            out.append((f"{name} header not set", "Informational", "Informational",
                        f"{name} is absent. A missing header is not automatically a vulnerability.",
                        "Minor privacy / feature-control hardening opportunity.",
                        f"Consider setting an appropriate {name}.", {"header": None}))
    srv = h.get("Server", "")
    if re.search(r"\d+\.\d+", srv) or h.get("X-Powered-By") or h.get("X-AspNet-Version"):
        out.append(("Server technology/version disclosure", "Low", "Confirmed",
                    f"Headers reveal software details (Server='{srv}', X-Powered-By='{h.get('X-Powered-By', '')}').",
                    "Helps attackers match known vulnerabilities to the stack.",
                    "Suppress or genericise version banners; also verify the disclosed versions are supported.",
                    {"Server": srv, "X-Powered-By": h.get("X-Powered-By")}))
    if h.get("Access-Control-Allow-Origin") == "*":
        out.append(("CORS allows any origin (wildcard)", "Informational", "Likely / needs client validation",
                    "Access-Control-Allow-Origin is '*'. Impact depends on whether the response is sensitive.",
                    "Cross-origin reads of non-credentialed responses.", "Restrict origins for sensitive endpoints.",
                    {"header": "*"}))
    missing = {"Secure": [], "HttpOnly": [], "SameSite": []}
    for raw in res.set_cookies:
        name, attrs = raw.split("=", 1)[0].strip(), raw.lower()
        if https and not re.search(r";\s*secure", attrs):
            missing["Secure"].append(name)
        if not re.search(r";\s*httponly", attrs):
            missing["HttpOnly"].append(name)
        if not re.search(r";\s*samesite=", attrs):
            missing["SameSite"].append(name)
    for attr, names in missing.items():
        if names:
            out.append((f"Cookie(s) without {attr} attribute", "Low", "Confirmed",
                        f"Cookies set without {attr}: {', '.join(sorted(set(names)))} (values never stored).",
                        "Weaker protection of cookies against interception, script access or CSRF (context-dependent).",
                        f"Set the {attr} attribute on session/authentication cookies.", {"cookies": sorted(set(names))}))
    return out


def module2_tls_headers(ctx: Ctx) -> None:
    log.info("== Module 2: TLS & security headers ==")
    t, scans = ctx.target, {}
    https_port = t.port if t.scheme == "https" else 443
    can_https = ctx.scope.allows(t.host, https_port)

    # --- HTTPS enforcement (single plain-HTTP request, redirect NOT followed) ---
    http_port = t.port if t.scheme == "http" else 80
    if ctx.scope.allows(t.host, http_port):
        plain = ctx.http.get(make_origin("http", t.host, http_port) + "/", follow=False)
        scans["http_enforcement"] = {"status": plain.status, "chain": plain.chain, "error": plain.error}
        if plain.ok:
            loc = urljoin(plain.url, plain.chain[-1][2]) if plain.chain and plain.chain[-1][2] else ""
            if 300 <= plain.status < 400 and loc.startswith("https://"):
                log.info("HTTP redirects to HTTPS (%s -> %s)", plain.status, loc)
            else:
                ctx.reg.add("HTTP is not redirected to HTTPS", "Medium", "Confirmed", plain.url,
                            f"Plain HTTP returned status {plain.status} and no redirect to HTTPS.",
                            "Traffic (including cookies) may be exposed on unencrypted connections.",
                            "Redirect all HTTP requests to HTTPS (301) and enable HSTS.",
                            [f"curl -sS -I {plain.url}"], ["OWASP WSTG-CRYP-03"],
                            [ctx.eng.save_http_evidence("http_plain", plain)], {"status": plain.status, "location": loc})
        else:
            log.info("Plain HTTP not reachable on port %s (%s)", http_port, plain.error)
    else:
        log.info("Plain-HTTP check skipped: port %s not in scope for this host.", http_port)

    # --- TLS ---
    if can_https and not ctx.args.skip_tls:
        ctx.throttle.wait()
        info = tls_inspect(t.host, https_port, ctx.args.timeout)
        probes = {}
        for label, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
            ctx.throttle.wait()
            probes[label] = probe_legacy_protocol(t.host, https_port, ver, ctx.args.timeout)
        info["legacy_protocol_probes"] = probes
        scans["tls"] = info
        log.info("TLS: protocol=%s cipher=%s verified=%s", info.get("protocol"), info.get("cipher"), info.get("verified"))
        asset = f"{t.host}:{https_port}"
        if info.get("verified") is False:
            ctx.reg.add("TLS certificate failed validation", "Medium", "Confirmed", asset,
                        f"Validation error: {info.get('verify_error')}", "Users see warnings; MITM is easier.",
                        "Install a valid, trusted certificate chain matching the hostname.",
                        [f"openssl s_client -connect {t.host}:{https_port} -servername {t.host} </dev/null"],
                        ["OWASP WSTG-CRYP-01"], [], info)
        days = info.get("days_to_expiry")
        if days is not None and days < 30:
            ctx.reg.add("TLS certificate expired" if days < 0 else "TLS certificate expires soon",
                        "Medium" if days < 0 else "Low", "Confirmed", asset,
                        f"Certificate notAfter={info.get('not_after')} ({days} days).",
                        "Service disruption / trust warnings.", "Renew and automate certificate renewal.", [], [], [], info)
        for label, state in probes.items():
            if state == "accepted":
                ctx.reg.add(f"Deprecated protocol {label} accepted", "Medium", "Confirmed", asset,
                            f"The server completed a {label} handshake.", "Legacy protocols have known weaknesses.",
                            "Disable TLS 1.0/1.1; allow TLS 1.2+ only.",
                            [f"openssl s_client -connect {t.host}:{https_port} -tls1 </dev/null"],
                            ["RFC 8996"], [], {"probe": state})
        log.info("Legacy probes %s (a 'rejected_or_untestable' result is NOT proof; confirm with testssl.sh)", probes)
    elif not can_https:
        log.info("TLS checks skipped: HTTPS port %s not in scope.", https_port)

    # --- Security headers on the HTTPS (or primary) response ---
    res = ctx.primary
    if not (res and res.final_url.startswith("https://")) and can_https:
        alt = ctx.http.get(make_origin("https", t.host, https_port) + "/", follow=True)
        if alt.tls_error:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            alt = ctx.http.get(make_origin("https", t.host, https_port) + "/", follow=True, verify=False)
        if alt.ok:
            res = alt
    if res and res.ok:
        https = res.final_url.startswith("https://")
        ev = ctx.eng.save_http_evidence("security_headers", res)
        for title, sev, status, desc, impact, rec, obs in analyze_headers(res, https):
            ctx.reg.add(title, sev, status, res.final_url, desc, impact, rec,
                        [f"curl -sS -I {res.final_url}"], ["OWASP WSTG-CONF-07", "OWASP Secure Headers Project"],
                        [ev], obs)
    ctx.eng.write("scans", f"tls-and-http-summary_{ctx.eng.run_id}.json", scans)


# --------------------------------------------------------------------------- #
# Module 3 - safe discovery / fingerprinting
# --------------------------------------------------------------------------- #
COOKIE_HINTS = {"PHPSESSID": "PHP", "JSESSIONID": "Java servlet container", "ASP.NET_SessionId": "ASP.NET",
                "laravel_session": "Laravel", "csrftoken": "Django", "ci_session": "CodeIgniter",
                "connect.sid": "Node.js/Express"}
BODY_HINTS = [(rb"wp-content|wp-includes", "WordPress"), (rb"/sites/default/files", "Drupal"),
              (rb"/media/jui/|Joomla!", "Joomla")]

# Fixed, reviewed list. Status + signature only; bodies are never written to disk.
EXPOSURE_CHECKS = {
    "/.git/HEAD": lambda b, c: b.startswith(b"ref:"),
    "/.env": lambda b, c: bool(re.search(rb"(?m)^[A-Z][A-Z0-9_]{2,}=", b)),
    "/.svn/entries": lambda b, c: "html" not in c and len(b) > 0,
    "/.DS_Store": lambda b, c: b.startswith(b"\x00\x00\x00\x01Bud1"),
    "/server-status": lambda b, c: b"Apache Server Status" in b,
    "/phpinfo.php": lambda b, c: b"phpinfo()" in b or b"PHP Version" in b,
    "/web.config": lambda b, c: b"<configuration" in b,
}


def fingerprint(res: FetchResult) -> dict:
    fp = {"headers": {k: res.headers.get(k) for k in
                      ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator", "Via") if res.headers.get(k)},
          "cookie_hints": [], "body_hints": []}
    for raw in res.set_cookies:
        name = raw.split("=", 1)[0].strip()
        if name in COOKIE_HINTS:
            fp["cookie_hints"].append(f"{name} -> {COOKIE_HINTS[name]}")
    for pat, label in BODY_HINTS:
        if re.search(pat, res.body):
            fp["body_hints"].append(label)
    m = re.search(rb"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']{1,100})", res.body, re.I)
    if m:
        fp["body_hints"].append("generator: " + m.group(1).decode("utf-8", "replace"))
    return fp


def module3_discovery(ctx: Ctx) -> None:
    log.info("== Module 3: safe discovery ==")
    t, scans = ctx.target, {}
    scans["fingerprint"] = fp = fingerprint(ctx.primary)
    if any(fp.values()):
        ctx.reg.add("Technologies identified (input for manual test planning)", "Informational", "Informational",
                    t.origin, f"Fingerprint: {json.dumps(fp)}", "Informs which manual test cases apply.",
                    "No action required; verify disclosed components are patched and supported.",
                    [f"curl -sS -I {t.origin}/"], ["OWASP WSTG-INFO-02/08"],
                    [ctx.eng.save_http_evidence("fingerprint", ctx.primary)], fp)
    if ctx.args.skip_discovery:
        ctx.eng.write("scans", f"discovery_{ctx.eng.run_id}.json", scans)
        return
    disc = scans["files"] = {}
    for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
        r = ctx.http.get(t.origin + path, follow=True)
        entry = disc[path] = {"status": r.status, "error": r.error or r.blocked}
        if r.ok and r.status == 200:
            if path == "/robots.txt":
                entry["disallow_paths_listed_not_requested"] = re.findall(
                    r"(?im)^disallow:\s*(\S+)", r.body.decode("utf-8", "replace"))[:50]
            elif path == "/sitemap.xml":
                locs = [x.decode("utf-8", "replace") for x in re.findall(rb"<loc>\s*([^<\s]+)\s*</loc>", r.body)]
                entry["url_count_in_first_256KB"] = len(locs)
                entry["in_scope_sample"] = [u for u in locs if (lambda p: ctx.scope.allows(
                    p.hostname or "", p.port or (443 if p.scheme == "https" else 80)))(urlsplit(u))][:25]
    if ctx.args.enable_exposure_checks:
        log.info("Exposure checks enabled: fixed list of %d well-known paths, GET only.", len(EXPOSURE_CHECKS))
        base = ctx.http.get(t.origin + f"/vapt-nonexistent-{secrets.token_hex(4)}", follow=False)
        scans["soft_404_baseline_status"] = base.status
        results = scans["exposure"] = {}
        for path, sig in EXPOSURE_CHECKS.items():
            r = ctx.http.get(t.origin + path, follow=False)
            ctype = (r.headers.get("Content-Type") or "").lower()
            hit = bool(r.ok and r.status == 200 and sig(r.body, ctype))
            results[path] = {"status": r.status, "content_type": ctype, "signature_match": hit}
            if hit:
                ctx.reg.add(f"Possible sensitive file exposed: {path}", "Medium", "Likely / needs client validation",
                            t.origin + path,
                            f"GET {path} returned 200 with content matching the expected file signature "
                            f"(baseline for unknown paths: {base.status}). Body was not stored.",
                            "May disclose source, configuration or secrets.",
                            "Remove the file from the web root / block access; rotate any exposed secrets.",
                            [f"curl -sS -o /dev/null -w '%{{http_code}}' {t.origin}{path}"],
                            ["OWASP WSTG-CONF-04"], [], results[path])
    ctx.eng.write("scans", f"discovery_{ctx.eng.run_id}.json", scans)


# --------------------------------------------------------------------------- #
# Module 4 - reporting + checksums
# --------------------------------------------------------------------------- #
def md_cell(s) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def write_reports(ctx: Ctx, meta: dict) -> None:
    items = sorted(ctx.reg.items, key=lambda f: (SEVERITY_ORDER.index(f.severity), f.id))
    ctx.eng.write("reports", f"findings_{ctx.eng.run_id}.json",
                  {"metadata": meta, "findings": [dataclasses.asdict(f) for f in ctx.reg.items]})
    counts = {s: sum(1 for f in items if f.severity == s) for s in SEVERITY_ORDER}
    md = [f"# Automated Assessment Summary - {meta['client']}", "",
          "> CONFIDENTIAL - authorized assessment use only. Automated results are **preliminary**; severities are not "
          "CVSS scores. Validate manually before client delivery.", "",
          "## Scope and limitations", f"- Target: `{meta['target']}`", f"- Scope file: `{meta['scope_file']}` (sha256 `{meta['scope_sha256']}`)",
          f"- Window: {meta['started']} to {meta['finished']}", f"- Tester: {meta['tester']} | Source IP: {meta['source_ip'] or '[record manually]'}",
          f"- Requests sent: {meta['requests_sent']} (ceiling {meta['max_requests']}, delay {meta['rate_limit']}s)",
          *(["- NOTE: the TLS certificate failed validation; headers were read with verification disabled."]
            if ctx.primary and not ctx.primary.verified else []),
          "- Not performed: authenticated testing, injection/XSS/IDOR/CSRF, business logic, fuzzing, full-port scans.", "",
          "## Methodology and tools", f"- {TOOL_NAME} {__version__}, Python {sys.version.split()[0]}, requests {requests.__version__}, "
          f"dnspython {dns.version.version}", "- GET-only requests, manual redirect handling with per-hop scope checks, TLS handshakes.", "",
          "## Findings summary", "| Severity | Count |", "|---|---|"]
    md += [f"| {s} | {n} |" for s, n in counts.items()]
    md += ["", "| ID | Finding | Severity | Status | Affected asset |", "|---|---|---|---|---|"]
    md += [f"| {f.id} | {md_cell(f.title)} | {f.severity} | {f.status} | {md_cell(f.asset)} |" for f in items]
    md += ["", "## Detailed findings"]
    for f in items:
        md += [f"### {f.id} - {f.title}", f"- **Severity / CVSS:** {f.severity} / {f.cvss} {f.cvss_vector}",
               f"- **Status:** {f.status}", f"- **Affected asset:** {f.asset} (Port/Service: {f.port_service})", f"- **Description:** {f.description}",
               f"- **Evidence:** {', '.join(f'`{e}`' for e in f.evidence_files) or 'n/a'}",
               "- **Reproduction:** " + ("; ".join(f"`{r}`" for r in f.reproduction) or "n/a"),
               f"- **Impact:** {f.impact}", f"- **Recommendation:** {f.recommendation}",
               f"- **References:** {', '.join(f.references) or 'n/a'}", f"- **Retest result:** {f.retest}", f"- **Remarks:** {f.remarks}",
               (f"- **PoC:** ![{f.id} PoC](../{f.poc_image})" if f.poc_image else ""), ""]
    ctx.eng.write("reports", f"findings_{ctx.eng.run_id}.md", "\n".join(md) + "\n")


# --------------------------------------------------------------------------- #
# CVSS v3.1 (PRELIMINARY scoring), reference links, port/service, PoC images
# --------------------------------------------------------------------------- #
def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss31_score(vector: str) -> float:
    m = dict(p.split(":") for p in vector.split("/")[1:])
    scope_changed = m["S"] == "C"
    av = {"N": .85, "A": .62, "L": .55, "P": .2}[m["AV"]]
    ac = {"L": .77, "H": .44}[m["AC"]]
    pr = {"N": .85, "L": .68 if scope_changed else .62, "H": .5 if scope_changed else .27}[m["PR"]]
    ui = {"N": .85, "R": .62}[m["UI"]]
    cia = {"H": .56, "L": .22, "N": 0}
    iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
    impact = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if scope_changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + 8.22 * av * ac * pr * ui) if scope_changed else impact + 8.22 * av * ac * pr * ui
    return _roundup(min(raw, 10))


def cvss_band(score: float) -> str:
    return ("Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4
            else "Low" if score > 0 else "Informational")


_P = "CVSS:3.1/"
CVSS_VECTORS = [  # (title substring, vector) - first match wins; no match = informational (0.0)
    ("HTTP is not redirected", _P + "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    ("HSTS", _P + "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    ("Content-Security-Policy", _P + "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    ("nosniff", _P + "AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"),
    ("Clickjacking", _P + "AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"),
    ("Cookie(s) without", _P + "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    ("Server technology", _P + "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    ("TLS certificate failed", _P + "AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"),
    ("TLS certificate expired", _P + "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    ("TLS certificate expires soon", _P + "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L"),
    ("Deprecated protocol", _P + "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("Possible sensitive file", _P + "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
]
_O = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
_CS = "https://cheatsheetseries.owasp.org/cheatsheets/"
_MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/"
REFERENCE_LINKS = [
    ("HTTP is not redirected", _CS + "Transport_Layer_Security_Cheat_Sheet.html"),
    ("HSTS", _CS + "HTTP_Strict_Transport_Security_Cheat_Sheet.html"),
    ("Content-Security-Policy", _CS + "Content_Security_Policy_Cheat_Sheet.html"),
    ("nosniff", _MDN + "Headers/X-Content-Type-Options"),
    ("Clickjacking", _CS + "Clickjacking_Defense_Cheat_Sheet.html"),
    ("Referrer-Policy", _MDN + "Headers/Referrer-Policy"),
    ("Permissions-Policy", _MDN + "Headers/Permissions-Policy"),
    ("CORS", _MDN + "CORS"),
    ("Cookie(s) without", _CS + "Session_Management_Cheat_Sheet.html"),
    ("Server technology", _O + "01-Information_Gathering/02-Fingerprint_Web_Server"),
    ("Technologies identified", _O + "01-Information_Gathering/08-Fingerprint_Web_Application_Framework"),
    ("TLS certificate", _CS + "Transport_Layer_Security_Cheat_Sheet.html"),
    ("Deprecated protocol", "https://datatracker.ietf.org/doc/html/rfc8996"),
    ("Possible sensitive file", _O + "02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"),
]
DEFAULT_LINK = "https://owasp.org/www-project-web-security-testing-guide/"


def _lookup(table, title: str, default=""):
    return next((v for k, v in table if k in title), default)


def port_service(asset: str) -> str:
    try:
        p = urlsplit(asset if "://" in asset else "tcp://" + asset)
        port = p.port or {"https": 443, "http": 80}.get(p.scheme)
    except ValueError:
        return "N/A"
    if not port:
        return "N/A"
    svc = {"https": "HTTPS", "http": "HTTP"}.get(p.scheme) or ("TLS" if port == 443 else "TCP")
    return f"{port}/{svc}"


def enrich_finding(f: Finding) -> None:
    vec = _lookup(CVSS_VECTORS, f.title)
    if vec:
        f.cvss_vector, f.cvss_score = vec, cvss31_score(vec)
        f.severity = cvss_band(f.cvss_score)
        f.cvss = f"{f.cvss_score:.1f} (CVSS v3.1, preliminary)"
    else:
        f.cvss_vector, f.cvss_score, f.cvss = "", 0.0, "0.0 / N/A (informational or not scored)"
    f.link = _lookup(REFERENCE_LINKS, f.title, DEFAULT_LINK)
    if f.link not in f.references:
        f.references.append(f.link)
    f.port_service = port_service(f.asset)
    base = {"Confirmed": "Observed by automated check; reproduce manually before reporting.",
            "Likely / needs client validation": "Credible signal; needs analyst/client validation before reporting.",
            "Not tested": "Not tested - see description.",
            "Informational": "Informational observation; no demonstrated security impact."}.get(f.status, "")
    if vec:
        base += " CVSS v3.1 score is preliminary; re-score per contract (v3.1/v4.0) after manual validation."
    f.remarks = base.strip()


POC_HIGHLIGHT = [("HSTS", "strict-transport-security"), ("Content-Security-Policy", "content-security-policy"),
                 ("nosniff", "x-content-type-options"), ("Clickjacking", "x-frame-options"),
                 ("Referrer-Policy", "referrer-policy"), ("Permissions-Policy", "permissions-policy"),
                 ("Server technology", "server"), ("CORS", "access-control-allow-origin"),
                 ("Cookie(s) without", "set-cookie")]
C_FG, C_DIM, C_RED, C_GRN, C_YEL, C_BLU = "#d4d4d4", "#8b949e", "#ff7b72", "#7ee787", "#f2cc60", "#58a6ff"


def poc_lines(ctx: Ctx, meta: dict, f: Finding) -> list:
    L = [(f"PoC / EVIDENCE  |  {f.id}  |  {f.title}", C_BLU),
         (f"Captured: {now_iso()}   Tester: {meta['tester']}   Source IP: {meta['source_ip'] or 'n/a'}", C_DIM),
         (f"Target: {f.asset}   Port/Service: {f.port_service}", C_DIM),
         (f"Severity: {f.severity}   CVSS: {f.cvss}", C_YEL), ("", C_FG)]
    hdr = next((e for e in f.evidence_files if e.endswith("_redacted.txt")), None)
    key = next((h for s, h in POC_HIGHLIGHT if s in f.title), None)
    if hdr:
        L.append((f"$ curl -sS -I {f.asset}", C_GRN))
        seen = False
        for line in (ctx.eng.root / hdr).read_text(encoding="utf-8").splitlines():
            if line.startswith("#"):
                L.append((line, C_DIM))
                continue
            hit = bool(key and line.lower().startswith(key + ":"))
            seen = seen or hit
            L.append((line, C_RED if hit else C_FG))
        if key and not seen:
            L.append((f">>> {key}: NOT PRESENT in response <<<", C_RED))
    else:
        js = next((e for e in f.evidence_files if e.endswith(".json")), None)
        observed = {}
        if js:
            observed = json.loads((ctx.eng.root / js).read_text(encoding="utf-8")).get("observed", {})
        L.append(("Observed data:", C_GRN))
        L += [(x, C_FG) for x in json.dumps(observed, indent=2, default=str).splitlines()]
    L += [("", C_FG), ("Cookie values / auth headers redacted. Response bodies are never stored.", C_YEL)]
    return L


def _font(size: int):
    from PIL import ImageFont
    for name in ("DejaVuSansMono.ttf", "consola.ttf", "cour.ttf", "LiberationMono-Regular.ttf", "Menlo.ttc"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def render_poc_png(path: Path, lines: list) -> None:
    from PIL import Image, ImageDraw
    font, lh, pad, width = _font(15), 21, 22, 1200
    rows = []
    for text, color in lines:
        for part in (textwrap.wrap(text, 125, break_long_words=True, break_on_hyphens=False) or [""]):
            rows.append((part, color))
    rows = rows[:55]
    img = Image.new("RGB", (width, pad * 2 + 30 + lh * len(rows)), "#0d1117")
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, width, 26], fill="#161b22")
    for i, c in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        d.ellipse([12 + i * 20, 8, 22 + i * 20, 18], fill=c)
    y = 26 + pad
    for text, color in rows:
        d.text((pad, y), text, font=font, fill=color)
        y += lh
    img.save(path, "PNG")


def make_poc_images(ctx: Ctx, meta: dict) -> None:
    try:
        import PIL  # noqa: F401
    except ImportError:
        log.warning("Pillow not installed (pip install Pillow): PoC screenshots skipped.")
        return
    for f in ctx.reg.items:
        try:
            name = f"{f.id}_{ctx.eng.run_id}_poc.png"
            render_poc_png(ctx.eng.root / "evidence" / name, poc_lines(ctx, meta, f))
            f.poc_image = f"evidence/{name}"
            f.evidence_files.append(f.poc_image)
        except Exception as exc:
            log.warning("PoC image for %s failed: %s", f.id, exc)


FINDINGS_COLS = ["Finding ID", "Title", "Asset ID", "Affected URL / endpoint", "Parameter / component",
                 "Category / CWE", "Severity", "CVSS version", "CVSS score", "CVSS vector", "Verification status",
                 "Description", "Reproduction steps", "Evidence references", "Technical impact", "Business impact",
                 "Recommendation", "Reference (OWASP/CVE/etc.)", "First seen", "Owner", "Target fix date",
                 "Retest status", "Retest date", "Residual risk / notes"]
EVIDENCE_COLS = ["Evidence ID", "Finding ID", "Filename / secure path", "Evidence type",
                 "Captured date/time + timezone", "Tester", "Asset / endpoint", "Redaction completed?",
                 "SHA-256 hash", "Storage location / access control", "Notes"]


def tracker_rows(ctx: Ctx, meta: dict):
    """Rows matching the 'Findings' and 'Evidence Register' sheets of the Excel tracker template."""
    f_rows, e_rows = [], []
    for f in ctx.reg.items:
        steps = "\n".join(f"{i}. {s}" for i, s in enumerate(f.reproduction, 1))
        f_rows.append([f.id, f.title, "[Asset ID]", f.asset, f.port_service, "", f.severity,
                       "3.1" if f.cvss_vector else "N/A", f.cvss_score, f.cvss_vector, f.status, f.description, steps,
                       ", ".join(f.evidence_files), f.impact, "[Business impact]", f.recommendation, f.link,
                       meta["started"][:10], "", "", f.retest, "", f.remarks])
        for i, ev in enumerate(f.evidence_files, 1):
            path = ctx.eng.root / ev
            digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""
            kind = ("PoC screenshot (PNG)" if ev.endswith(".png") else
                    "HTTP headers (redacted)" if ev.endswith("_redacted.txt") else "Finding record (JSON)")
            e_rows.append([f"{f.id}-E{i:02d}", f.id, ev, kind, meta["started"], meta["tester"], f.asset,
                           "Yes - cookie values/auth headers redacted; bodies never stored", digest,
                           "[Secure storage path / access control]", ""])
    return f_rows, e_rows


def place_poc_image(ws, ctx: Ctx, f: Finding, anchor: str, row: int, target_w: int = 520) -> None:
    """Embed the finding's PoC PNG at `anchor` and size the row to fit."""
    if not f.poc_image or not (ctx.eng.root / f.poc_image).is_file():
        return
    from openpyxl.drawing.image import Image as XLImage
    img = XLImage(str(ctx.eng.root / f.poc_image))
    ratio = min(target_w / img.width, 530 / img.height)  # Excel max row height is 409 pt (~545 px)
    img.width, img.height = int(img.width * ratio), int(img.height * ratio)
    ws.add_image(img, anchor)
    ws.row_dimensions[row].height = max(ws.row_dimensions[row].height or 15, img.height * 0.75 + 6)


def write_findings_xlsx(ctx: Ctx, meta: dict) -> None:
    """Stand-alone Excel: title, severity, CVSS, port/service, recommendation, article link, remarks, PoC image."""
    try:
        import openpyxl
        from openpyxl.styles import Alignment, Font, PatternFill
    except ImportError:
        log.warning("openpyxl not installed (pip install openpyxl): Excel export skipped (CSV still written).")
        return
    items = sorted(ctx.reg.items, key=lambda f: (SEVERITY_ORDER.index(f.severity), f.id))
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Findings"
    cols = [("S.No", 6), ("Finding ID", 11), ("Vulnerability Title", 36), ("Severity", 13), ("CVSS Score", 10),
            ("CVSS Vector", 42), ("Port / Service", 13), ("Affected Asset", 32), ("Description", 48),
            ("Recommendation", 48), ("Reference (Article Link)", 46), ("Remarks", 40),
            ("PoC / Evidence (Screenshot)", 75)]
    for i, (name, w) in enumerate(cols, 1):
        c = ws.cell(row=1, column=i, value=name)
        c.font, c.fill = Font(bold=True, color="FFFFFF"), PatternFill("solid", fgColor="1F3864")
        c.alignment = Alignment(wrap_text=True, vertical="center", horizontal="center")
        ws.column_dimensions[openpyxl.utils.get_column_letter(i)].width = w
    ws.freeze_panes = "D2"
    fills = {"Critical": "C00000", "High": "FF6B6B", "Medium": "FFB347", "Low": "FFE066", "Informational": "9DC3E6"}
    for r, f in enumerate(items, 2):
        vals = [r - 1, f.id, f.title, f.severity, f.cvss_score, f.cvss_vector or "N/A", f.port_service, f.asset,
                f.description, f.recommendation, f.link, f.remarks, ""]
        for c, v in enumerate(vals, 1):
            cell = ws.cell(row=r, column=c, value=v)
            cell.alignment = Alignment(wrap_text=True, vertical="top")
        ws.cell(row=r, column=4).fill = PatternFill("solid", fgColor=fills.get(f.severity, "FFFFFF"))
        ws.cell(row=r, column=4).font = Font(bold=True)
        link = ws.cell(row=r, column=11)
        link.hyperlink, link.font = f.link, Font(color="0563C1", underline="single")
        try:
            place_poc_image(ws, ctx, f, f"M{r}", r)
        except Exception as exc:
            log.warning("Could not embed image for %s: %s", f.id, exc)
    s = wb.create_sheet("Summary")
    for row in [("Client", meta["client"]), ("Target", meta["target"]), ("Tester", meta["tester"]),
                ("Source IP", meta["source_ip"]), ("Started", meta["started"]), ("Finished", meta["finished"]),
                ("Requests sent", meta["requests_sent"]), ("CVSS note", "Preliminary CVSS v3.1 - re-score after manual validation")] + \
               [(f"{sev} findings", sum(1 for f in items if f.severity == sev)) for sev in SEVERITY_ORDER]:
        s.append(row)
    s.column_dimensions["A"].width, s.column_dimensions["B"].width = 20, 70
    out = ctx.eng.root / "reports" / f"VAPT_Findings_{ctx.eng.run_id}.xlsx"
    wb.save(out)
    log.info("Excel findings workbook: %s", out)


def write_trackers(ctx: Ctx, meta: dict) -> None:
    f_rows, e_rows = tracker_rows(ctx, meta)
    for name, cols, rows in (("tracker_findings", FINDINGS_COLS, f_rows), ("tracker_evidence", EVIDENCE_COLS, e_rows)):
        with open(ctx.eng.root / "reports" / f"{name}_{ctx.eng.run_id}.csv", "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow(cols)
            w.writerows(rows)
    try:
        write_findings_xlsx(ctx, meta)
    except Exception as exc:
        log.warning("Excel findings workbook failed (%s); CSV exports were still written.", exc)
    tpl = ctx.args.tracker_template
    if not tpl:
        return
    try:
        import openpyxl
        wb = openpyxl.load_workbook(tpl)
        for sheet, rows in (("Findings", f_rows), ("Evidence Register", e_rows)):
            ws = wb[sheet]  # header is row 4; data starts at row 5
            for i, row in enumerate(rows):
                for j, val in enumerate(row, 1):
                    ws.cell(row=5 + i, column=j, value=val)
        poc = wb["PoC Evidence"] if "PoC Evidence" in wb.sheetnames else wb.create_sheet("PoC Evidence")
        for j, (h, w) in enumerate((("Finding ID", 12), ("Title", 40), ("PoC / Evidence (Screenshot)", 75)), 1):
            poc.cell(row=1, column=j, value=h)
            poc.column_dimensions[openpyxl.utils.get_column_letter(j)].width = w
        for r, f in enumerate(ctx.reg.items, 2):
            poc.cell(row=r, column=1, value=f.id)
            poc.cell(row=r, column=2, value=f.title)
            place_poc_image(poc, ctx, f, f"C{r}", r)
        out = ctx.eng.root / "reports" / f"Web_VAPT_Tracker_{ctx.eng.run_id}.xlsx"
        wb.save(out)
        log.info("Filled Excel tracker: %s", out)
    except ImportError:
        log.warning("--tracker-template needs openpyxl (pip install openpyxl); CSV exports were still written.")
    except Exception as exc:
        log.warning("Could not fill Excel template (%s); CSV exports were still written.", exc)


def write_checksums(eng: Engagement) -> int:
    lines = []
    for sub in ("evidence", "scans", "recon", "reports"):
        for p in sorted((eng.root / sub).glob("*")):
            if p.is_file() and p.name != "SHA256SUMS.txt":
                lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {sub}/{p.name}")
    (eng.root / "evidence" / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def rate_type(v: str) -> float:
    f = float(v)
    if f < 0.2:
        raise argparse.ArgumentTypeError("--rate-limit must be at least 0.2 seconds")
    return f


def positive_int(v: str) -> int:
    n = int(v)
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="safe_vapt.py", description=__doc__.split("\n\n")[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog="Example:\n  python3 safe_vapt.py --target https://www.example.com "
                                       "--client-name acme-web --scope-file scope.txt --confirm-authorization")
    p.add_argument("--target", required=True, help="Approved URL/host to assess")
    p.add_argument("--client-name", required=True, help="Engagement name (used as directory name)")
    p.add_argument("--scope-file", required=True, help="Allowlist file (one host/*.domain/IP/CIDR per line)")
    p.add_argument("--confirm-authorization", action="store_true",
                   help="REQUIRED: confirms you hold written authorization for this target and window")
    p.add_argument("--rate-limit", type=rate_type, default=1.0, help="Seconds between requests (min 0.2, default 1.0)")
    p.add_argument("--tracker-template", default="", help="Optional: path to Web_VAPT_Findings_and_Tracking_Template.xlsx "
                   "to auto-fill the Findings and Evidence Register sheets (needs openpyxl)")
    p.add_argument("--max-requests", type=positive_int, default=150, help="Hard request ceiling (default 150)")
    p.add_argument("--timeout", type=float, default=15.0, help="Per-request timeout in seconds")
    p.add_argument("--output-dir", default=".", help="Where the engagement folder is created")
    p.add_argument("--tester", default="[Analyst name]")
    p.add_argument("--source-ip", default="", help="Your public IP, recorded in the report")
    p.add_argument("--contact", default="", help="Contact info added to the User-Agent so the client can identify you")
    p.add_argument("--skip-tls", action="store_true", help="Skip TLS handshake checks")
    p.add_argument("--skip-discovery", action="store_true", help="Skip robots/sitemap/security.txt requests")
    p.add_argument("--enable-exposure-checks", action="store_true",
                   help="Opt in: GET a fixed list of well-known sensitive paths (status/signature only)")
    p.add_argument("--allow-private-ips", action="store_true", help="Permit private/loopback targets (internal tests)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def setup_logging(verbose: bool) -> None:
    log.setLevel(logging.DEBUG)
    h = logging.StreamHandler()
    h.setLevel(logging.DEBUG if verbose else logging.INFO)
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S"))
    log.addHandler(h)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)
    if not args.confirm_authorization:
        log.error("Refusing to run: add --confirm-authorization to confirm you have written authorization "
                  "(approved assets, window, source IP, rate limits).")
        return EXIT_USAGE
    try:  # --- validation happens BEFORE any file creation or network traffic ---
        scope = Scope.load(Path(args.scope_file))
        target = parse_target(args.target)
        scope.require(target.host, target.port)
    except ScopeError as exc:
        log.error("%s", exc)
        return EXIT_SCOPE

    run_id = dt.datetime.now().strftime("%Y%m%dT%H%M%S")
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", args.client_name).strip("-.") or "engagement"
    try:
        eng = Engagement(Path(args.output_dir) / safe_name, run_id)
        shutil.copy2(scope.path, eng.root / "scope" / f"scope_{run_id}.txt")
        (eng.root / "scope" / "approved-target.txt").write_text(target.origin + "\n")
        fh = logging.FileHandler(eng.root / "notes" / f"run_{run_id}.log", encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(fh)
    except OSError as exc:
        log.error("Cannot create engagement directory: %s", exc)
        return EXIT_RUNTIME

    started = now_iso()
    (eng.root / "notes" / "start-time.txt").write_text(started + "\n")
    ua = f"{TOOL_NAME}/{__version__} (authorized security assessment" + (f"; contact: {args.contact}" if args.contact else "") + ")"
    throttle = Throttle(args.rate_limit, args.max_requests)
    meta = {"client": safe_name, "target": target.origin, "tester": args.tester, "source_ip": args.source_ip,
            "scope_file": str(scope.path), "scope_sha256": scope.sha256, "started": started,
            "rate_limit": args.rate_limit, "max_requests": args.max_requests}
    ctx = Ctx(args, target, scope, throttle, SafeHttp(scope, throttle, args.timeout, ua), eng, Registry(eng, meta))
    log.info("Engagement folder: %s | target %s | delay %.1fs | ceiling %d requests",
             eng.root, target.origin, args.rate_limit, args.max_requests)

    code = EXIT_OK
    steps = [("Module 1", module1_scope_connectivity), ("Module 2", module2_tls_headers),
             ("Module 3", module3_discovery)]
    try:
        for name, fn in steps:
            if name != "Module 1" and not ctx.reachable:
                break
            try:
                fn(ctx)
            except (ScopeError, BudgetExceeded):
                raise
            except Exception as exc:  # one broken module must not kill the report
                log.error("%s failed: %s (see run log with -v)", name, exc)
                log.debug("Details", exc_info=True)
                ctx.reg.add(f"{name} did not complete", "Informational", "Not tested", target.origin,
                            f"Unexpected error: {type(exc).__name__}: {exc}", "Coverage gap.",
                            "Re-run or test manually.", [], [], [], {})
                code = EXIT_RUNTIME
        if not ctx.reachable:
            code = EXIT_RUNTIME
    except ScopeError as exc:
        log.error("Stopped: %s", exc)
        code = EXIT_SCOPE
    except BudgetExceeded as exc:
        log.warning("Stopped: %s Results so far are saved.", exc)
        code = EXIT_RUNTIME
    except KeyboardInterrupt:
        log.warning("Interrupted by user; saving partial results.")
        code = EXIT_RUNTIME
    finally:
        meta.update(finished=now_iso(), requests_sent=throttle.count)
        (eng.root / "notes" / "end-time.txt").write_text(meta["finished"] + "\n")
        try:
            make_poc_images(ctx, meta)  # before reports so they can reference the PNGs
            write_reports(ctx, meta)
            write_trackers(ctx, meta)
            n = write_checksums(eng)  # last, so every generated file is hashed
            log.info("Done: %d finding(s), %d file(s) hashed. Reports in %s", len(ctx.reg.items), n, eng.root / "reports")
        except OSError as exc:
            log.error("Could not write reports: %s", exc)
            code = EXIT_RUNTIME
    return code


if __name__ == "__main__":
    sys.exit(main())
