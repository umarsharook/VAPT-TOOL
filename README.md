# VAPT-TOOL

**Scope-guarded, non-destructive web security assessment helper for authorized VAPT engagements.**

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Version](https://img.shields.io/badge/version-1.2.0-informational)
![Requests](https://img.shields.io/badge/traffic-GET%20only-success)
![Use](https://img.shields.io/badge/use-authorized%20testing%20only-red)

`safe_vapt` automates the safe, repeatable parts of a web assessment (scope checks, DNS, TLS and security-header analysis, passive discovery) and produces audit-ready output: redacted evidence, PoC screenshots, CVSS-scored findings, an Excel workbook, a Markdown report and SHA-256 checksums.

It is built for beginners to use safely. It refuses anything outside your scope file, rate-limits every request, and cannot send attack payloads.

> **Legal notice:** Use this tool only against assets you are explicitly authorized, in writing, to test (exact assets, test window, source IP and rate limits). Running it with `--confirm-authorization` is your statement that you hold that authorization. You are responsible for how you use it.

---

## Contents

- [Features](#features)
- [Safety guardrails](#safety-guardrails)
- [Install](#install)
- [Quick start](#quick-start)
- [Scope file format](#scope-file-format)
- [Command-line options](#command-line-options)
- [What it checks](#what-it-checks)
- [Output](#output)
- [Excel workbook and PoC screenshots](#excel-workbook-and-poc-screenshots)
- [Severity and CVSS](#severity-and-cvss)
- [Exit codes](#exit-codes)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Development and tests](#development-and-tests)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **Mandatory scope allowlist:** the target is validated against your scope file before any file is created or any request is sent.
- **Strict rate limiting:** a configurable delay between every request and a hard request ceiling.
- **Module 1, scope and connectivity:** DNS (A, AAAA, CNAME) through `dnspython`, plus an HTTP status and header check through `requests`.
- **Module 2, TLS and security headers:** HTTP-to-HTTPS enforcement, HSTS, CSP, `X-Content-Type-Options`, clickjacking protection, Referrer-Policy, Permissions-Policy, CORS, cookie flags, version disclosure, certificate validity and expiry, and legacy TLS probes.
- **Module 3, safe discovery:** technology fingerprinting from headers and cookies, `robots.txt`, `sitemap.xml`, `security.txt`, and an optional fixed list of well-known sensitive paths.
- **Module 4, evidence and reporting:** engagement folder tree, redacted evidence, PoC images, JSON and Markdown findings, tracker CSVs, an Excel workbook, and SHA-256 checksums.
- **Graceful failure:** unreachable or out-of-scope targets stop cleanly with a clear message and an exit code, not a traceback.

## Safety guardrails

| Guardrail | How it works |
|---|---|
| Scope allowlist | Target host and port must match an entry in the scope file, or nothing is sent (exit code 2). |
| Per-hop redirect checks | Every redirect hop is re-checked against scope. Out-of-scope hops are refused and recorded, never followed. |
| Port restriction | A scope entry with no port allows only 80 and 443. Other ports must be listed explicitly (`host:8443`). |
| Private-IP guard | Targets resolving to private, loopback or link-local addresses are blocked unless you pass `--allow-private-ips`. |
| Rate limit | `--rate-limit` sets the minimum delay in seconds between requests (minimum 0.2, default 1.0). |
| Request ceiling | `--max-requests` stops the run when reached (default 150). |
| Read-only methods | Only `GET` requests and TLS handshakes are sent. There are no POST, PUT or DELETE requests. |
| No fuzzing | There is no payload, wordlist or brute-force capability. Discovery uses small fixed lists only. |
| No body storage | Response bodies are never written to disk. Cookie values and auth headers are redacted. |
| Authorization gate | The tool refuses to run without `--confirm-authorization`. |
| No environment proxies | Proxy environment variables are ignored, so traffic does not route somewhere unexpected. |

## Install

Requires Python 3.9 or newer.

**Linux / macOS / Kali**
```bash
git clone https://github.com/YOUR-USERNAME/safe-vapt-toolkit.git
cd safe-vapt-toolkit
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

**Windows (PowerShell)**
```powershell
git clone https://github.com/YOUR-USERNAME/safe-vapt-toolkit.git
cd safe-vapt-toolkit
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Dependencies: `requests`, `dnspython`, `openpyxl` (Excel output) and `Pillow` (PoC screenshots). If `openpyxl` or `Pillow` is missing, the tool still runs and skips the Excel or image output with a warning.

## Quick start

**1. Create a scope file** with only the assets named in your authorization:

```bash
cp examples/scope.example.txt scope.txt
# edit scope.txt, or create it directly:
printf 'www.client.com\n' > scope.txt
```

On Windows PowerShell, use `Set-Content -Path scope.txt -Value "www.client.com" -Encoding ascii`. Avoid `echo ... > scope.txt`, which can save the file as UTF-16.

**2. Check that the guardrail works.** An out-of-scope target must be refused:

```bash
python safe_vapt.py --target https://not-in-scope.example \
  --client-name test --scope-file scope.txt --confirm-authorization
# ERROR  not-in-scope.example:443 is NOT in the scope file. Nothing was sent.
```

**3. Run the assessment**, only inside the approved test window:

```bash
python safe_vapt.py \
  --target https://www.client.com \
  --client-name client-project \
  --scope-file scope.txt \
  --rate-limit 1.5 \
  --tester "Your Name" \
  --source-ip "YOUR.PUBLIC.IP" \
  --contact "you@company.com" \
  --confirm-authorization
```

`--source-ip` is **your** public IP (the address the target sees), not the target's. Find it with `curl -s ifconfig.me`. The target's address is resolved by the tool and saved in `recon/dns_*.json`.

**4. Read the results** in `client-project/reports/`.

To fill your own Excel tracker template as well, add `--tracker-template "path/to/Web_VAPT_Findings_and_Tracking_Template.xlsx"`.

## Scope file format

One approved asset per line. Everything after `#` is a comment. Use plain text only, with no Markdown links, `https://` prefixes or quotes.

```
# One approved asset per line. Anything not listed here will be refused.
www.client.com                # exact host, ports 80/443 only
*.client.com                  # subdomains only (not the apex)
app.client.com:8443           # explicit non-default port
203.0.113.10                  # single IP
198.51.100.0/28               # CIDR range
```

Verify the file before running: `cat -A scope.txt` (Linux) or `Get-Content scope.txt` (PowerShell). Each line should show only the hostname.

## Command-line options

| Option | Required | Default | Description |
|---|---|---|---|
| `--target` | yes | | Approved URL or host to assess. |
| `--client-name` | yes | | Engagement name, used as the output folder name. |
| `--scope-file` | yes | | Allowlist file (see above). |
| `--confirm-authorization` | yes | | Confirms you hold written authorization for this target and window. |
| `--rate-limit` | no | `1.0` | Seconds between requests (minimum 0.2). |
| `--max-requests` | no | `150` | Hard request ceiling. |
| `--timeout` | no | `15` | Per-request timeout in seconds. |
| `--output-dir` | no | `.` | Where the engagement folder is created. |
| `--tester` | no | `[Analyst name]` | Tester name recorded in reports and evidence. |
| `--source-ip` | no | empty | Your public IP, recorded in reports. |
| `--contact` | no | empty | Added to the User-Agent so the client can identify your traffic. |
| `--skip-tls` | no | off | Skip TLS handshake checks. |
| `--skip-discovery` | no | off | Skip `robots.txt`, `sitemap.xml` and `security.txt` requests. |
| `--enable-exposure-checks` | no | off | Opt in: GET a fixed list of 7 well-known sensitive paths (status and signature only). |
| `--allow-private-ips` | no | off | Permit private or loopback targets (approved internal tests only). |
| `--tracker-template` | no | empty | Path to the Excel tracker template to auto-fill (needs `openpyxl`). |
| `-v`, `--verbose` | no | off | Show debug output. |

## What it checks

| Area | Checks |
|---|---|
| Connectivity | DNS records, HTTP status and headers, redirect chain with scope enforcement |
| HTTPS | HTTP-to-HTTPS redirect, HSTS presence and `max-age` |
| Headers | CSP (missing or weak), `X-Content-Type-Options`, clickjacking protection (`X-Frame-Options` or `frame-ancestors`), Referrer-Policy, Permissions-Policy, CORS wildcard |
| Cookies | `Secure`, `HttpOnly` and `SameSite` attributes (values never stored) |
| Disclosure | `Server` and `X-Powered-By` version banners |
| TLS | Certificate validation, expiry, negotiated protocol and cipher, TLS 1.0 and 1.1 acceptance |
| Discovery | Header, cookie and body fingerprints; `robots.txt`; `sitemap.xml`; `security.txt` |
| Exposure (opt-in) | `/.git/HEAD`, `/.env`, `/.svn/entries`, `/.DS_Store`, `/server-status`, `/phpinfo.php`, `/web.config`, matched by file signature with a soft-404 baseline |

**Deliberately not automated:** authentication, session handling, IDOR, XSS, injection, CSRF, file upload, API authorization and business logic. Test these manually (for example with Burp Suite) under your rules of engagement.

## Output

Everything is written to `<output-dir>/<client-name>/`:

```
client-project/
├── scope/       scope copy and approved target
├── recon/       dns_<run>.json, http-headers_<run>.txt
├── scans/       tls-and-http-summary_<run>.json, discovery_<run>.json
├── evidence/    redacted header captures, per-finding JSON records,
│                VAPT-00X_<run>_poc.png screenshots, SHA256SUMS.txt
├── notes/       start-time.txt, end-time.txt, run_<run>.log
└── reports/     findings_<run>.md / .json
                 VAPT_Findings_<run>.xlsx
                 tracker_findings_<run>.csv, tracker_evidence_<run>.csv
                 Web_VAPT_Tracker_<run>.xlsx   (with --tracker-template)
```

Verify evidence integrity from inside the engagement folder:

```bash
cd client-project
sha256sum -c evidence/SHA256SUMS.txt
```

## Excel workbook and PoC screenshots

`reports/VAPT_Findings_<run>.xlsx` contains one row per finding:

| Column | Content |
|---|---|
| Vulnerability Title | Short finding title |
| Severity | Derived from the CVSS score (colour-coded) |
| CVSS Score and Vector | Preliminary CVSS v3.1 |
| Port / Service | For example `443/HTTPS` |
| Affected Asset | URL or host:port |
| Description and Recommendation | What was observed and the corrective control |
| Reference (Article Link) | Clickable OWASP, MDN or RFC article for the finding |
| Remarks | Verification guidance |
| PoC / Evidence | Embedded screenshot |

Each finding also gets a PoC image at `evidence/VAPT-00X_<run>_poc.png`, rendered from the captured, redacted request and response, with the problem line highlighted (for example `content-security-policy: NOT PRESENT in response`). These are generated evidence images, not browser screenshots. A Summary sheet lists the engagement details and finding counts.

With `--tracker-template`, the tool fills the **Findings** and **Evidence Register** sheets of your template and adds a **PoC Evidence** sheet with the images.

## Severity and CVSS

CVSS v3.1 scores come from preset vectors per check, and the severity band (Critical, High, Medium, Low, Informational) follows the score. Observations without a security impact, such as a technology fingerprint, are scored 0.0 and marked Informational.

**Scores are preliminary.** Re-score each verified finding per your contract (v3.1 or v4.0) after manual validation, and adjust priority for asset criticality and compensating controls. Statuses used: `Confirmed`, `Likely / needs client validation`, `Informational`, `Not tested`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed |
| 1 | Missing `--confirm-authorization` |
| 2 | Target out of scope, or the scope file is missing or invalid |
| 3 | Runtime error, request ceiling reached, or target unreachable |

## Limitations

- Findings are automated observations. Validate them manually before reporting.
- A header missing from one response is not automatically a vulnerability. Check the context.
- A TLS 1.0 or 1.1 result of `rejected_or_untestable` is not proof the protocol is disabled, because it can depend on your local OpenSSL build. Confirm with `testssl.sh`.
- Scope is checked by name before DNS and HTTP. DNS can change between checks (rebinding), so also have the client allowlist your source IP and monitor on their side.
- CDN, WAF and shared-hosting infrastructure may be outside your authorization. If the target resolves to such infrastructure, confirm with the client before testing it.
- A single run covers one target host. Run it again for each approved host.

## Troubleshooting

| Message | Fix |
|---|---|
| `Missing dependency: dns` | Activate the virtual environment and run `python -m pip install -r requirements.txt`. On Windows, use `python`, not `python3`. |
| `Scope file not found` | Create `scope.txt` in the folder you run from, or pass the full path. |
| `Invalid scope entry` | Use plain hostnames only, with no `[ ]`, `( )` or `https://`. |
| `... is NOT in the scope file` | The target host or port is missing from the scope file. Add it only if your authorization lists it. |
| `resolves to non-public address` | Internal target. Use `--allow-private-ips` only if approved. |
| `Target unreachable` | The site may be down, block your IP, or you may be outside the test window. Do not retry repeatedly. |
| `Redirect ... refused` | The site redirects to an unlisted host. Ask the client before adding it to scope. |
| Excel or screenshots skipped | Install `openpyxl` and `Pillow`. |

## Development and tests

```bash
python -m unittest discover -s tests -v
```

The tests cover scope matching, target parsing, the request ceiling, cookie redaction, header analysis, the CVSS calculator and port/service parsing.

## Contributing

Issues and pull requests are welcome. Keep changes non-destructive and in line with the safety guardrails above. Features that send payloads, fuzz or brute-force will not be accepted.

Never commit client data, scan results, evidence or scope files. The provided `.gitignore` entries cover these.

## License

Add a `LICENSE` file of your choice (MIT is common for tools like this) before publishing.
