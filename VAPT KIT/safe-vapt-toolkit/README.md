# safe_vapt - Scope-guarded web assessment helper (v1.2.0)

Automates the *safe, non-destructive* parts of the Authorized Web VAPT workflow:
scope/connectivity, TLS & security headers, passive discovery, evidence + reporting.
GET requests and TLS handshakes only. No fuzzing, payloads, logins, or body storage.

> Use ONLY with written authorization (assets, window, source IP, rate limits).

## Install
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt   # includes openpyxl + Pillow for Excel/PoC images

## Configure
Copy `examples/scope.example.txt` to `scope.txt` and list ONLY approved assets
(host, `*.domain`, IP, CIDR, optional `:port`; no port = 80/443 only).

## Run
    python3 safe_vapt.py --target https://www.authorized-example.com \
      --client-name acme-web --scope-file scope.txt \
      --rate-limit 1.5 --tester "Your Name" --source-ip 203.0.113.5 \
      --tracker-template Web_VAPT_Findings_and_Tracking_Template.xlsx \
      --confirm-authorization

Useful flags: `--max-requests` (default 150), `--skip-tls`, `--skip-discovery`,
`--enable-exposure-checks` (opt-in, fixed 7-path list), `--allow-private-ips`, `-v`.

## What is new in v1.2.0
- `reports/VAPT_Findings_<run>.xlsx`: Vulnerability Title, Severity, CVSS Score + Vector, Port / Service,
  Recommendation, Reference (article link), Remarks, and an embedded PoC / Evidence screenshot per finding.
- PoC screenshots (`evidence/VAPT-00X_<run>_poc.png`) are rendered from the captured, redacted request/response,
  with the problem line highlighted. They are generated evidence images, not browser screenshots.
- CVSS v3.1 scores are PRELIMINARY (preset vectors per check). Re-score per your contract (v3.1/v4.0) after manual validation.
- With `--tracker-template`, the Findings sheet (CVSS, severity, port/service, link, remarks) and Evidence Register
  are filled, and a "PoC Evidence" sheet with the images is added.

## Output (`<client-name>/`)
scope/ recon/ scans/ evidence/ notes/ reports/
- `reports/findings_<run>.json|md` - findings in the report template layout
- `reports/tracker_findings_<run>.csv`, `tracker_evidence_<run>.csv` - match the Excel tracker columns
- `reports/Web_VAPT_Tracker_<run>.xlsx` - filled template (with `--tracker-template`)
- `evidence/SHA256SUMS.txt` - verify: `cd <client-name> && sha256sum -c evidence/SHA256SUMS.txt`

## Exit codes
0 OK | 1 missing `--confirm-authorization` | 2 out of scope / bad scope file | 3 runtime error or unreachable

## Limitations (read these)
- Severities are preliminary; CVSS is left blank - score after manual validation.
- Legacy-TLS "rejected_or_untestable" is not proof; confirm with `testssl.sh`.
- Scope is checked by name before DNS/HTTP; DNS can change between checks (rebinding) -
  also allowlist the source IP and monitor client-side.
- Redirect targets are scope-checked per hop; out-of-scope hops are never followed.
- Manual testing (Burp: IDOR, XSS, injection, CSRF, business logic) is not automated.

## Tests
    python3 -m unittest discover -s tests -v
