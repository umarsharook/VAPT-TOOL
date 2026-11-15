import sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import safe_vapt as sv


class ScopeTests(unittest.TestCase):
    def setUp(self):
        p = Path(tempfile.mkdtemp()) / "scope.txt"
        p.write_text("a.example.com\n*.b.example.com\n10.0.0.0/30\n1.2.3.4:8443\n# comment\n")
        self.s = sv.Scope.load(p)

    def test_exact(self):
        self.assertTrue(self.s.allows("a.example.com", 443))
        self.assertFalse(self.s.allows("x.a.example.com", 443))

    def test_wildcard_not_apex(self):
        self.assertTrue(self.s.allows("x.b.example.com", 80))
        self.assertFalse(self.s.allows("b.example.com", 80))

    def test_default_ports_only(self):
        self.assertFalse(self.s.allows("a.example.com", 8080))

    def test_cidr_and_port(self):
        self.assertTrue(self.s.allows("10.0.0.2", 443))
        self.assertFalse(self.s.allows("10.0.0.9", 443))
        self.assertTrue(self.s.allows("1.2.3.4", 8443))
        self.assertFalse(self.s.allows("1.2.3.4", 443))

    def test_lookalike_rejected(self):
        self.assertFalse(self.s.allows("a.example.com.evil.com", 443))


class TargetTests(unittest.TestCase):
    def test_default_scheme(self):
        t = sv.parse_target("a.example.com")
        self.assertEqual((t.scheme, t.port), ("https", 443))

    def test_credentials_rejected(self):
        with self.assertRaises(sv.ScopeError):
            sv.parse_target("https://u:p@a.example.com")

    def test_bad_scheme(self):
        with self.assertRaises(sv.ScopeError):
            sv.parse_target("ftp://a.example.com")


class MiscTests(unittest.TestCase):
    def test_throttle_ceiling(self):
        t = sv.Throttle(0.0, 2)
        t.wait(); t.wait()
        with self.assertRaises(sv.BudgetExceeded):
            t.wait()

    def test_cookie_redaction(self):
        self.assertEqual(sv.redact_set_cookie("sid=abc123; Secure"), "sid=[REDACTED]; Secure")

    def test_header_analysis(self):
        r = sv.FetchResult(url="https://x")
        r.set_cookies = ["sid=1; Path=/"]
        titles = [x[0] for x in sv.analyze_headers(r, True)]
        self.assertIn("HSTS header missing", titles)
        self.assertIn("Cookie(s) without Secure attribute", titles)


class CvssTests(unittest.TestCase):
    def test_known_scores(self):
        self.assertEqual(sv.cvss31_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(sv.cvss31_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(sv.cvss31_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"), 5.3)

    def test_bands_and_enrich(self):
        self.assertEqual(sv.cvss_band(0), "Informational")
        self.assertEqual(sv.cvss_band(6.8), "Medium")
        f = sv.Finding("VAPT-001", "HSTS header missing", "Low", "Confirmed", "https://a.example.com/", "d", "i", "r", [], [], [])
        sv.enrich_finding(f)
        self.assertEqual((f.cvss_score, f.severity, f.port_service), (3.1, "Low", "443/HTTPS"))
        self.assertTrue(f.link.startswith("https://"))

    def test_port_service(self):
        self.assertEqual(sv.port_service("host.example.com:443"), "443/TLS")
        self.assertEqual(sv.port_service("http://h:8080/"), "8080/HTTP")


if __name__ == "__main__":
    unittest.main()
