import unittest

from fuzzstorm import SecurityAnalyzer


class SecurityAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = SecurityAnalyzer()
        self.url = "http://example.com/"

    def test_detects_directory_listing_and_traceback(self):
        html = b"""
        <html>
            <title>Index of /</title>
            <body>Traceback (most recent call last): boom</body>
        </html>
        """

        findings = self.analyzer.scan_for_vulnerabilities(self.url, html, 200)
        types = {finding["type"] for finding in findings}

        self.assertIn("dir_listing", types)
        self.assertIn("stack_trace_python", types)
        self.assertIn(self.url, self.analyzer.findings)
        self.assertIn("vulnerabilities", self.analyzer.findings[self.url])

    def test_detects_version_leak_in_headers(self):
        content = b"healthy response body" * 10
        headers = {"Server": "nginx/1.23.0", "X-Powered-By": "PHP/8.2"}

        findings = self.analyzer.scan_for_vulnerabilities(self.url, content, 200, headers=headers)
        version_findings = [f for f in findings if f["type"] == "server_version"]

        self.assertEqual(len(version_findings), 2)
        self.assertTrue(any("nginx/1.23.0" in match for match in version_findings[0]["matches"]))

    def test_clean_response_does_not_raise_findings(self):
        content = b"safe content" * 50

        findings = self.analyzer.scan_for_vulnerabilities(self.url, content, 200)

        self.assertFalse(findings)
        self.assertNotIn(self.url, self.analyzer.findings)

    def test_techackz_results_are_recorded(self):
        technologies = [{"name": "nginx", "version": "1.25"}, "python"]
        vulnerabilities = [{"description": "CVE-1234"}, "CVE-5678"]

        self.analyzer.add_techackz_results(self.url, technologies, vulnerabilities, {"raw": True})

        self.assertIn(self.url, self.analyzer.findings)
        techackz = self.analyzer.findings[self.url].get("techackz")

        self.assertIsNotNone(techackz)
        self.assertEqual(techackz["technologies"], technologies)
        self.assertEqual(techackz["vulnerabilities"], vulnerabilities)


if __name__ == "__main__":
    unittest.main()
