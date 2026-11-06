"""Fixes from the pre-publication review, mirroring js/test/review.test.js."""
import json
import os
import tempfile
import time
import unittest

import onlinewebdirectory as owd
from onlinewebdirectory import client
from onlinewebdirectory.classify import classify
from tests.helpers import start_server


def resp(status, body="", headers=None, url=None):
    def fetch(u, headers_in=None, timeout=None):
        return owd.Response(status=status, headers=headers or {}, text=body, url=url or u)
    return fetch


class ReviewTest(unittest.TestCase):
    def setUp(self):
        owd._reset()
        self.reply = lambda host: {"body": {"host": host, "strategy": {"fetch": "plain_http"}, "facts": []}}

        def handle(r):
            if r["method"] == "POST" and r["url"] == "/v1/agents":
                return {"status": 201, "body": {"handle": "agent_t", "read_token": "tok"}}
            if r["method"] == "POST" and r["url"] == "/v1/observations":
                return {"status": 202, "body": {}}
            return self.reply(r["url"].rsplit("/", 1)[1])

        self.base, self.reqs, close = start_server(handle)
        self.addCleanup(close)
        self.home = tempfile.mkdtemp()

    def opts(self, fetch, **extra):
        o = {"base": self.base, "home": self.home, "fetch": fetch}
        o.update(extra)
        return o

    def sent(self):
        return [o for r in self.reqs if r["url"] == "/v1/observations" for o in json.loads(r["body"])["observations"]]

    def lookups(self):
        return len([r for r in self.reqs if r["url"].startswith("/v1/origins/")])

    def test_C1_odd_replies_never_break_the_fetch(self):
        for body in [[1, 2], "text", {"facts": "x"}, {"facts": {"a": 1}}, {"facts": [None]}, {"strategy": "plain"}, {"registry_check": []}]:
            owd._reset()
            self.reply = lambda host, body=body: {"body": body}
            r = owd.get("https://shape.example/", **self.opts(resp(200, "ok")))
            self.assertEqual(200, r.status)
            self.assertEqual(["directory_unavailable"], [w["code"] for w in r.owd["warnings"]], body)

    def test_I1_corrupt_key_files_never_break_the_fetch(self):
        for content in ["null", "[]", '"x"', '{"public_key": "a", "private_pem": 5}', '{"public_key": "a", "private_pem": "not a pem"}']:
            owd._reset()
            home = tempfile.mkdtemp()
            open(client.key_file_for(home, self.base), "w").write(content)
            r = owd.get("https://k.example/", base=self.base, home=home, fetch=resp(200, "ok"))
            self.assertEqual(200, r.status, content)

    def test_I4_get_during_shutdown_does_not_raise(self):
        real = owd._pool_submit
        owd._pool_submit = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("cannot schedule new futures after interpreter shutdown"))
        try:
            r = owd.get("https://site.example/", **self.opts(resp(403, "x", {"content-type": "text/html"})))
            self.assertEqual({}, r.owd["reported"].result(1))
        finally:
            owd._pool_submit = real

    def test_I5_reports_run_on_a_daemon_thread_with_a_bounded_queue(self):
        self.assertTrue(owd._worker_is_daemon())
        self.assertGreater(owd._QUEUE_MAX, 0)

    def test_I6_no_registration_when_the_key_cannot_be_saved(self):
        f = os.path.join(tempfile.mkdtemp(), "file")
        open(f, "w").write("x")
        self.assertIsNone(client.load_or_create_key(home=os.path.join(f, "sub"), base=self.base, register=True))
        self.assertEqual([], [r for r in self.reqs if r["url"] == "/v1/agents"])

    def test_I7_only_site_wide_facts(self):
        html = {"content-type": "text/html"}
        cases = [
            ("https://site.example/private/doc", resp(403, "denied", html), {}),
            ("https://site.example/api/items", resp(401, ""), {}),
            ("https://site.example/", resp(403, "denied", html), {"headers": {"Authorization": "Bearer x"}}),
            ("https://site.example/", resp(403, "denied", html), {"headers": {"Cookie": "a=1"}}),
            ("https://short.example/", resp(403, "<title>Just a moment...</title>", html, "https://other.example/"), {}),
            ("https://forum.example/thread/1", resp(200, "<p>Just a moment... challenge-platform</p>", html), {}),
        ]
        for url, fetch, extra in cases:
            owd.get(url, **self.opts(fetch), **extra).owd["reported"].result(5)
        self.assertEqual([], self.sent())
        owd.get("https://site.example/", **self.opts(resp(403, "denied", html))).owd["reported"].result(5)
        owd.get("https://wall.example/deep?q=1", **self.opts(resp(403, "<title>Just a moment...</title>", {"cf-mitigated": "challenge", **html}))).owd["reported"].result(5)
        got = sorted(f"{o['host']} {o['kind']}={o['value']}" for o in self.sent())
        self.assertEqual(["site.example access_posture=blocked", "site.example challenge_vendor=none",
                          "wall.example access_posture=bot_challenged", "wall.example challenge_vendor=cloudflare"], got)

    def test_I7_js_required_only_from_html_and_client_class_passed(self):
        owd.get("https://api.example/", **self.opts(resp(200, json.dumps({"a": "x" * 2000}), {"content-type": "application/json"}))).owd["reported"].result(5)
        self.assertFalse(any(o["kind"] == "js_required" for o in self.sent()))
        owd.after("https://browser.example/", 200, {"content-type": "text/html"}, "<p>" + "w " * 400 + "</p>", base=self.base, home=self.home, client_class="headless_chrome")
        self.assertTrue(all(o["client_class"] == "headless_chrome" for o in self.sent() if o["host"] == "browser.example"))

    def test_I8_private_names_never_sent(self):
        for u in ["https://jenkins.corp/", "https://nas.home.arpa/", "http://printer.local/", "https://foo.internal/", "http://box.lan/",
                  "http://localhost.localdomain/", "https://a.test/", "https://b.invalid/", "https://c.localhost/"]:
            self.assertIsNone(client.host_of(u), u)
        self.assertEqual("xn--bcher-kva.de", client.host_of("https://bücher.de/"))

    def test_I9_a_failing_directory_is_not_asked_every_time(self):
        self.reply = lambda host: {"status": 500, "body": {}}
        for i in range(5):
            owd.get(f"https://down.example/{i}", **self.opts(resp(200, "ok")))
        self.assertEqual(1, self.lookups())

    def test_I9_402_stops_lookups_for_the_day(self):
        self.reply = lambda host: {"status": 402, "body": {}}
        owd.get("https://a1.example/", **self.opts(resp(200, "ok")))
        owd.get("https://a2.example/", **self.opts(resp(200, "ok")))
        self.assertEqual(1, self.lookups())

    def test_I10_redirects_drop_credentials_across_hosts(self):
        h = owd._SafeRedirect()
        import urllib.request
        req = urllib.request.Request("https://a.example/x", headers={"Authorization": "Bearer t", "Cookie": "c=1", "X-Other": "1"})
        new = h.redirect_request(req, None, 302, "Found", {}, "https://b.example/y")
        self.assertIsNone(new.get_header("Authorization"))
        self.assertIsNone(new.get_header("Cookie"))
        same = h.redirect_request(req, None, 302, "Found", {}, "https://a.example/z")
        self.assertEqual("Bearer t", same.get_header("Authorization"))

    def test_minor_prefer_path_and_retry_after_and_bytes(self):
        self.reply = lambda host: {"body": {"host": host, "strategy": {"fetch": "use_machine_interface", "prefer": "//evil.example/x"}, "facts": []}}
        self.assertEqual([{"code": "machine_interface_available"}], owd.before("https://pref.example/", base=self.base, home=self.home)["warnings"])
        self.assertEqual("30", classify(429, {"Retry-After": "30abc"}, "", "")["retry_after_s"])
        self.assertEqual("1000", classify(429, {"Retry-After": "1_000"}, "", "")["retry_after_s"])
        self.assertEqual("bot_challenged", classify(503, {}, b"<title>Just a moment...</title>", "")["access_posture"])


if __name__ == "__main__":
    unittest.main()


class MinorTest(unittest.TestCase):
    def test_key_file_per_directory_address(self):
        self.assertEqual(os.path.join("/h", "key.json"), client.key_file_for("/h", "https://onlinewebdirectory.net"))
        self.assertEqual(os.path.join("/h", "key-127.0.0.1-4000.json"), client.key_file_for("/h", "http://127.0.0.1:4000"))

    def test_mistyped_option_warns(self):
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            owd._settings(timeout_ms=5)
        self.assertTrue(any("timeout_ms" in str(x.message) for x in w))
