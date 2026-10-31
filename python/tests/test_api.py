import json
import os
import tempfile
import unittest

import onlinewebdirectory as owd
from tests.helpers import start_server


def answer(host, **extra):
    a = {"host": host, "strategy": {"fetch": "plain_http"}, "facts": []}
    a.update(extra)
    return a


ANSWERS = {
    "open.example": answer("open.example"),
    "robots.example": answer("robots.example", registry_check={"values": {"robots_posture": "disallow_all"}}),
    "crowdrobots.example": answer("crowdrobots.example", facts=[{"kind": "robots_posture", "value": "disallow_all", "state": "verified"}]),
    "partial.example": answer("partial.example", registry_check={"values": {"robots_posture": "partial"}}),
    "blocked.example": answer("blocked.example", strategy={"fetch": "do_not_fetch", "reason": "blocked"}),
    "cf.example": answer("cf.example", strategy={"fetch": "headless_required", "expect_challenge": "cloudflare"}),
    "llms.example": answer("llms.example", strategy={"fetch": "use_machine_interface", "prefer": "/llms.txt"}),
    "unknown.example": answer("unknown.example", strategy={"fetch": "unknown"}),
}


def site(status=200, body="<p>" + "words " * 200 + "</p>", headers=None):
    def fetch(url, headers_in=None, timeout=None):
        return owd.Response(status=status, headers=headers or {}, text=body, url=url)
    return fetch


class ApiTest(unittest.TestCase):
    def setUp(self):
        owd._reset()
        os.environ.pop("OWD_REPORT", None)
        self.delay = 0

        def handle(r):
            if r["method"] == "POST" and r["url"] == "/v1/agents":
                return {"status": 201, "body": {"handle": "agent_t", "read_token": "tok"}}
            if r["method"] == "POST" and r["url"] == "/v1/observations":
                return {"status": 202, "body": {}}
            host = r["url"].rsplit("/", 1)[1]
            return {"delay": self.delay, "body": ANSWERS.get(host, answer(host, strategy={"fetch": "unknown"}))}

        self.base, self.reqs, self._close = start_server(handle)
        self.home = tempfile.mkdtemp()
        self.addCleanup(self._close)

    def opts(self, **extra):
        o = {"base": self.base, "home": self.home, "fetch": site()}
        o.update(extra)
        return o

    def codes(self, r):
        return [w["code"] for w in r.owd["warnings"]]

    def sent(self):
        return [o for r in self.reqs if r["url"] == "/v1/observations" for o in json.loads(r["body"])["observations"]]

    def test_robots_disallow_all_refused_unless_forced(self):
        with self.assertRaises(owd.Refused) as e:
            owd.get("https://robots.example/x", **self.opts())
        self.assertEqual("robots.example", e.exception.host)
        self.assertEqual("robots_disallow_all", e.exception.reason)
        self.assertEqual(200, owd.get("https://robots.example/x", force=True, **self.opts()).status)
        with self.assertRaises(owd.Refused):
            owd.get("https://crowdrobots.example/", **self.opts())

    def test_warnings(self):
        self.assertEqual(["site_blocks_agents"], self.codes(owd.get("https://blocked.example/", **self.opts())))
        self.assertEqual([{"code": "needs_browser", "expect_challenge": "cloudflare"}], owd.get("https://cf.example/", **self.opts()).owd["warnings"])
        self.assertEqual([{"code": "machine_interface_available", "path": "/llms.txt"}], owd.get("https://llms.example/", **self.opts()).owd["warnings"])
        self.assertEqual(["robots_partial"], self.codes(owd.get("https://partial.example/", **self.opts())))
        self.assertEqual([], self.codes(owd.get("https://unknown.example/", **self.opts())))
        self.assertEqual([], self.codes(owd.get("https://open.example/", **self.opts())))

    def test_page_link_for_citing(self):
        r = owd.get("https://cf.example/", **self.opts())
        self.assertEqual(self.base + "/sites/cf.example", r.owd["page"])

    def test_directory_down_or_slow_never_stops_the_fetch(self):
        self.delay = 1.0
        r = owd.get("https://open.example/", timeout=0.2, **self.opts())
        self.assertEqual(200, r.status)
        self.assertEqual(["directory_unavailable"], self.codes(r))

    def test_lookup_cached_per_host(self):
        owd.get("https://open.example/a", **self.opts())
        owd.get("https://open.example/b", **self.opts())
        self.assertEqual(1, len([r for r in self.reqs if r["url"] == "/v1/origins/open.example"]))

    def test_challenge_reported_once_signed(self):
        wall = self.opts(fetch=site(403, "<title>Just a moment...</title>", {"cf-mitigated": "challenge"}))
        owd.get("https://open.example/", **wall).owd["reported"].result(5)
        owd.get("https://open.example/", **wall).owd["reported"].result(5)
        self.assertEqual(["access_posture=bot_challenged", "challenge_vendor=cloudflare"], sorted(f"{o['kind']}={o['value']}" for o in self.sent()))

    def test_report_off_and_404(self):
        owd.get("https://open.example/", report=False, **self.opts()).owd["reported"].result(5)
        os.environ["OWD_REPORT"] = "0"
        owd.get("https://open.example/", **self.opts()).owd["reported"].result(5)
        os.environ.pop("OWD_REPORT")
        owd.get("https://open.example/", **self.opts(fetch=site(404, "nope"))).owd["reported"].result(5)
        self.assertEqual([], self.sent())
        self.assertEqual([], [r for r in self.reqs if r["url"] == "/v1/agents"])

    def test_ip_fetched_without_lookup(self):
        self.assertEqual(200, owd.get("http://10.0.0.1/", **self.opts()).status)
        self.assertEqual([], self.reqs)

    def test_without_cryptography_it_still_fetches_but_does_not_report(self):
        from onlinewebdirectory import client
        client.CAN_SIGN, saved = False, client.CAN_SIGN
        try:
            r = owd.get("https://cf.example/", **self.opts(fetch=site(403, "<title>Just a moment...</title>")))
            self.assertEqual(403, r.status)
            self.assertEqual("needs_browser", r.owd["warnings"][0]["code"])
            r.owd["reported"].result(5)
            self.assertEqual([], self.sent())
        finally:
            client.CAN_SIGN = saved

    def test_before_and_after_alone(self):
        self.assertFalse(owd.before("https://robots.example/", base=self.base, home=self.home)["fetch"])
        facts = owd.after("https://open.example/", 429, {"Retry-After": "60"}, "", base=self.base, home=self.home)
        self.assertEqual({"access_posture": "rate_limited", "retry_after_s": "60"}, facts)


if __name__ == "__main__":
    unittest.main()
