import base64
import json
import os
import stat
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from onlinewebdirectory import client
from tests.helpers import start_server


def directory():
    def handle(r):
        if r["method"] == "POST" and r["url"] == "/v1/agents":
            return {"status": 201, "body": {"handle": "agent_test", "read_token": "tok123"}}
        if r["method"] == "GET" and r["url"].startswith("/v1/origins/"):
            return {"body": {"host": r["url"].rsplit("/", 1)[1], "strategy": {"fetch": "plain_http"}}}
        if r["method"] == "POST" and r["url"] == "/v1/observations":
            return {"status": 202, "body": {"accepted": 1}}
        return {"status": 404}
    return start_server(handle)


class ClientTest(unittest.TestCase):
    def test_host_of(self):
        self.assertEqual("www.example.com", client.host_of("https://user:pw@WWW.Example.COM:8443/a?b=1"))
        self.assertEqual("example.com", client.host_of("https://example.com./x"))
        self.assertIsNone(client.host_of("http://1.2.3.4/x"))
        self.assertIsNone(client.host_of("http://[::1]:3000/"))
        self.assertIsNone(client.host_of("not a url"))

    def test_key_registered_once_saved_600_and_reused(self):
        base, reqs, close = directory(); home = tempfile.mkdtemp()
        try:
            k1 = client.load_or_create_key(home=home, base=base, register=True)
            k2 = client.load_or_create_key(home=home, base=base, register=True)
            self.assertEqual("tok123", k1["read_token"])
            self.assertEqual(k1["public_key"], k2["public_key"])
            self.assertEqual(1, len([r for r in reqs if r["url"] == "/v1/agents"]))
            self.assertEqual("owd-fetch-py", json.loads(reqs[0]["body"])["source"])
            self.assertEqual(0o600, stat.S_IMODE(os.stat(client.key_file_for(home, base)).st_mode))
        finally:
            close()

    def test_no_key_without_register(self):
        self.assertIsNone(client.load_or_create_key(home=tempfile.mkdtemp(), base="http://127.0.0.1:9", register=False))

    def test_corrupt_key_file_left_alone(self):
        base, reqs, close = directory(); home = tempfile.mkdtemp()
        try:
            path = client.key_file_for(home, base)
            open(path, "w").write("{not json")
            self.assertIsNone(client.load_or_create_key(home=home, base=base, register=True))
            self.assertEqual("{not json", open(path).read())
            self.assertEqual([], reqs)
        finally:
            close()

    def test_lookup_sends_only_host_and_token(self):
        base, reqs, close = directory()
        try:
            r = client.lookup("example.com", base=base, key={"read_token": "tok123"}, timeout=1.5)
            self.assertTrue(r["ok"])
            self.assertEqual("/v1/origins/example.com", reqs[0]["url"])
            self.assertEqual("tok123", reqs[0]["headers"]["x-agent-token"])
        finally:
            close()

    def test_lookup_fails_open(self):
        for out in [{"delay": 1.0}, {"status": 402, "body": {}}, {"status": 500, "body": {}}]:
            base, _, close = start_server(lambda r, out=out: out)
            try:
                self.assertFalse(client.lookup("example.com", base=base, timeout=0.2)["ok"])
            finally:
                close()

    def test_report_signs_each_fact(self):
        base, reqs, close = directory(); home = tempfile.mkdtemp()
        try:
            key = client.load_or_create_key(home=home, base=base, register=True)
            self.assertTrue(client.report("example.com", {"access_posture": "bot_challenged", "challenge_vendor": "cloudflare"}, base=base, key=key))
            body = json.loads([r for r in reqs if r["url"] == "/v1/observations"][0]["body"])
            pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(key["public_key"]))
            self.assertEqual(2, len(body["observations"]))
            for o in body["observations"]:
                self.assertRegex(o["observed_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
                payload = "\n".join([o["host"], o["kind"], o["value"], o["client_class"], o["observed_at"]]).encode()
                pub.verify(base64.b64decode(o["signature"]), payload)
                self.assertEqual(sorted(o), ["client_class", "host", "kind", "observed_at", "signature", "value"])
        finally:
            close()

    def test_key_file_shared_with_javascript_format(self):
        base, _, close = directory(); home = tempfile.mkdtemp()
        try:
            client.load_or_create_key(home=home, base=base, register=True)
            saved = json.load(open(client.key_file_for(home, base)))
            self.assertTrue({"public_key", "private_pem", "handle", "read_token"} <= set(saved))
            self.assertTrue(saved["private_pem"].startswith("-----BEGIN PRIVATE KEY-----"))
        finally:
            close()


if __name__ == "__main__":
    unittest.main()
