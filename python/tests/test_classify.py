import json
import os
import unittest

from onlinewebdirectory.classify import classify

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "classify.json")


class ClassifyTest(unittest.TestCase):
    def test_every_server_case(self):
        for c in json.load(open(FIXTURES)):
            with self.subTest(c["name"]):
                self.assertEqual(c["expected"], classify(c["status"], c["headers"], c["body"], c["final_url"]))

    def test_headers_match_case_insensitively(self):
        self.assertEqual("cloudflare", classify(403, {"CF-Mitigated": "challenge"}, "", "https://x.example/")["challenge_vendor"])

    def test_huge_body_read_only_to_200000_chars(self):
        body = "a" * 1_000_000 + "Just a moment..."
        self.assertEqual("blocked", classify(503, {}, body, "https://x.example/")["access_posture"])


if __name__ == "__main__":
    unittest.main()
