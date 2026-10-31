import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { classify } from "../src/classify.js";

const cases = JSON.parse(readFileSync(new URL("../../fixtures/classify.json", import.meta.url), "utf8"));

for (const c of cases) {
  test(`classify matches the server: ${c.name}`, () => {
    assert.deepEqual(classify({ status: c.status, headers: c.headers, body: c.body, finalUrl: c.final_url }), c.expected);
  });
}

test("headers may be a Headers object, matched case-insensitively", () => {
  const headers = new Headers({ "CF-Mitigated": "challenge" });
  assert.equal(classify({ status: 403, headers, body: "", finalUrl: "https://x.example/" }).challenge_vendor, "cloudflare");
});

test("a huge body is only read to 200,000 characters for walls", () => {
  const body = "a".repeat(1_000_000) + "Just a moment...";
  assert.equal(classify({ status: 503, headers: {}, body, finalUrl: "https://x.example/" }).access_posture, "blocked");
});
