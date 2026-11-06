import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPublicKey, verify } from "node:crypto";
import { hostOf, loadOrCreateKey, lookup, report, keyFileFor } from "../src/client.js";
import { startServer } from "./helpers/server.js";

const tmp = () => mkdtempSync(join(tmpdir(), "owd-"));
const directory = () => startServer(({ method, url }) => {
  if (method === "POST" && url === "/v1/agents") return { status: 201, body: { handle: "agent_test", read_token: "tok123" } };
  if (method === "GET" && url.startsWith("/v1/origins/")) return { body: { host: decodeURIComponent(url.split("/").pop()), strategy: { fetch: "plain_http" } } };
  if (method === "POST" && url === "/v1/observations") return { status: 202, body: { accepted: 1 } };
  return { status: 404 };
});

test("hostOf gives the bare lowercase hostname, and null for IP literals", () => {
  assert.equal(hostOf("https://user:pw@WWW.Example.COM:8443/a?b=1"), "www.example.com");
  assert.equal(hostOf("https://example.com./x"), "example.com");
  assert.equal(hostOf("http://1.2.3.4/x"), null);
  assert.equal(hostOf("http://[::1]:3000/"), null);
  assert.equal(hostOf("not a url"), null);
});

test("a key is registered once, saved with mode 600, then reused", async () => {
  const s = await directory(); const home = tmp();
  const k1 = await loadOrCreateKey({ home, base: s.base, register: true, source: "owd-fetch-js" });
  const k2 = await loadOrCreateKey({ home, base: s.base, register: true, source: "owd-fetch-js" });
  assert.equal(k1.read_token, "tok123");
  assert.equal(k2.public_key, k1.public_key);
  assert.equal(s.requests.filter((r) => r.url === "/v1/agents").length, 1);
  assert.equal(JSON.parse(s.requests[0].body).source, "owd-fetch-js");
  assert.equal(statSync(keyFileFor(home, s.base)).mode & 0o777, 0o600);
  await s.close();
});

test("without register, no key is made", async () => {
  assert.equal(await loadOrCreateKey({ home: tmp(), base: "http://127.0.0.1:9", register: false }), null);
});

test("a corrupt key file is left alone and no key is used", async () => {
  const s = await directory(); const home = tmp();
  writeFileSync(keyFileFor(home, s.base), "{not json");
  assert.equal(await loadOrCreateKey({ home, base: s.base, register: true }), null);
  assert.equal(readFileSync(keyFileFor(home, s.base), "utf8"), "{not json");
  assert.equal(s.requests.length, 0);
  await s.close();
});

test("lookup sends only the host, with the read token when there is a key", async () => {
  const s = await directory();
  const r = await lookup("example.com", { base: s.base, key: { read_token: "tok123" }, timeoutMs: 1500 });
  assert.equal(r.ok, true);
  assert.equal(r.data.strategy.fetch, "plain_http");
  assert.equal(s.requests[0].url, "/v1/origins/example.com");
  assert.equal(s.requests[0].headers["x-agent-token"], "tok123");
  await s.close();
});

test("lookup fails open on a timeout, a 402 and a 500", async () => {
  for (const out of [{ hang: true }, { status: 402, body: {} }, { status: 500, body: {} }]) {
    const s = await startServer(() => out);
    const r = await lookup("example.com", { base: s.base, timeoutMs: 200 });
    assert.equal(r.ok, false);
    await s.close();
  }
});

test("report signs one observation per fact, verifiable with the public key", async () => {
  const s = await directory(); const home = tmp();
  const key = await loadOrCreateKey({ home, base: s.base, register: true });
  const ok = await report("example.com", { access_posture: "bot_challenged", challenge_vendor: "cloudflare" }, { base: s.base, key });
  assert.equal(ok, true);
  const body = JSON.parse(s.requests.find((r) => r.url === "/v1/observations").body);
  assert.equal(body.public_key, key.public_key);
  assert.equal(body.observations.length, 2);
  const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(key.public_key, "base64").toString("base64url") }, format: "jwk" });
  for (const o of body.observations) {
    assert.equal(o.host, "example.com");
    assert.equal(o.client_class, "plain_http");
    assert.match(o.observed_at, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
    const payload = [o.host, o.kind, o.value, o.client_class, o.observed_at].join("\n");
    assert.ok(verify(null, Buffer.from(payload), pub, Buffer.from(o.signature, "base64")), o.kind);
    assert.deepEqual(Object.keys(o).sort(), ["client_class", "host", "kind", "observed_at", "signature", "value"]);
  }
  await s.close();
});
