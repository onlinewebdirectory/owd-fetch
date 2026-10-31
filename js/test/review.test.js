// Fixes from the pre-publication review: the client must never break the
// caller's fetch, never report something that is not true of the whole site,
// and never leak internal names.
import { test, beforeEach, after as afterAllTests } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { owdFetch, before, after, _reset } from "../src/index.js";
import { hostOf, loadOrCreateKey } from "../src/client.js";
import { classify } from "../src/classify.js";
import { startServer } from "./helpers/server.js";

const tmp = () => mkdtempSync(join(tmpdir(), "owd-"));
let dir, home, reply;
const sent = () => dir.requests.filter((r) => r.url === "/v1/observations").flatMap((r) => JSON.parse(r.body).observations);
const lookups = () => dir.requests.filter((r) => r.url.startsWith("/v1/origins/")).length;
const resp = (status, body, headers = {}, url) => {
  const r = new Response(body, { status, headers });
  if (url) Object.defineProperty(r, "url", { value: url });
  return r;
};
const opts = (fetchImpl, extra = {}) => ({ base: dir.base, home, fetch: fetchImpl, ...extra });

afterAllTests(async () => { await dir?.close(); });
beforeEach(async () => {
  await dir?.close(); _reset(); home = tmp();
  reply = (host) => ({ body: { host, strategy: { fetch: "plain_http" }, facts: [] } });
  dir = await startServer(({ method, url }) => {
    if (method === "POST" && url === "/v1/agents") return { status: 201, body: { handle: "agent_t", read_token: "tok" } };
    if (method === "POST" && url === "/v1/observations") return { status: 202, body: {} };
    return reply(decodeURIComponent(url.split("/").pop()));
  });
});

test("C1: badly shaped directory replies never break the fetch, and are not cached", async () => {
  for (const body of [{ host: "x", facts: { a: 1 } }, { facts: [null] }, { strategy: "plain" }, [1, 2], "text", { registry_check: [] }]) {
    _reset();
    reply = () => ({ body });
    const r = await owdFetch("https://shape.example/", undefined, opts(async () => resp(200, "ok")));
    assert.equal(r.status, 200);
    assert.deepEqual(r.owd.warnings.map((w) => w.code), ["directory_unavailable"], JSON.stringify(body));
  }
});

test("I2: a streaming response is not read by the client, and the caller can cancel it", async () => {
  let pulls = 0;
  const stream = new ReadableStream({ pull(c) { pulls++; c.enqueue(new TextEncoder().encode("data: x\n\n")); return new Promise((r) => setTimeout(r, 20)); } });
  const r = await owdFetch("https://sse.example/", undefined, opts(async () => resp(200, stream, { "content-type": "text/event-stream" })));
  const reader = r.body.getReader();
  await reader.read();
  await Promise.race([reader.cancel(), new Promise((_, no) => setTimeout(() => no(new Error("cancel hung")), 2000))]);
});

test("I2: an endless HTML body is read only for a bounded time", async () => {
  const stream = new ReadableStream({ pull(c) { c.enqueue(new TextEncoder().encode("<p>x</p>")); return new Promise((r) => setTimeout(r, 10)); } });
  const r = await owdFetch("https://slow.example/", undefined, opts(async () => resp(200, stream, { "content-type": "text/html" }), { bodyTimeoutMs: 200 }));
  const reported = await Promise.race([r.owd.reported, new Promise((_, no) => setTimeout(() => no(new Error("read never stopped")), 2000))]);
  assert.ok(reported);
  r.body.cancel();
});

test("I3: a custom fetch returning a plain object still works", async () => {
  const r = await owdFetch("https://plain.example/", undefined, opts(async () => Object.freeze({ status: 200, headers: {}, text: async () => "ok" })));
  assert.equal(r.status, 200);
});

test("I6: when the key cannot be saved, no agent is registered", async () => {
  const file = join(tmp(), "not-a-dir");
  writeFileSync(file, "x");
  assert.equal(await loadOrCreateKey({ home: join(file, "sub"), base: dir.base, register: true }), null);
  assert.equal(dir.requests.filter((r) => r.url === "/v1/agents").length, 0);
});

test("I7: only facts true of the whole site are reported", async () => {
  const run = async (url, r, init) => (await owdFetch(url, init, opts(async () => r))).owd.reported;
  await run("https://site.example/private/doc", resp(403, "denied", { "content-type": "text/html" }));
  await run("https://site.example/api/items", resp(401, ""));
  await run("https://site.example/api/items", resp(429, "", { "Retry-After": "5" }));
  await run("https://site.example/", resp(403, "denied", { "content-type": "text/html" }), { headers: { Authorization: "Bearer x" } });
  await run("https://site.example/", resp(403, "denied", { "content-type": "text/html" }), { headers: { Cookie: "a=1" } });
  await run("https://site.example/", resp(403, "denied", { "content-type": "text/html" }), { method: "POST" });
  await run("https://short.example/", resp(403, "<title>Just a moment...</title>", { "content-type": "text/html" }, "https://other.example/"));
  await run("https://forum.example/thread/1", resp(200, "<p>How do I get past Just a moment... and challenge-platform?</p>", { "content-type": "text/html" }));
  assert.deepEqual(sent(), []);
});

test("I7: the home page and a bot wall on any page are reported", async () => {
  await (await owdFetch("https://site.example/", undefined, opts(async () => resp(403, "denied", { "content-type": "text/html" })))).owd.reported;
  await (await owdFetch("https://wall.example/deep/page?q=1", undefined, opts(async () => resp(403, "<title>Just a moment...</title>", { "cf-mitigated": "challenge", "content-type": "text/html" })))).owd.reported;
  const got = sent().map((o) => `${o.host} ${o.kind}=${o.value}`).sort();
  assert.deepEqual(got, ["site.example access_posture=blocked", "site.example challenge_vendor=none", "wall.example access_posture=bot_challenged", "wall.example challenge_vendor=cloudflare"]);
});

test("I7: js_required is only judged from an HTML body, and after() passes the client class", async () => {
  await (await owdFetch("https://api.example/", undefined, opts(async () => resp(200, JSON.stringify({ a: "x".repeat(2000) }), { "content-type": "application/json" })))).owd.reported;
  assert.ok(!sent().some((o) => o.kind === "js_required"));
  await after("https://browser.example/", { status: 200, headers: { "content-type": "text/html" }, body: "<p>" + "w ".repeat(400) + "</p>" }, { base: dir.base, home, clientClass: "headless_chrome" });
  assert.ok(sent().filter((o) => o.host === "browser.example").every((o) => o.client_class === "headless_chrome"));
});

test("I8: internal and reserved names are never sent to the directory", () => {
  for (const u of ["https://jenkins.corp/", "https://nas.home.arpa/", "http://printer.local/", "https://foo.internal/", "http://box.lan/", "http://localhost.localdomain/", "https://a.test/", "https://b.invalid/", "https://c.localhost/"])
    assert.equal(hostOf(u), null, u);
  assert.equal(hostOf("https://g2.com/"), "g2.com");
});

test("I9: a failing directory is not asked on every fetch", async () => {
  reply = () => ({ status: 500, body: {} });
  for (let i = 0; i < 5; i++) await owdFetch(`https://down.example/${i}`, undefined, opts(async () => resp(200, "ok")));
  assert.equal(lookups(), 1);
});

test("I9: out of free lookups (402) stops lookups for the day", async () => {
  reply = () => ({ status: 402, body: {} });
  await owdFetch("https://a1.example/", undefined, opts(async () => resp(200, "ok")));
  await owdFetch("https://a2.example/", undefined, opts(async () => resp(200, "ok")));
  assert.equal(lookups(), 1);
});

test("minor: a strange prefer path is not passed through", async () => {
  reply = (host) => ({ body: { host, strategy: { fetch: "use_machine_interface", prefer: "//evil.example/x" }, facts: [] } });
  const b = await before("https://pref.example/", { base: dir.base, home });
  assert.deepEqual(b.warnings, [{ code: "machine_interface_available" }]);
});

test("minor: Retry-After parses like the server (leading digits)", () => {
  assert.equal(classify({ status: 429, headers: { "Retry-After": "30abc" }, body: "" }).retry_after_s, "30");
  assert.equal(classify({ status: 429, headers: { "Retry-After": "1_000" }, body: "" }).retry_after_s, "1000");
});
