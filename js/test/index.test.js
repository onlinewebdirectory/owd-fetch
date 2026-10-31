import { test, beforeEach, after as afterAllTests } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { owdFetch, before, after, OwdRefused, _reset } from "../src/index.js";
import { startServer } from "./helpers/server.js";

const tmp = () => mkdtempSync(join(tmpdir(), "owd-"));
const answer = (host, extra = {}) => ({ host, strategy: { fetch: "plain_http" }, facts: [], ...extra });
const ANSWERS = {
  "open.example": answer("open.example"),
  "robots.example": answer("robots.example", { strategy: { fetch: "plain_http", basis: "registry_check" }, registry_check: { values: { robots_posture: "disallow_all" } } }),
  "partial.example": answer("partial.example", { registry_check: { values: { robots_posture: "partial" } } }),
  "blocked.example": answer("blocked.example", { strategy: { fetch: "do_not_fetch", reason: "blocked" } }),
  "cf.example": answer("cf.example", { strategy: { fetch: "headless_required", expect_challenge: "cloudflare" } }),
  "llms.example": answer("llms.example", { strategy: { fetch: "use_machine_interface", prefer: "/llms.txt" } }),
  "unknown.example": answer("unknown.example", { strategy: { fetch: "unknown" } }),
  "crowdrobots.example": answer("crowdrobots.example", { facts: [{ kind: "robots_posture", value: "disallow_all", state: "verified" }] }),
};

let dir, home;
async function directory(delayMs = 0) {
  return startServer(async ({ method, url }) => {
    if (delayMs) await new Promise((r) => setTimeout(r, delayMs));
    if (method === "POST" && url === "/v1/agents") return { status: 201, body: { handle: "agent_t", read_token: "tok" } };
    if (method === "POST" && url === "/v1/observations") return { status: 202, body: {} };
    const host = decodeURIComponent(url.split("/").pop());
    return { body: ANSWERS[host] ?? answer(host, { strategy: { fetch: "unknown" } }) };
  });
}
const site = (status = 200, body = "<p>" + "words ".repeat(200) + "</p>", headers = {}) =>
  async () => new Response(body, { status, headers });
const opts = (extra = {}) => ({ base: dir.base, home, fetch: site(), ...extra });
const codes = (r) => r.owd.warnings.map((w) => w.code);
const sent = () => dir.requests.filter((r) => r.url === "/v1/observations").flatMap((r) => JSON.parse(r.body).observations);

afterAllTests(async () => { await dir?.close(); });
beforeEach(async () => { await dir?.close(); _reset(); dir = await directory(); home = tmp(); delete process.env.OWD_REPORT; });

test("robots disallow all is not fetched, unless forced", async () => {
  await assert.rejects(owdFetch("https://robots.example/x", undefined, opts()), (e) => e instanceof OwdRefused && e.host === "robots.example" && e.reason === "robots_disallow_all");
  const r = await owdFetch("https://robots.example/x", undefined, opts({ force: true }));
  assert.equal(r.status, 200);
});

test("crowd-verified robots disallow all is honoured too", async () => {
  await assert.rejects(owdFetch("https://crowdrobots.example/", undefined, opts()), OwdRefused);
});

test("a site that blocks agents is fetched with a warning", async () => {
  const r = await owdFetch("https://blocked.example/", undefined, opts());
  assert.deepEqual(codes(r), ["site_blocks_agents"]);
});

test("bot walls, machine interfaces and partial robots come back as warnings with details", async () => {
  const cf = await owdFetch("https://cf.example/", undefined, opts());
  assert.deepEqual(cf.owd.warnings, [{ code: "needs_browser", expect_challenge: "cloudflare" }]);
  const llms = await owdFetch("https://llms.example/", undefined, opts());
  assert.deepEqual(llms.owd.warnings, [{ code: "machine_interface_available", path: "/llms.txt" }]);
  assert.deepEqual(codes(await owdFetch("https://partial.example/", undefined, opts())), ["robots_partial"]);
});

test("every answer carries the site's directory page, so an agent can cite it", async () => {
  const r = await owdFetch("https://cf.example/", undefined, opts());
  assert.equal(r.owd.page, `${dir.base}/sites/cf.example`);
  const b = await before("https://cf.example/", { base: dir.base, home });
  assert.equal(b.page, `${dir.base}/sites/cf.example`);
});

test("an unknown site and an open site fetch with no warnings", async () => {
  assert.deepEqual(codes(await owdFetch("https://unknown.example/", undefined, opts())), []);
  assert.deepEqual(codes(await owdFetch("https://open.example/", undefined, opts())), []);
});

test("the directory being down never stops the fetch", async () => {
  await dir.close();
  const r = await owdFetch("https://open.example/", undefined, opts({ timeoutMs: 200 }));
  assert.equal(r.status, 200);
  assert.deepEqual(codes(r), ["directory_unavailable"]);
});

test("a slow directory times out and the fetch goes ahead", async () => {
  await dir.close(); dir = await directory(1000);
  const r = await owdFetch("https://open.example/", undefined, opts({ timeoutMs: 100 }));
  assert.deepEqual(codes(r), ["directory_unavailable"]);
});

test("concurrent first calls to one host make one lookup, and later calls use the cache", async () => {
  await Promise.all([1, 2, 3].map(() => owdFetch("https://open.example/a", undefined, opts())));
  await owdFetch("https://open.example/b", undefined, opts());
  assert.equal(dir.requests.filter((r) => r.url === "/v1/origins/open.example").length, 1);
});

test("the caller can still read the body after classification", async () => {
  const r = await owdFetch("https://open.example/", undefined, opts());
  assert.match(await r.text(), /words/);
  await r.owd.reported;
});

test("a Cloudflare challenge is reported once, signed, even when fetched twice", async () => {
  const wall = opts({ fetch: site(403, "<title>Just a moment...</title>", { "cf-mitigated": "challenge" }) });
  await (await owdFetch("https://open.example/", undefined, wall)).owd.reported;
  await (await owdFetch("https://open.example/", undefined, wall)).owd.reported;
  const obs = sent();
  assert.deepEqual(obs.map((o) => `${o.kind}=${o.value}`).sort(), ["access_posture=bot_challenged", "challenge_vendor=cloudflare"]);
  assert.ok(obs.every((o) => o.host === "open.example" && o.signature));
});

test("reporting can be switched off by option or environment", async () => {
  await (await owdFetch("https://open.example/", undefined, opts({ report: false }))).owd.reported;
  process.env.OWD_REPORT = "0";
  await (await owdFetch("https://open.example/", undefined, opts())).owd.reported;
  assert.equal(sent().length, 0);
  assert.equal(dir.requests.filter((r) => r.url === "/v1/agents").length, 0);
});

test("a 404 reports nothing", async () => {
  await (await owdFetch("https://open.example/", undefined, opts({ fetch: site(404, "nope") }))).owd.reported;
  assert.equal(sent().length, 0);
});

test("IP addresses are fetched without asking the directory", async () => {
  const r = await owdFetch("http://10.0.0.1/", undefined, opts());
  assert.equal(r.status, 200);
  assert.equal(dir.requests.length, 0);
});

test("before and after work on their own for any HTTP client", async () => {
  const b = await before("https://robots.example/", { base: dir.base, home });
  assert.equal(b.fetch, false);
  const facts = await after("https://open.example/", { status: 429, headers: { "Retry-After": "60" }, body: "" }, { base: dir.base, home });
  assert.deepEqual(facts, { access_posture: "rate_limited", retry_after_s: "60" });
});
