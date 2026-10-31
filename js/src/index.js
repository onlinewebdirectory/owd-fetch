// Check before fetch. owdFetch(url) asks Online Web Directory how the site
// treats agents, fetches it (unless robots.txt tells every agent to stay out),
// and reports what it saw in the background. It never breaks the fetch: if the
// directory is slow, down or out of free lookups, the fetch just goes ahead.
import { classify, MAX_CHARS } from "./classify.js";
import { DEFAULT_BASE, defaultHome, hostOf, loadOrCreateKey, lookup, report } from "./client.js";

const LOOKUP_TTL_MS = 60 * 60 * 1000;
const REPORT_TTL_MS = 6 * 60 * 60 * 1000;
const lookups = new Map(); // host -> { at, promise }
const reported = new Map(); // host|kind|value -> at

export class OwdRefused extends Error {
  constructor(host, reason, strategy, page) {
    super(`${host}: robots.txt tells all agents to stay out; not fetched (see ${page}; pass { force: true } to fetch anyway)`);
    this.name = "OwdRefused";
    this.host = host;
    this.reason = reason;
    this.strategy = strategy;
    this.page = page;
  }
}

/** For tests: forget cached lookups and sent reports. */
export function _reset() { lookups.clear(); reported.clear(); }

const settings = (o = {}) => ({
  base: (o.base || process.env.OWD_BASE || DEFAULT_BASE).replace(/\/$/, ""),
  home: o.home || defaultHome(),
  timeoutMs: o.timeoutMs ?? 3000,
  report: o.report !== false && process.env.OWD_REPORT !== "0",
  lookup: o.lookup !== false,
  force: !!o.force,
});

function cachedLookup(host, s) {
  const hit = lookups.get(host);
  if (hit && Date.now() - hit.at < LOOKUP_TTL_MS) return hit.promise;
  const promise = loadOrCreateKey({ home: s.home, base: s.base, register: false })
    .then((key) => lookup(host, { base: s.base, key, timeoutMs: s.timeoutMs }))
    .then((r) => { if (!r.ok) lookups.delete(host); return r; }); // a failed lookup is retried next time
  lookups.set(host, { at: Date.now(), promise });
  return promise;
}

const USABLE = new Set(["verified", "stale"]);
function robotsPosture(data) {
  const crowd = (data.facts || []).find((f) => f.kind === "robots_posture" && USABLE.has(f.state));
  return crowd?.value ?? data.registry_check?.values?.robots_posture ?? null;
}

/**
 * What the directory knows about a site, without fetching it.
 * @returns {Promise<{fetch: boolean, host: string|null, page: string|null, strategy: object|null, warnings: object[], reason?: string}>}
 */
export async function before(url, options = {}) {
  const s = settings(options);
  const host = hostOf(url);
  if (!host || !s.lookup) return { fetch: true, host, page: null, strategy: null, warnings: [] };
  const page = `${s.base}/sites/${host}`;

  const r = await cachedLookup(host, s);
  if (!r.ok) return { fetch: true, host, page, strategy: null, warnings: [{ code: "directory_unavailable" }] };

  const strategy = r.data.strategy || { fetch: "unknown" };
  const warnings = [];
  const robots = robotsPosture(r.data);
  if (robots === "disallow_all" && !s.force) return { fetch: false, host, page, strategy, warnings, reason: "robots_disallow_all" };
  if (robots === "partial") warnings.push({ code: "robots_partial" });
  if (strategy.fetch === "do_not_fetch") warnings.push({ code: "site_blocks_agents", reason: strategy.reason });
  if (strategy.fetch === "headless_required") warnings.push({ code: "needs_browser", ...(strategy.expect_challenge ? { expect_challenge: strategy.expect_challenge } : {}) });
  if (strategy.fetch === "use_machine_interface") warnings.push({ code: "machine_interface_available", path: strategy.prefer });
  return { fetch: true, host, page, strategy, warnings };
}

/**
 * Classify a response you fetched yourself and report it (deduplicated).
 * @returns {Promise<object>} the facts that were reported
 */
export async function after(url, { status, headers, body, finalUrl } = {}, options = {}) {
  const s = settings(options);
  const host = hostOf(url);
  if (!host || !s.report) return {};
  const facts = classify({ status, headers, body, finalUrl: finalUrl || url });
  const now = Date.now();
  const fresh = Object.fromEntries(Object.entries(facts).filter(([kind, value]) => {
    const k = `${host}|${kind}|${value}`;
    if (now - (reported.get(k) ?? 0) < REPORT_TTL_MS) return false;
    reported.set(k, now);
    return true;
  }));
  if (!Object.keys(fresh).length) return {};
  const forget = () => { for (const [kind, value] of Object.entries(fresh)) reported.delete(`${host}|${kind}|${value}`); };
  try {
    const key = await loadOrCreateKey({ home: s.home, base: s.base, register: true, source: "owd-fetch-js" });
    if (!key || !(await report(host, fresh, { base: s.base, key }))) { forget(); return {}; }
    return fresh;
  } catch (e) {
    forget();
    if (process.env.OWD_DEBUG === "1") console.error("owd report failed:", e);
    return {};
  }
}

// The first MAX_CHARS characters of a body, without reading the rest.
async function readPrefix(res) {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let text = "";
  try {
    while (text.length < MAX_CHARS) {
      const { done, value } = await reader.read();
      if (done) break;
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    reader.cancel().catch(() => {});
  }
  return text.slice(0, MAX_CHARS);
}

/**
 * fetch, with the directory consulted before and told after.
 * Same arguments as fetch, plus options: force, report, lookup, timeoutMs, base, home, fetch.
 * @returns {Promise<Response & {owd: {page: string|null, strategy: object|null, warnings: object[], reported: Promise<object>}}>}
 */
export async function owdFetch(input, init, options = {}) {
  const url = typeof input === "string" ? input : input?.url ?? String(input);
  const b = await before(url, options);
  if (!b.fetch) throw new OwdRefused(b.host, b.reason, b.strategy, b.page);

  const doFetch = options.fetch || globalThis.fetch;
  const res = await doFetch(input, init);
  let reportedPromise = Promise.resolve({});
  if (settings(options).report && b.host) {
    const copy = res.clone();
    reportedPromise = readPrefix(copy)
      .then((body) => after(url, { status: res.status, headers: res.headers, body, finalUrl: res.url || url }, options))
      .catch(() => ({}));
  }
  res.owd = { page: b.page, strategy: b.strategy, warnings: b.warnings, reported: reportedPromise };
  return res;
}
