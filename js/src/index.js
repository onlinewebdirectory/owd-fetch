// Check before fetch. owdFetch(url) asks Online Web Directory how the site
// treats agents, fetches it (unless robots.txt tells every agent to stay out),
// and reports what it saw in the background. It never breaks the fetch: if the
// directory is slow, down, out of free lookups or answers something odd, the
// fetch just goes ahead.
import { classify, MAX_CHARS } from "./classify.js";
import { DEFAULT_BASE, defaultHome, hostOf, loadOrCreateKey, lookup, report, _resetClient } from "./client.js";

const LOOKUP_TTL_MS = 60 * 60 * 1000;
const FAILURE_TTL_MS = 60 * 1000;
const REPORT_TTL_MS = 6 * 60 * 60 * 1000;
const MAX_ENTRIES = 10_000;
const lookups = new Map(); // host -> { at, ttl, promise }
const reported = new Map(); // host|kind|value -> at
let quotaUntil = 0; // out of free lookups: no lookups until the next UTC day

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

/** For tests: forget cached lookups, sent reports and backoffs. */
export function _reset() { lookups.clear(); reported.clear(); quotaUntil = 0; _resetClient(); }

function remember(map, key, value) {
  if (map.size >= MAX_ENTRIES) map.delete(map.keys().next().value); // oldest first
  map.set(key, value);
}

const KNOWN = new Set(["base", "home", "timeoutMs", "bodyTimeoutMs", "report", "lookup", "force", "clientClass", "fetch"]);
const warnedOptions = new Set();
function warnUnknown(o) {
  for (const k of Object.keys(o)) {
    if (KNOWN.has(k) || warnedOptions.has(k)) continue;
    warnedOptions.add(k);
    console.warn(`@onlinewebdirectory/fetch: unknown option "${k}" is ignored (known: ${[...KNOWN].join(", ")})`);
  }
}

const settings = (o = {}) => (warnUnknown(o), {
  base: (o.base || process.env.OWD_BASE || DEFAULT_BASE).replace(/\/$/, ""),
  home: o.home || defaultHome(),
  timeoutMs: o.timeoutMs ?? 3000,
  bodyTimeoutMs: o.bodyTimeoutMs ?? 3000,
  report: o.report !== false && process.env.OWD_REPORT !== "0",
  lookup: o.lookup !== false,
  force: !!o.force,
  clientClass: o.clientClass || "plain_http",
});

const nextUtcDay = () => { const d = new Date(); d.setUTCHours(24, 0, 0, 0); return d.getTime(); };

function cachedLookup(host, s) {
  if (Date.now() < quotaUntil) return Promise.resolve({ ok: false, status: 402 });
  const hit = lookups.get(host);
  if (hit && Date.now() - hit.at < hit.ttl) return hit.promise;
  const entry = { at: Date.now(), ttl: LOOKUP_TTL_MS, promise: null };
  entry.promise = loadOrCreateKey({ home: s.home, base: s.base, register: false })
    .then((key) => lookup(host, { base: s.base, key, timeoutMs: s.timeoutMs }))
    .catch(() => ({ ok: false }))
    .then((r) => {
      if (!r.ok) entry.ttl = FAILURE_TTL_MS; // a failure is remembered briefly, not retried on every fetch
      if (r.status === 402) quotaUntil = nextUtcDay();
      return r;
    });
  remember(lookups, host, entry);
  return entry.promise;
}

const USABLE = new Set(["verified", "stale"]);
function robotsPosture(data) {
  const crowd = (data.facts || []).find((f) => f.kind === "robots_posture" && USABLE.has(f.state));
  return crowd?.value ?? data.registry_check?.values?.robots_posture ?? null;
}

// A same-site path like "/llms.txt"; anything else is not passed on.
const safePath = (p) => (typeof p === "string" && /^\/(?!\/)[^\s]*$/.test(p) && p.length < 512 ? p : undefined);

function advise(host, page, data, s) {
  const strategy = data.strategy || { fetch: "unknown" };
  const warnings = [];
  const robots = robotsPosture(data);
  if (robots === "disallow_all" && !s.force) return { fetch: false, host, page, strategy, warnings, reason: "robots_disallow_all" };
  if (robots === "partial") warnings.push({ code: "robots_partial" });
  if (strategy.fetch === "do_not_fetch") warnings.push({ code: "site_blocks_agents", ...(typeof strategy.reason === "string" ? { reason: strategy.reason } : {}) });
  if (strategy.fetch === "headless_required") warnings.push({ code: "needs_browser", ...(typeof strategy.expect_challenge === "string" ? { expect_challenge: strategy.expect_challenge } : {}) });
  if (strategy.fetch === "use_machine_interface") {
    const path = safePath(strategy.prefer);
    warnings.push(path ? { code: "machine_interface_available", path } : { code: "machine_interface_available" });
  }
  return { fetch: true, host, page, strategy, warnings };
}

/**
 * What the directory knows about a site, without fetching it. Never throws.
 * @returns {Promise<{fetch: boolean, host: string|null, page: string|null, strategy: object|null, warnings: object[], reason?: string}>}
 */
export async function before(url, options = {}) {
  const s = settings(options);
  const host = hostOf(url);
  if (!host || !s.lookup) return { fetch: true, host, page: null, strategy: null, warnings: [] };
  const page = `${s.base}/sites/${host}`;
  const unavailable = { fetch: true, host, page, strategy: null, warnings: [{ code: "directory_unavailable" }] };
  try {
    const r = await cachedLookup(host, s);
    return r.ok ? advise(host, page, r.data, s) : unavailable;
  } catch {
    return unavailable;
  }
}

function isRootPath(url) {
  try { const u = new URL(url); return u.pathname === "/" && !u.search; } catch { return false; }
}
const isHtml = (contentType) => /text\/html|application\/xhtml\+xml/i.test(contentType || "");
const headerOf = (headers, name) => {
  if (!headers) return "";
  if (typeof headers.get === "function") return headers.get(name) ?? "";
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
  return key === undefined ? "" : String(headers[key]);
};

// What this response says about the whole site, and nothing more. The home
// page tells us the site's posture; any other page only counts when it is a
// bot wall (a challenge served anywhere means the site walls plain clients).
// js_required and on-page challenge markers are only judged from HTML.
export function siteFacts(url, { status, headers, body, finalUrl }) {
  const html = isHtml(headerOf(headers, "content-type"));
  const facts = classify({ status, headers, body: html ? body : "", finalUrl: finalUrl || url });
  if (isRootPath(url)) return facts;
  const wall = facts.access_posture === "bot_challenged" && !(Number(status) >= 200 && Number(status) <= 299);
  return wall ? facts : {};
}

/**
 * Classify a response you fetched yourself and report what it says about the
 * whole site (deduplicated). Options as owdFetch, plus clientClass.
 * @returns {Promise<object>} the facts that were reported
 */
export async function after(url, response = {}, options = {}) {
  try {
    const s = settings(options);
    const host = hostOf(url);
    if (!host || !s.report) return {};
    const facts = siteFacts(url, response);
    const now = Date.now();
    const fresh = Object.fromEntries(Object.entries(facts).filter(([kind, value]) => {
      const k = `${host}|${kind}|${value}`;
      if (now - (reported.get(k) ?? 0) < REPORT_TTL_MS) return false;
      remember(reported, k, now);
      return true;
    }));
    if (!Object.keys(fresh).length) return {};
    const key = await loadOrCreateKey({ home: s.home, base: s.base, register: true, source: "owd-fetch-js" });
    if (key && (await report(host, fresh, { base: s.base, key, clientClass: s.clientClass }))) return fresh;
    return {}; // not sent: the dedupe still holds it for 6 hours, so a down directory is not hammered
  } catch (e) {
    if (process.env.OWD_DEBUG === "1") console.error("owd report failed:", e);
    return {};
  }
}

// The first MAX_CHARS characters of a body, within timeoutMs, without reading the rest.
async function readPrefix(res, timeoutMs) {
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let text = "";
  const deadline = Date.now() + timeoutMs;
  try {
    while (text.length < MAX_CHARS) {
      const left = deadline - Date.now();
      if (left <= 0) break;
      let timer;
      const chunk = await Promise.race([reader.read(), new Promise((r) => { timer = setTimeout(() => r({ timeout: true }), left); })]);
      clearTimeout(timer);
      if (chunk.timeout || chunk.done) break;
      text += decoder.decode(chunk.value, { stream: true });
    }
  } finally {
    reader.cancel().catch(() => {});
  }
  return text.slice(0, MAX_CHARS);
}

function sentCredentials(input, init) {
  const sources = [init?.headers, typeof input === "object" ? input?.headers : undefined];
  return sources.some((h) => headerOf(h, "authorization") || headerOf(h, "cookie"));
}

function reportable(url, input, init, res, s, host) {
  if (!s.report || !host) return false;
  const method = String(init?.method || (typeof input === "object" && input?.method) || "GET").toUpperCase();
  if (method !== "GET" || sentCredentials(input, init)) return false;
  const finalUrl = res?.url;
  if (finalUrl && hostOf(finalUrl) !== host) return false; // redirected to another site
  return true;
}

/**
 * fetch, with the directory consulted before and told after.
 * Same arguments as fetch, plus options: force, report, lookup, timeoutMs, bodyTimeoutMs, base, home, fetch.
 * Throws OwdRefused only when robots.txt tells all agents to stay out.
 * @returns {Promise<Response & {owd: {page: string|null, strategy: object|null, warnings: object[], reported: Promise<object>}}>}
 */
export async function owdFetch(input, init, options = {}) {
  const url = typeof input === "string" ? input : input?.url ?? String(input);
  const s = settings(options);
  const b = await before(url, options);
  if (!b.fetch) throw new OwdRefused(b.host, b.reason, b.strategy, b.page);

  const res = await (options.fetch || globalThis.fetch)(input, init);

  let reportedPromise = Promise.resolve({});
  try {
    if (reportable(url, input, init, res, s, b.host)) {
      const html = isHtml(headerOf(res.headers, "content-type"));
      const meta = { status: res.status, headers: res.headers, finalUrl: res.url || url };
      if (html && res.body?.getReader && typeof res.clone === "function") {
        const copy = res.clone();
        reportedPromise = readPrefix(copy, s.bodyTimeoutMs).then((body) => after(url, { ...meta, body }, options));
      } else {
        reportedPromise = after(url, { ...meta, body: "" }, options); // status and headers only; the body is left alone
      }
      reportedPromise = reportedPromise.catch(() => ({}));
    }
  } catch { /* the fetch already succeeded; reporting is best effort */ }

  try {
    res.owd = { page: b.page, strategy: b.strategy, warnings: b.warnings, reported: reportedPromise };
  } catch { /* a frozen custom response: hints are not attached */ }
  return res;
}
