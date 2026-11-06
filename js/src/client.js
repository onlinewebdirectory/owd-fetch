// Talking to Online Web Directory: the agent key (shared with the skill, in
// ~/.config/onlinewebdirectory/key.json), the free lookup and the signed report.
// Only the hostname and typed facts ever leave this machine.
import { generateKeyPairSync, createPrivateKey, sign } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync, unlinkSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const DEFAULT_BASE = "https://onlinewebdirectory.net";
export const defaultHome = () => process.env.OWD_HOME || join(homedir(), ".config", "onlinewebdirectory");
const b64 = (buf) => Buffer.from(buf).toString("base64");
// Captured once, so an app that patches the global fetch (to add its own auth
// headers, say) never sends them to the directory.
const nativeFetch = globalThis.fetch;
// Private and reserved names: never looked up or reported.
const PRIVATE_SUFFIXES = ["local", "internal", "lan", "home.arpa", "corp", "localhost", "localdomain", "test", "invalid", "intranet", "private", "home"];
let cannotSaveKey = false;

// The bare hostname for a URL, or null when there is no lookup to do (an IP
// literal, or not a URL at all).
export function hostOf(url) {
  let host;
  try { host = new URL(String(url)).hostname.toLowerCase(); } catch { return null; }
  host = host.replace(/\.$/, "");
  if (!host || host.startsWith("[") || /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || !host.includes(".")) return null;
  if (PRIVATE_SUFFIXES.some((s) => host === s || host.endsWith(`.${s}`))) return null;
  return host;
}

async function call(base, method, path, body, token, timeoutMs) {
  const headers = { Accept: "application/json" };
  if (body) headers["Content-Type"] = "application/json";
  if (token) headers["X-Agent-Token"] = token;
  const res = await nativeFetch(base.replace(/\/$/, "") + path, {
    method, headers, body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(timeoutMs ?? 5000),
  });
  let data = null;
  try { data = await res.json(); } catch { /* not JSON */ }
  return { status: res.status, data };
}

// One key per directory address: a key made against a test server is never
// reused against the real directory (which would reject every report).
export function keyFileFor(home, base) {
  let u;
  try { u = new URL(base); } catch { return join(home, "key.json"); }
  if (u.origin === new URL(DEFAULT_BASE).origin) return join(home, "key.json");
  return join(home, `key-${u.hostname}${u.port ? "-" + u.port : ""}.json`.replace(/[^\w.-]/g, "_"));
}

// The saved key, or a newly registered one when register is true. A key file
// that cannot be read is left untouched and no key is used, so a broken file
// never gets silently replaced by a new identity.
export async function loadOrCreateKey({ home = defaultHome(), base = DEFAULT_BASE, register = false, source = "owd-fetch-js", timeoutMs = 5000 } = {}) {
  const file = keyFileFor(home, base);
  if (existsSync(file)) {
    try {
      const k = JSON.parse(readFileSync(file, "utf8"));
      if (!k.public_key || !k.private_pem) return null;
      return { ...k, privateKey: createPrivateKey(k.private_pem) };
    } catch { return null; }
  }
  if (!register || cannotSaveKey) return null;

  // Prove the key can be saved before registering, so a read-only home never
  // registers a new agent on every report.
  try {
    mkdirSync(home, { recursive: true, mode: 0o700 });
    const probe = join(home, `.write-test-${process.pid}`);
    writeFileSync(probe, "");
    unlinkSync(probe);
  } catch {
    cannotSaveKey = true;
    return null;
  }

  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const public_key = b64(Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url"));
  const signature = b64(sign(null, Buffer.from(`onlinewebdirectory:register:${public_key}`), privateKey));
  const { status, data } = await call(base, "POST", "/v1/agents", { public_key, signature, source }, null, timeoutMs);
  if (status !== 201 || !data?.read_token) return null;
  const saved = { public_key, private_pem: privateKey.export({ format: "pem", type: "pkcs8" }),
                  handle: data.handle, read_token: data.read_token, referral_url: data.referral_url };
  try {
    writeFileSync(file, JSON.stringify(saved, null, 2), { mode: 0o600, flag: "wx" });
  } catch (e) {
    if (e.code === "EEXIST") return loadOrCreateKey({ home, base, register: false }); // another process won the race
    cannotSaveKey = true;
    return null;
  }
  return { ...saved, privateKey };
}

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// Only a reply shaped like the directory's answer is used; anything else
// counts as no answer, so a server change can never break a caller.
export function wellFormed(data) {
  if (!isObject(data)) return false;
  if (data.strategy !== undefined && !isObject(data.strategy)) return false;
  if (data.facts !== undefined && !(Array.isArray(data.facts) && data.facts.every(isObject))) return false;
  if (data.registry_check !== undefined && !(isObject(data.registry_check) && (data.registry_check.values === undefined || isObject(data.registry_check.values)))) return false;
  return true;
}

// The directory's answer for a host: { ok: true, data } or { ok: false, status }.
// Never throws.
export async function lookup(host, { base = DEFAULT_BASE, key = null, timeoutMs = 3000 } = {}) {
  try {
    const { status, data } = await call(base, "GET", `/v1/origins/${encodeURIComponent(host)}`, null, key?.read_token, timeoutMs);
    return status === 200 && wellFormed(data) ? { ok: true, data } : { ok: false, status };
  } catch {
    return { ok: false };
  }
}

/** For tests: forget that the key could not be saved. */
export function _resetClient() { cannotSaveKey = false; }

// Signed report of typed facts about a host. Resolves true when accepted.
// Never throws.
export async function report(host, facts, { base = DEFAULT_BASE, key, clientClass = "plain_http", timeoutMs = 5000 } = {}) {
  if (!key?.privateKey) return false;
  const observed_at = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const observations = Object.entries(facts).map(([kind, value]) => ({
    host, kind, value: String(value), client_class: clientClass, observed_at,
    signature: b64(sign(null, Buffer.from([host, kind, String(value), clientClass, observed_at].join("\n")), key.privateKey)),
  }));
  if (!observations.length) return false;
  try {
    const { status } = await call(base, "POST", "/v1/observations", { public_key: key.public_key, observations }, null, timeoutMs);
    return status === 202;
  } catch {
    return false;
  }
}
