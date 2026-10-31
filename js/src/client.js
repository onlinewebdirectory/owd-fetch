// Talking to Online Web Directory: the agent key (shared with the skill, in
// ~/.config/onlinewebdirectory/key.json), the free lookup and the signed report.
// Only the hostname and typed facts ever leave this machine.
import { generateKeyPairSync, createPrivateKey, sign } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const DEFAULT_BASE = "https://onlinewebdirectory.net";
export const defaultHome = () => process.env.OWD_HOME || join(homedir(), ".config", "onlinewebdirectory");
const b64 = (buf) => Buffer.from(buf).toString("base64");

// The bare hostname for a URL, or null when there is no lookup to do (an IP
// literal, or not a URL at all).
export function hostOf(url) {
  let host;
  try { host = new URL(String(url)).hostname.toLowerCase(); } catch { return null; }
  host = host.replace(/\.$/, "");
  if (!host || host.startsWith("[") || /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || !host.includes(".")) return null;
  return host;
}

async function call(base, method, path, body, token, timeoutMs) {
  const headers = { Accept: "application/json" };
  if (body) headers["Content-Type"] = "application/json";
  if (token) headers["X-Agent-Token"] = token;
  const res = await fetch(base.replace(/\/$/, "") + path, {
    method, headers, body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(timeoutMs ?? 5000),
  });
  let data = null;
  try { data = await res.json(); } catch { /* not JSON */ }
  return { status: res.status, data };
}

// The saved key, or a newly registered one when register is true. A key file
// that cannot be read is left untouched and no key is used, so a broken file
// never gets silently replaced by a new identity.
export async function loadOrCreateKey({ home = defaultHome(), base = DEFAULT_BASE, register = false, source = "owd-fetch-js", timeoutMs = 5000 } = {}) {
  const file = join(home, "key.json");
  if (existsSync(file)) {
    try {
      const k = JSON.parse(readFileSync(file, "utf8"));
      if (!k.public_key || !k.private_pem) return null;
      return { ...k, privateKey: createPrivateKey(k.private_pem) };
    } catch { return null; }
  }
  if (!register) return null;

  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const public_key = b64(Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url"));
  const signature = b64(sign(null, Buffer.from(`onlinewebdirectory:register:${public_key}`), privateKey));
  const { status, data } = await call(base, "POST", "/v1/agents", { public_key, signature, source }, null, timeoutMs);
  if (status !== 201 || !data?.read_token) return null;
  mkdirSync(home, { recursive: true, mode: 0o700 });
  const saved = { public_key, private_pem: privateKey.export({ format: "pem", type: "pkcs8" }),
                  handle: data.handle, read_token: data.read_token, referral_url: data.referral_url };
  if (existsSync(file)) return loadOrCreateKey({ home, base, register: false }); // another process won the race
  writeFileSync(file, JSON.stringify(saved, null, 2), { mode: 0o600 });
  return { ...saved, privateKey };
}

// The directory's answer for a host: { ok: true, data } or { ok: false }.
// Never throws.
export async function lookup(host, { base = DEFAULT_BASE, key = null, timeoutMs = 1500 } = {}) {
  try {
    const { status, data } = await call(base, "GET", `/v1/origins/${encodeURIComponent(host)}`, null, key?.read_token, timeoutMs);
    return status === 200 && data ? { ok: true, data } : { ok: false, status };
  } catch {
    return { ok: false };
  }
}

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
