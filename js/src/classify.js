// What a plain HTTP client saw at a site, as directory facts. A port of the
// server's checker (Seeding::SiteProbe.access in the Online Web Directory app);
// fixtures/classify.json is generated from it and both must agree.

const CHALLENGE_MARKERS = [
  ["cloudflare", [/cf-chl/i, /Just a moment\.\.\./, /__cf_chl/i, /challenge-platform/i]],
  ["recaptcha", [/www\.google\.com\/recaptcha/i, /grecaptcha/i]],
  ["hcaptcha", [/hcaptcha\.com/i]],
  ["datadome", [/datadome/i]],
  ["perimeterx", [/perimeterx/i, /_pxhd/i, /px-captcha/i]],
  ["akamai", [/akamai/i, /ak_bmsc/i, /_abck/i]],
];
const JS_WALL = [/enable javascript/i, /javascript is (required|disabled)/i, /please enable js/i];
const LOGIN_PATH = /\/(login|signin|sign-in|auth|account\/login)/i;
export const MAX_CHARS = 200_000;

function header(headers, name) {
  if (!headers) return "";
  if (typeof headers.get === "function") return headers.get(name) ?? "";
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
  return key === undefined ? "" : String(headers[key]);
}

const visibleText = (html) =>
  html.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ").replace(/ {2,}/g, " ");

function challengeVendor(status, headers, text) {
  if (header(headers, "cf-mitigated").toLowerCase() === "challenge") return "cloudflare";
  for (const [vendor, patterns] of CHALLENGE_MARKERS) {
    // A 200 page that merely embeds a reCAPTCHA widget on a form is not a wall.
    if (status >= 200 && status <= 299 && vendor !== "cloudflare") continue;
    if (patterns.some((p) => p.test(text))) return vendor;
  }
  const server = header(headers, "Server");
  if ((status === 403 || status === 503) && server.toLowerCase() === "cloudflare" && /attention required|access denied/i.test(text)) return "cloudflare";
  if (status === 403 && /akamai/i.test(server)) return "akamai";
  return null;
}

function jsRequired(text) {
  const visible = visibleText(text).length;
  if (JS_WALL.some((p) => p.test(text)) && visible < 600) return true;
  if (visible >= 600) return false;
  return null;
}

// { status, headers, body, finalUrl } -> { kind: value }. Empty when the
// response says nothing about how the site treats agents (404, 500...).
export function classify({ status, headers, body, finalUrl }) {
  status = Number(status) || 0;
  const text = String(body ?? "").slice(0, MAX_CHARS);
  const vendor = challengeVendor(status, headers, text);
  if (vendor) return { access_posture: "bot_challenged", challenge_vendor: vendor };
  if (status === 429) {
    const out = { access_posture: "rate_limited" };
    // Leading digits, like the server's Ruby to_i ("30abc" is 30, "1_000" is 1000).
    const m = header(headers, "Retry-After").match(/^\s*\+?(\d[\d_]*)/);
    const retry = m ? parseInt(m[1].replace(/_/g, ""), 10) : 0;
    if (retry >= 1 && retry <= 86_400) out.retry_after_s = String(retry);
    return out;
  }
  if (status === 401 || (status >= 300 && status <= 399 && LOGIN_PATH.test(String(finalUrl ?? "")))) return { access_posture: "login_required" };
  if (status === 402) return { access_posture: "paywalled" };
  if (status === 403 || status === 503 || status === 451) return { access_posture: "blocked", challenge_vendor: "none" };
  if (status >= 200 && status <= 299) {
    const out = { access_posture: "open", challenge_vendor: "none" };
    const js = jsRequired(text);
    if (js !== null) out.js_required = String(js);
    return out;
  }
  return {};
}
