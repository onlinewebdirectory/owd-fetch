"""What a plain HTTP client saw at a site, as directory facts.

A port of the server's checker (Seeding::SiteProbe.access in the Online Web
Directory app); fixtures/classify.json is generated from it and both must agree.
"""
import re

CHALLENGE_MARKERS = [
    ("cloudflare", [re.compile(r"cf-chl", re.I), re.compile(r"Just a moment\.\.\."), re.compile(r"__cf_chl", re.I), re.compile(r"challenge-platform", re.I)]),
    ("recaptcha", [re.compile(r"www\.google\.com/recaptcha", re.I), re.compile(r"grecaptcha", re.I)]),
    ("hcaptcha", [re.compile(r"hcaptcha\.com", re.I)]),
    ("datadome", [re.compile(r"datadome", re.I)]),
    ("perimeterx", [re.compile(r"perimeterx", re.I), re.compile(r"_pxhd", re.I), re.compile(r"px-captcha", re.I)]),
    ("akamai", [re.compile(r"akamai", re.I), re.compile(r"ak_bmsc", re.I), re.compile(r"_abck", re.I)]),
]
JS_WALL = [re.compile(r"enable javascript", re.I), re.compile(r"javascript is (required|disabled)", re.I), re.compile(r"please enable js", re.I)]
LOGIN_PATH = re.compile(r"/(login|signin|sign-in|auth|account/login)", re.I)
MAX_CHARS = 200_000


def _header(headers, name):
    if not headers:
        return ""
    for k, v in dict(headers).items():
        if k.lower() == name.lower():
            return str(v)
    return ""


def _visible_text(html):
    html = re.sub(r"<script.*?</script>", " ", html, flags=re.I | re.S)
    html = re.sub(r"<style.*?</style>", " ", html, flags=re.I | re.S)
    html = re.sub(r"<[^>]+>", " ", html)
    return re.sub(r" {2,}", " ", html)


def _challenge_vendor(status, headers, text):
    if _header(headers, "cf-mitigated").lower() == "challenge":
        return "cloudflare"
    for vendor, patterns in CHALLENGE_MARKERS:
        # A 200 page that merely embeds a reCAPTCHA widget on a form is not a wall.
        if 200 <= status <= 299 and vendor != "cloudflare":
            continue
        if any(p.search(text) for p in patterns):
            return vendor
    server = _header(headers, "Server")
    if status in (403, 503) and server.lower() == "cloudflare" and re.search(r"attention required|access denied", text, re.I):
        return "cloudflare"
    if status == 403 and re.search(r"akamai", server, re.I):
        return "akamai"
    return None


def _js_required(text):
    visible = len(_visible_text(text))
    if any(p.search(text) for p in JS_WALL) and visible < 600:
        return True
    if visible >= 600:
        return False
    return None


def classify(status, headers, body, final_url=""):
    """Return {kind: value}; empty when the response says nothing about agents (404, 500...)."""
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = 0
    text = str(body or "")[:MAX_CHARS]
    vendor = _challenge_vendor(status, headers, text)
    if vendor:
        return {"access_posture": "bot_challenged", "challenge_vendor": vendor}
    if status == 429:
        out = {"access_posture": "rate_limited"}
        try:
            retry = int(_header(headers, "Retry-After"))
        except ValueError:
            retry = 0
        if 1 <= retry <= 86_400:
            out["retry_after_s"] = str(retry)
        return out
    if status == 401 or (300 <= status <= 399 and LOGIN_PATH.search(str(final_url or ""))):
        return {"access_posture": "login_required"}
    if status == 402:
        return {"access_posture": "paywalled"}
    if status in (403, 503, 451):
        return {"access_posture": "blocked", "challenge_vendor": "none"}
    if 200 <= status <= 299:
        out = {"access_posture": "open", "challenge_vendor": "none"}
        js = _js_required(text)
        if js is not None:
            out["js_required"] = "true" if js else "false"
        return out
    return {}
