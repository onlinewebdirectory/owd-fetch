"""Check before fetch.

    import onlinewebdirectory as owd
    r = owd.get("https://example.com/")   # status, headers, text, url, owd

Asks Online Web Directory how the site treats agents, fetches it (unless
robots.txt tells every agent to stay out), and reports what it saw in the
background. It never breaks the fetch: if the directory is slow, down, out of
free lookups or answers something odd, the fetch just goes ahead.
"""
import os
import queue
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import Future

from .classify import MAX_CHARS, classify
from .client import DEFAULT_BASE, _reset_client, default_home, host_of, load_or_create_key, lookup, report

__all__ = ["get", "before", "after", "Refused", "Response", "classify"]
__version__ = "0.1.0"

LOOKUP_TTL = 3600
FAILURE_TTL = 60
REPORT_TTL = 6 * 3600
MAX_ENTRIES = 10_000
_QUEUE_MAX = 1000
_lookups = {}   # host -> (at, ttl, result)
_reported = {}  # (host, kind, value) -> at
_host_locks = {}
_lock = threading.Lock()
_quota_until = 0.0
USABLE = {"verified", "stale"}


class Refused(Exception):
    """robots.txt tells every agent to stay out; pass force=True to fetch anyway."""

    def __init__(self, host, reason, strategy, page):
        super().__init__(f"{host}: robots.txt tells all agents to stay out; not fetched (see {page}; pass force=True to fetch anyway)")
        self.host, self.reason, self.strategy, self.page = host, reason, strategy, page


class Response:
    """What get() returns: status, headers (dict), text, url, owd."""

    def __init__(self, status, headers, text, url, owd=None):
        self.status, self.headers, self.text, self.url, self.owd = status, dict(headers or {}), text, url, owd

    def __repr__(self):
        return f"<owd.Response {self.status} {self.url}>"


# Reports go through one bounded queue served by one daemon thread: a pending
# report never holds up interpreter exit, and a flood of hosts is dropped, not queued forever.
_queue = queue.Queue(maxsize=_QUEUE_MAX)


def _worker():
    while True:
        fn, args, kwargs, future = _queue.get()
        try:
            future.set_result(fn(*args, **kwargs))
        except Exception:
            future.set_result({})


_thread = threading.Thread(target=_worker, name="owd-report", daemon=True)
_thread.start()


def _worker_is_daemon():
    return _thread.daemon


def _pool_submit(fn, *args, **kwargs):
    future = Future()
    try:
        _queue.put_nowait((fn, args, kwargs, future))
    except queue.Full:
        future.set_result({})
    return future


def _reset():
    """For tests: forget cached lookups, sent reports and backoffs."""
    global _quota_until
    with _lock:
        _lookups.clear()
        _reported.clear()
        _quota_until = 0.0
    _reset_client()


def _remember(d, key, value):
    if len(d) >= MAX_ENTRIES:
        d.pop(next(iter(d)))
    d[key] = value


_warned_options = set()


def _settings(base=None, home=None, timeout=3.0, report=True, lookup=True, force=False, client_class="plain_http", **unknown):
    for k in unknown:
        if k not in _warned_options:
            _warned_options.add(k)
            import warnings
            warnings.warn(f"onlinewebdirectory: unknown option {k!r} is ignored", stacklevel=3)
    return {"base": (base or os.environ.get("OWD_BASE") or DEFAULT_BASE).rstrip("/"), "home": home or default_home(),
            "timeout": timeout, "report": report and os.environ.get("OWD_REPORT") != "0", "lookup": lookup,
            "force": force, "client_class": client_class}


def _next_utc_day():
    t = time.gmtime()
    return time.time() - (t.tm_hour * 3600 + t.tm_min * 60 + t.tm_sec) + 86400


def _cached_lookup(host, s):
    global _quota_until
    if time.time() < _quota_until:
        return {"ok": False, "status": 402}
    with _lock:
        host_lock = _host_locks.get(host)
        if host_lock is None:
            host_lock = threading.Lock()
            _remember(_host_locks, host, host_lock)
    with host_lock:  # concurrent first calls for one host make one lookup
        hit = _lookups.get(host)
        if hit and time.time() - hit[0] < hit[1]:
            return hit[2]
        key = load_or_create_key(home=s["home"], base=s["base"], register=False)
        r = lookup(host, base=s["base"], key=key, timeout=s["timeout"])
        if r.get("status") == 402:
            _quota_until = _next_utc_day()
        with _lock:
            # a failure is remembered briefly, not retried on every fetch
            _remember(_lookups, host, (time.time(), LOOKUP_TTL if r["ok"] else FAILURE_TTL, r))
        return r


def _robots(data):
    for f in data.get("facts") or []:
        if f.get("kind") == "robots_posture" and f.get("state") in USABLE:
            return f.get("value")
    return (data.get("registry_check") or {}).get("values", {}).get("robots_posture")


def _safe_path(p):
    """A same-site path like "/llms.txt"; anything else is not passed on."""
    if isinstance(p, str) and p.startswith("/") and not p.startswith("//") and " " not in p and len(p) < 512:
        return p
    return None


def _advise(host, page, data, s):
    strategy = data.get("strategy") or {"fetch": "unknown"}
    warnings = []
    robots = _robots(data)
    if robots == "disallow_all" and not s["force"]:
        return {"fetch": False, "host": host, "page": page, "strategy": strategy, "warnings": warnings, "reason": "robots_disallow_all"}
    if robots == "partial":
        warnings.append({"code": "robots_partial"})
    fetch = strategy.get("fetch")
    if fetch == "do_not_fetch":
        w = {"code": "site_blocks_agents"}
        if isinstance(strategy.get("reason"), str):
            w["reason"] = strategy["reason"]
        warnings.append(w)
    elif fetch == "headless_required":
        w = {"code": "needs_browser"}
        if isinstance(strategy.get("expect_challenge"), str):
            w["expect_challenge"] = strategy["expect_challenge"]
        warnings.append(w)
    elif fetch == "use_machine_interface":
        path = _safe_path(strategy.get("prefer"))
        warnings.append({"code": "machine_interface_available", "path": path} if path else {"code": "machine_interface_available"})
    return {"fetch": True, "host": host, "page": page, "strategy": strategy, "warnings": warnings}


def before(url, **options):
    """What the directory knows about a site, without fetching it. Never raises."""
    s = _settings(**options)
    host = host_of(url)
    if not host or not s["lookup"]:
        return {"fetch": True, "host": host, "page": None, "strategy": None, "warnings": []}
    page = f"{s['base']}/sites/{host}"
    try:
        r = _cached_lookup(host, s)
        if r["ok"]:
            return _advise(host, page, r["data"], s)
    except Exception:
        pass
    return {"fetch": True, "host": host, "page": page, "strategy": None, "warnings": [{"code": "directory_unavailable"}]}


def _header(headers, name):
    items = headers.items() if hasattr(headers, "items") else (headers or [])
    for k, v in items:
        if str(k).lower() == name.lower():
            return str(v)
    return ""


def _is_html(headers):
    ct = _header(headers, "content-type").lower()
    return "text/html" in ct or "application/xhtml+xml" in ct


def _is_root(url):
    try:
        u = urllib.parse.urlsplit(url)
        return (u.path or "/") == "/" and not u.query
    except ValueError:
        return False


def site_facts(url, status, headers, body, final_url=None):
    """What this response says about the whole site, and nothing more. The home page
    tells the site's posture; any other page only counts when it is a bot wall.
    js_required and on-page challenge markers are only judged from HTML."""
    facts = classify(status, headers, body if _is_html(headers) else "", final_url or url)
    if _is_root(url):
        return facts
    try:
        ok = 200 <= int(status) <= 299
    except (TypeError, ValueError):
        ok = False
    return facts if facts.get("access_posture") == "bot_challenged" and not ok else {}


def after(url, status, headers, body, final_url=None, **options):
    """Classify a response you fetched yourself and report what it says about the whole
    site (deduplicated). Options as get(), plus client_class. Returns the facts reported."""
    try:
        s = _settings(**options)
        host = host_of(url)
        if not host or not s["report"]:
            return {}
        if isinstance(body, (bytes, bytearray)):
            body = bytes(body[: MAX_CHARS * 4]).decode("utf-8", "replace")
        facts = site_facts(url, status, headers, (body or "")[:MAX_CHARS], final_url)
        now = time.time()
        fresh = {}
        with _lock:
            for kind, value in facts.items():
                k = (host, kind, value)
                if now - _reported.get(k, 0) >= REPORT_TTL:
                    _remember(_reported, k, now)
                    fresh[kind] = value
        if not fresh:
            return {}
        key = load_or_create_key(home=s["home"], base=s["base"], register=True)
        if key and report(host, fresh, base=s["base"], key=key, client_class=s["client_class"]):
            return fresh
        return {}  # not sent: the dedupe still holds it, so a down directory is not hammered
    except Exception as e:
        if os.environ.get("OWD_DEBUG") == "1":
            print("owd report failed:", e)
        return {}


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Follows redirects like a browser, but drops Authorization and Cookie when the host changes."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlsplit(newurl).hostname != urllib.parse.urlsplit(req.full_url).hostname:
            for h in ("Authorization", "Cookie"):
                new.remove_header(h)
                new.remove_header(h.capitalize())
                new.unredirected_hdrs.pop(h, None)
        return new


_opener = urllib.request.build_opener(_SafeRedirect)


def _decode(raw, headers):
    charset = "utf-8"
    for part in _header(headers, "content-type").split(";"):
        if part.strip().lower().startswith("charset="):
            charset = part.split("=", 1)[1].strip().strip('"') or "utf-8"
    try:
        return raw.decode(charset, "replace")
    except LookupError:
        return raw.decode("utf-8", "replace")


def _urllib_fetch(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with _opener.open(req, timeout=timeout) as res:
            h = dict(res.headers.items())
            return Response(res.status, h, _decode(res.read(), h), res.geturl())
    except urllib.error.HTTPError as e:
        h = dict(e.headers.items()) if e.headers else {}
        return Response(e.code, h, _decode(e.read(), h), e.geturl() or url)


def _sent_credentials(headers):
    return bool(_header(headers or {}, "authorization") or _header(headers or {}, "cookie"))


def get(url, headers=None, fetch_timeout=30, fetch=None, **options):
    """GET url with the directory consulted before and told after.

    Options: force, report, lookup, timeout (directory call, seconds), base, home, and fetch
    (your own callable(url, headers, timeout) returning an owd.Response). fetch_timeout is the
    page fetch timeout. Raises Refused only when robots.txt disallows all agents.
    """
    b = before(url, **options)
    if not b["fetch"]:
        raise Refused(b["host"], b["reason"], b["strategy"], b["page"])
    res = (fetch or _urllib_fetch)(url, headers, fetch_timeout)
    future = None
    try:
        s = _settings(**options)
        same_host = not getattr(res, "url", None) or host_of(res.url) == b["host"]
        if s["report"] and b["host"] and same_host and not _sent_credentials(headers):
            future = _pool_submit(after, url, res.status, res.headers, res.text, res.url or url, **options)
    except Exception:
        future = None
    if future is None:
        future = Future()
        future.set_result({})
    try:
        res.owd = {"page": b["page"], "strategy": b["strategy"], "warnings": b["warnings"], "reported": future}
    except Exception:
        pass
    return res
