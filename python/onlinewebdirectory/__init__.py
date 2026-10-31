"""Check before fetch.

    import onlinewebdirectory as owd
    r = owd.get("https://example.com/")   # status, headers, text, url, owd

Asks Online Web Directory how the site treats agents, fetches it (unless
robots.txt tells every agent to stay out), and reports what it saw in the
background. It never breaks the fetch: if the directory is slow, down or out of
free lookups, the fetch just goes ahead.
"""
import os
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import Future, ThreadPoolExecutor

from .classify import MAX_CHARS, classify
from .client import DEFAULT_BASE, default_home, host_of, load_or_create_key, lookup, report

__all__ = ["get", "before", "after", "Refused", "Response", "classify"]
__version__ = "0.1.0"

LOOKUP_TTL = 3600
REPORT_TTL = 6 * 3600
_lookups = {}   # host -> (at, result)
_reported = {}  # (host, kind, value) -> at
_lock = threading.Lock()
_host_locks = {}
_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="owd-report")
USABLE = {"verified", "stale"}


class Refused(Exception):
    """robots.txt tells every agent to stay out; pass force=True to fetch anyway."""

    def __init__(self, host, reason, strategy, page):
        super().__init__(f"{host}: robots.txt tells all agents to stay out; not fetched (see {page}; pass force=True to fetch anyway)")
        self.host, self.reason, self.strategy, self.page = host, reason, strategy, page


class Response:
    def __init__(self, status, headers, text, url, owd=None):
        self.status, self.headers, self.text, self.url, self.owd = status, dict(headers or {}), text, url, owd

    def __repr__(self):
        return f"<owd.Response {self.status} {self.url}>"


def _reset():
    """For tests: forget cached lookups and sent reports."""
    with _lock:
        _lookups.clear()
        _reported.clear()


def _settings(base=None, home=None, timeout=3.0, report=True, lookup=True, force=False, **_):
    return {"base": (base or os.environ.get("OWD_BASE") or DEFAULT_BASE).rstrip("/"), "home": home or default_home(),
            "timeout": timeout, "report": report and os.environ.get("OWD_REPORT") != "0", "lookup": lookup, "force": force}


def _cached_lookup(host, s):
    with _lock:
        host_lock = _host_locks.setdefault(host, threading.Lock())
    with host_lock:  # concurrent first calls for one host make one lookup
        hit = _lookups.get(host)
        if hit and time.time() - hit[0] < LOOKUP_TTL:
            return hit[1]
        key = load_or_create_key(home=s["home"], base=s["base"], register=False)
        r = lookup(host, base=s["base"], key=key, timeout=s["timeout"])
        if r["ok"]:
            _lookups[host] = (time.time(), r)
        return r


def _robots(data):
    for f in data.get("facts") or []:
        if f.get("kind") == "robots_posture" and f.get("state") in USABLE:
            return f.get("value")
    return ((data.get("registry_check") or {}).get("values") or {}).get("robots_posture")


def before(url, **options):
    """What the directory knows about a site, without fetching it."""
    s = _settings(**options)
    host = host_of(url)
    if not host or not s["lookup"]:
        return {"fetch": True, "host": host, "page": None, "strategy": None, "warnings": []}
    page = f"{s['base']}/sites/{host}"
    r = _cached_lookup(host, s)
    if not r["ok"]:
        return {"fetch": True, "host": host, "page": page, "strategy": None, "warnings": [{"code": "directory_unavailable"}]}
    data = r["data"]
    strategy = data.get("strategy") or {"fetch": "unknown"}
    warnings = []
    robots = _robots(data)
    if robots == "disallow_all" and not s["force"]:
        return {"fetch": False, "host": host, "page": page, "strategy": strategy, "warnings": warnings, "reason": "robots_disallow_all"}
    if robots == "partial":
        warnings.append({"code": "robots_partial"})
    fetch = strategy.get("fetch")
    if fetch == "do_not_fetch":
        warnings.append({"code": "site_blocks_agents", "reason": strategy.get("reason")})
    elif fetch == "headless_required":
        w = {"code": "needs_browser"}
        if strategy.get("expect_challenge"):
            w["expect_challenge"] = strategy["expect_challenge"]
        warnings.append(w)
    elif fetch == "use_machine_interface":
        warnings.append({"code": "machine_interface_available", "path": strategy.get("prefer")})
    return {"fetch": True, "host": host, "page": page, "strategy": strategy, "warnings": warnings}


def after(url, status, headers, body, final_url=None, **options):
    """Classify a response you fetched yourself and report it (deduplicated). Returns the facts reported."""
    s = _settings(**options)
    host = host_of(url)
    if not host or not s["report"]:
        return {}
    facts = classify(status, headers, (body or "")[:MAX_CHARS], final_url or url)
    now = time.time()
    fresh = {}
    with _lock:
        for kind, value in facts.items():
            k = (host, kind, value)
            if now - _reported.get(k, 0) >= REPORT_TTL:
                _reported[k] = now
                fresh[kind] = value
    if not fresh:
        return {}

    def forget():
        with _lock:
            for kind, value in fresh.items():
                _reported.pop((host, kind, value), None)

    try:
        key = load_or_create_key(home=s["home"], base=s["base"], register=True)
        if not key or not report(host, fresh, base=s["base"], key=key):
            forget()
            return {}
        return fresh
    except Exception as e:
        forget()
        if os.environ.get("OWD_DEBUG") == "1":
            print("owd report failed:", e)
        return {}


def _urllib_fetch(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return Response(res.status, dict(res.headers.items()), res.read().decode("utf-8", "replace"), res.geturl())
    except urllib.error.HTTPError as e:
        return Response(e.code, dict(e.headers.items()), e.read().decode("utf-8", "replace"), url)


def get(url, headers=None, fetch_timeout=30, fetch=None, **options):
    """GET url with the directory consulted before and told after.

    Options: force, report, lookup, timeout (directory call, seconds), base, home, fetch (your own
    callable(url, headers, timeout) -> Response). Raises Refused when robots.txt disallows all agents.
    """
    b = before(url, **options)
    if not b["fetch"]:
        raise Refused(b["host"], b["reason"], b["strategy"], b["page"])
    res = (fetch or _urllib_fetch)(url, headers, fetch_timeout)
    if _settings(**options)["report"] and b["host"]:
        future = _pool.submit(after, url, res.status, res.headers, res.text, res.url or url, **options)
    else:
        future = Future()
        future.set_result({})
    res.owd = {"page": b["page"], "strategy": b["strategy"], "warnings": b["warnings"], "reported": future}
    return res
