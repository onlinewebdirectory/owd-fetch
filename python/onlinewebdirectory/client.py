"""Talking to Online Web Directory: the agent key (shared with the skill and the
JavaScript package, in ~/.config/onlinewebdirectory/key.json), the free lookup
and the signed report. Only the hostname and typed facts leave this machine."""
import base64
import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

DEFAULT_BASE = "https://onlinewebdirectory.net"

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    CAN_SIGN = True
except ImportError:  # still looks up and fetches; reporting is skipped
    CAN_SIGN = False


def default_home():
    return os.environ.get("OWD_HOME") or os.path.join(os.path.expanduser("~"), ".config", "onlinewebdirectory")


def host_of(url):
    """The bare lowercase hostname, or None for an IP literal or something that is not a URL."""
    try:
        host = (urllib.parse.urlsplit(str(url)).hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    if not host or "." not in host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        return host


def _call(base, method, path, body=None, token=None, timeout=5.0):
    headers = {"Accept": "application/json", "User-Agent": "onlinewebdirectory-py"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    if token:
        headers["X-Agent-Token"] = token
    req = urllib.request.Request(base.rstrip("/") + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            status, raw = res.status, res.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    try:
        return status, json.loads(raw.decode() or "null")
    except ValueError:
        return status, None


def _b64(b):
    return base64.b64encode(b).decode()


def _sign(private_key, text):
    return _b64(private_key.sign(text.encode()))


def load_or_create_key(home=None, base=DEFAULT_BASE, register=False, source="owd-fetch-py", timeout=5.0):
    """The saved key, or a newly registered one when register is True. A key file
    that cannot be read is left untouched and no key is used."""
    home = home or default_home()
    path = os.path.join(home, "key.json")
    if os.path.exists(path):
        try:
            k = json.load(open(path))
            if not k.get("public_key") or not k.get("private_pem"):
                return None
            if CAN_SIGN:
                k["private_key"] = serialization.load_pem_private_key(k["private_pem"].encode(), password=None)
            return k
        except (ValueError, OSError, TypeError):
            return None
    if not register or not CAN_SIGN:
        return None
    priv = Ed25519PrivateKey.generate()
    public_key = _b64(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    signature = _sign(priv, f"onlinewebdirectory:register:{public_key}")
    try:
        status, data = _call(base, "POST", "/v1/agents", {"public_key": public_key, "signature": signature, "source": source}, timeout=timeout)
    except (OSError, urllib.error.URLError):
        return None
    if status != 201 or not (data or {}).get("read_token"):
        return None
    os.makedirs(home, mode=0o700, exist_ok=True)
    if os.path.exists(path):  # another process won the race
        return load_or_create_key(home=home, base=base, register=False)
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    saved = {"public_key": public_key, "private_pem": pem, "handle": data.get("handle"),
             "read_token": data.get("read_token"), "referral_url": data.get("referral_url")}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(saved, f, indent=2)
    saved["private_key"] = priv
    return saved


def lookup(host, base=DEFAULT_BASE, key=None, timeout=1.5):
    """{"ok": True, "data": {...}} or {"ok": False}. Never raises."""
    try:
        status, data = _call(base, "GET", "/v1/origins/" + urllib.parse.quote(host, safe=""), token=(key or {}).get("read_token"), timeout=timeout)
    except Exception:  # timeouts, DNS, refused: fail open
        return {"ok": False}
    return {"ok": True, "data": data} if status == 200 and data else {"ok": False, "status": status}


def report(host, facts, base=DEFAULT_BASE, key=None, client_class="plain_http", timeout=5.0):
    """Signed report of typed facts. True when accepted. Never raises."""
    if not CAN_SIGN or not key or not key.get("private_key") or not facts:
        return False
    observed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    observations = []
    for kind, value in facts.items():
        value = str(value)
        payload = "\n".join([host, kind, value, client_class, observed_at])
        observations.append({"host": host, "kind": kind, "value": value, "client_class": client_class,
                             "observed_at": observed_at, "signature": _sign(key["private_key"], payload)})
    try:
        status, _ = _call(base, "POST", "/v1/observations", {"public_key": key["public_key"], "observations": observations}, timeout=timeout)
    except Exception:
        return False
    return status == 202
