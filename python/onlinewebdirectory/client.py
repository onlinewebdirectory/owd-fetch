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
# Private and reserved names: never looked up or reported.
PRIVATE_SUFFIXES = ("local", "internal", "lan", "home.arpa", "corp", "localhost", "localdomain", "test", "invalid", "intranet", "private", "home")
_cannot_save_key = False

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
        pass
    try:
        host = host.encode("idna").decode("ascii")  # the same ASCII form the JavaScript package sends
    except UnicodeError:
        return None
    if any(host == s or host.endswith("." + s) for s in PRIVATE_SUFFIXES):
        return None
    return host


def well_formed(data):
    """Only a reply shaped like the directory's answer is used."""
    if not isinstance(data, dict):
        return False
    if "strategy" in data and not isinstance(data["strategy"], dict):
        return False
    if "facts" in data and not (isinstance(data["facts"], list) and all(isinstance(f, dict) for f in data["facts"])):
        return False
    rc = data.get("registry_check")
    if "registry_check" in data and not (isinstance(rc, dict) and isinstance(rc.get("values", {}), dict)):
        return False
    return True


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


def _reset_client():
    global _cannot_save_key
    _cannot_save_key = False


def _read_key(path):
    try:
        with open(path) as f:
            k = json.load(f)
        if not isinstance(k, dict) or not isinstance(k.get("public_key"), str) or not isinstance(k.get("private_pem"), str):
            return None
        if CAN_SIGN:
            k["private_key"] = serialization.load_pem_private_key(k["private_pem"].encode(), password=None)
        return k
    except Exception:  # unreadable, not JSON, not a key: left untouched, no key used
        return None


def load_or_create_key(home=None, base=DEFAULT_BASE, register=False, source="owd-fetch-py", timeout=5.0):
    """The saved key, or a newly registered one when register is True. A key file
    that cannot be read is left untouched and no key is used."""
    global _cannot_save_key
    home = home or default_home()
    path = os.path.join(home, "key.json")
    if os.path.exists(path):
        return _read_key(path)
    if not register or not CAN_SIGN or _cannot_save_key:
        return None
    # Prove the key can be saved before registering, so a read-only home never
    # registers a new agent on every report.
    try:
        os.makedirs(home, mode=0o700, exist_ok=True)
        probe = os.path.join(home, ".write-test-%d" % os.getpid())
        open(probe, "w").close()
        os.remove(probe)
    except OSError:
        _cannot_save_key = True
        return None
    priv = Ed25519PrivateKey.generate()
    public_key = _b64(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    signature = _sign(priv, f"onlinewebdirectory:register:{public_key}")
    try:
        status, data = _call(base, "POST", "/v1/agents", {"public_key": public_key, "signature": signature, "source": source}, timeout=timeout)
    except Exception:
        return None
    if status != 201 or not isinstance(data, dict) or not data.get("read_token"):
        return None
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    saved = {"public_key": public_key, "private_pem": pem, "handle": data.get("handle"),
             "read_token": data.get("read_token"), "referral_url": data.get("referral_url")}
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:  # another process won the race
        return _read_key(path)
    except OSError:
        _cannot_save_key = True
        return None
    with os.fdopen(fd, "w") as f:
        json.dump(saved, f, indent=2)
    saved["private_key"] = priv
    return saved


def lookup(host, base=DEFAULT_BASE, key=None, timeout=3.0):
    """{"ok": True, "data": {...}} or {"ok": False}. Never raises."""
    try:
        status, data = _call(base, "GET", "/v1/origins/" + urllib.parse.quote(host, safe=""), token=(key or {}).get("read_token"), timeout=timeout)
    except Exception:  # timeouts, DNS, refused: fail open
        return {"ok": False}
    return {"ok": True, "data": data} if status == 200 and well_formed(data) else {"ok": False, "status": status}


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
