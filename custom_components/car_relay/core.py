"""car_relay core: pairing, phone presence and the lock state machine.

No Home Assistant imports, so tests/test_core.py runs it with plain Python.

The rules this file enforces:
  * A car (device) only exists after a pairing that an allowed HA user approved by scanning
    the code shown on the car's screen. Pairing is closed unless an admin opened a window.
  * A paired car is "unlocked" only while an allowed phone is marked in the car, no hard lock
    is set, and (inside the optional scan hours) someone scanned during this window.
  * Anything may lock. Only a scan by an allowed HA user unlocks a hard lock.
  * The device token is random, shown to the car once, and stored here only as a SHA-256.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta

CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # no 0/O/1/I
PAIR_TTL_S = 300
SCAN_TTL_S = 180
MAX_PENDING = 4
NONCE_TTL_S = 900


def new_code(n: int = 8) -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(n))


def token_hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def parse_hhmm(text: str) -> int:
    """'23:00' -> minutes after midnight."""
    h, m = str(text).split(":")
    h, m = int(h), int(m)
    if not (0 <= h < 24 and 0 <= m < 60):
        raise ValueError("bad time " + str(text))
    return h * 60 + m


class Relay:
    """cfg keys: lock_after_s, scan_hours (None or (start_min, end_min)), allowed_users
    (set of HA user ids; empty = any real user), max_devices, qr_template."""

    def __init__(self, cfg, data=None, tz=None, now=time.time):
        self.cfg = cfg
        self.tz = tz
        self.now = now
        d = data or {}
        self.devices = dict(d.get("devices", {}))        # id -> {name, hash, paired_at, paired_by}
        self.hard_locked = bool(d.get("hard_locked", False))
        self.last_scan_at = float(d.get("last_scan_at", 0))
        self.phones = dict(d.get("phones", {}))          # user id -> connected_at
        self.last_seen = float(d.get("last_seen", 0))    # last authenticated request from a car
        self.pairing_until = 0.0
        self.pending_pairs = {}                           # pair_id -> {code, name, expires, token}
        self.pending_scans = {}                           # code -> expires
        self.nonces = {}                                  # nonce -> seen_at
        self.dirty = False

    def to_store(self):
        return {
            "devices": self.devices, "hard_locked": self.hard_locked,
            "last_scan_at": self.last_scan_at, "phones": self.phones, "last_seen": self.last_seen,
        }

    # ---------------------------------------------------------------- helpers

    def _allowed(self, user_id) -> bool:
        if not user_id:
            return False
        allowed = self.cfg.get("allowed_users") or set()
        return not allowed or user_id in allowed

    def _purge(self):
        t = self.now()
        for k in [k for k, v in self.pending_pairs.items() if v["expires"] < t]:
            del self.pending_pairs[k]
        for k in [k for k, v in self.pending_scans.items() if v < t]:
            del self.pending_scans[k]
        for k in [k for k, v in self.nonces.items() if v < t - NONCE_TTL_S]:
            del self.nonces[k]

    def qr(self, code: str) -> str:
        return self.cfg.get("qr_template", "{code}").replace("{code}", code)

    # ---------------------------------------------------------------- pairing

    def open_pairing(self, minutes: float = 10):
        self.pairing_until = self.now() + minutes * 60

    def pair_start(self, name: str):
        """-> (status, payload). The car shows payload['qr'] and polls pair_status."""
        self._purge()
        if self.now() > self.pairing_until:
            return "pairing-closed", None
        if len(self.devices) >= int(self.cfg.get("max_devices", 1)):
            return "device-limit", None
        if len(self.pending_pairs) >= MAX_PENDING:
            return "busy", None
        pair_id = secrets.token_hex(16)
        code = new_code()
        self.pending_pairs[pair_id] = {
            "code": code, "name": str(name or "car")[:40],
            "expires": self.now() + PAIR_TTL_S, "token": None,
        }
        return "ok", {"pair_id": pair_id, "code": code, "qr": self.qr(code), "expires_in": PAIR_TTL_S}

    def pair_status(self, pair_id: str):
        """-> (status, token). The token is returned exactly once."""
        self._purge()
        p = self.pending_pairs.get(str(pair_id))
        if not p:
            return "unknown", None
        if not p["token"]:
            return "pending", None
        del self.pending_pairs[str(pair_id)]
        return "approved", p["token"]

    def unpair(self, device_id: str) -> bool:
        if device_id in self.devices:
            del self.devices[device_id]
            self.dirty = True
            return True
        return False

    def auth(self, header: str):
        """'<device id>.<secret>' -> device id, or None."""
        if not header or "." not in header:
            return None
        dev_id, secret = header.split(".", 1)
        dev = self.devices.get(dev_id)
        want = dev["hash"] if dev else "0" * 64
        ok = hmac.compare_digest(token_hash(secret), want)
        if not (dev and ok):
            return None
        self.last_seen = self.now()
        return dev_id

    # ---------------------------------------------------------------- scans, phones, locks

    def scan_new(self):
        """A single-use code for the car to show when it needs a scan."""
        self._purge()
        while len(self.pending_scans) >= MAX_PENDING:
            del self.pending_scans[min(self.pending_scans, key=self.pending_scans.get)]
        code = new_code()
        self.pending_scans[code] = self.now() + SCAN_TTL_S
        return {"code": code, "qr": self.qr(code), "expires_in": SCAN_TTL_S}

    def _scanned(self, user_id):
        self.hard_locked = False
        self.last_scan_at = self.now()
        self.phones[user_id] = self.now()
        self.dirty = True

    def scan(self, code, user_id) -> str:
        """An HA user scanned a code. -> 'paired' | 'unlocked' | 'forbidden' | 'unknown'."""
        if not self._allowed(user_id):
            return "forbidden"
        self._purge()
        code = str(code or "").strip().upper()
        if not code:
            return "unknown"
        for p in self.pending_pairs.values():
            if not p["token"] and hmac.compare_digest(p["code"], code):
                dev_id = secrets.token_hex(6)
                secret = secrets.token_urlsafe(32)
                self.devices[dev_id] = {
                    "name": p["name"], "hash": token_hash(secret),
                    "paired_at": self.now(), "paired_by": user_id,
                }
                p["token"] = dev_id + "." + secret
                self.pairing_until = 0.0
                self._scanned(user_id)
                return "paired"
        if code in self.pending_scans:
            del self.pending_scans[code]
            self._scanned(user_id)
            return "unlocked"
        return "unknown"

    def phone(self, user_id, connected: bool) -> bool:
        """A phone's CarPlay connect / disconnect. False when the user is not allowed."""
        if not self._allowed(user_id):
            return False
        if connected:
            self.phones[user_id] = self.now()
        else:
            self.phones.pop(user_id, None)
        self.dirty = True
        return True

    def lock(self, reason: str):
        """Always allowed. 'button' needs a scan to undo; anything else only forgets the phones,
        so the next CarPlay connect unlocks again."""
        if reason == "button":
            self.hard_locked = True
        self.phones.clear()
        self.dirty = True

    def tick(self):
        """Forget phones once the car has been silent for lock_after_s. A phone that connected
        recently is kept, so a CarPlay connect that beats the car's first request survives."""
        self._purge()
        cutoff = self.now() - float(self.cfg.get("lock_after_s", 600))
        if self.last_seen >= cutoff:
            return
        stale = [u for u, at in self.phones.items() if at < cutoff]
        for u in stale:
            del self.phones[u]
        if stale:
            self.dirty = True

    def _window_start(self):
        """Start (epoch) of the scan-hours window we are inside now, or None."""
        hours = self.cfg.get("scan_hours")
        if not hours:
            return None
        start, end = hours
        local = datetime.fromtimestamp(self.now(), self.tz)
        minute = local.hour * 60 + local.minute
        midnight = local.replace(hour=0, minute=0, second=0, microsecond=0)
        if start <= end:
            inside, day = start <= minute < end, midnight
        else:
            inside = minute >= start or minute < end
            day = midnight if minute >= start else midnight - timedelta(days=1)
        if not inside:
            return None
        return (day + timedelta(minutes=start)).timestamp()

    def session(self):
        """-> {'unlocked': bool, 'reason': str}. reason tells the car what to draw."""
        if self.hard_locked:
            return {"unlocked": False, "reason": "scan-required"}
        ws = self._window_start()
        if ws is not None and self.last_scan_at < ws:
            return {"unlocked": False, "reason": "scan-required-hours"}
        if not self.phones:
            return {"unlocked": False, "reason": "no-phone"}
        return {"unlocked": True, "reason": "ok"}

    def nonce(self, n) -> bool:
        """True the first time a nonce is seen."""
        self._purge()
        n = str(n or "")[:64]
        if not n or n in self.nonces:
            return False
        self.nonces[n] = self.now()
        return True


# ---------------------------------------------------------------------------------------------
# What the car reports about itself (POST /car). It comes from the car, so it is checked here and
# is only ever shown: nothing the car says about itself may decide a lock, a pairing or an action.
# Where the car is, is a separate matter (clean_position below) and is off unless the owner turns it on.

# key: (name, kind, low, high, unit, device class, icon)
CAR_FIELDS = {
    "speed_kmh": ("Speed", "number", 0, 400, "km/h", "speed", "mdi:speedometer"),
    "rpm": ("Engine speed", "number", 0, 12000, "rpm", None, "mdi:engine"),
    "coolant_c": ("Coolant temperature", "number", -60, 200, "°C", "temperature", None),
    "oil_c": ("Oil temperature", "number", -60, 250, "°C", "temperature", None),
    "battery_v": ("Battery voltage", "number", 0, 20, "V", "voltage", None),
    "gear": ("Gear", "number", -1, 10, None, None, "mdi:car-shift-pattern"),
    "condition": ("Vehicle condition", "number", 0, 20, None, None, "mdi:car-info"),
    "stage": ("Selector", "text", None, None, None, None, "mdi:car-shift-pattern"),
    "moving": ("Moving", "flag", None, None, None, "moving", None),
    "engine": ("Engine running", "flag", None, None, None, "running", None),
}
CAR_STALE_S = 900   # no word from the car for this long: its sensors go to "unavailable"


def clean_car(data) -> dict:
    """The known fields of a car report, each of the right type and inside its range; the rest is dropped."""
    out = {}
    if not isinstance(data, dict):
        return out
    for key, (_name, kind, low, high, _unit, _cls, _icon) in CAR_FIELDS.items():
        v = data.get(key)
        if v is None:
            continue
        if kind == "flag":
            if isinstance(v, bool):
                out[key] = v
        elif kind == "number":
            if isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and low <= v <= high:
                out[key] = round(float(v), 1)
        elif isinstance(v, str):
            text = "".join(ch for ch in v if ch.isalnum() or ch in " -")[:16].strip()
            if text:
                out[key] = text
    return out


def car_entities(clean: dict, online: bool = True) -> list:
    """One Home Assistant state per reported field: [(entity_id, state, attributes)].

    Numbers are sensors with their unit, flags are binary sensors. With online False every known
    field is given as "unavailable", so a car that has gone quiet does not keep its last speed."""
    out = []
    for key, (name, kind, _low, _high, unit, cls, icon) in CAR_FIELDS.items():
        if online and key not in clean:
            continue
        domain = "binary_sensor" if kind == "flag" else "sensor"
        attrs = {"friendly_name": "Car " + name.lower()}
        if unit:
            attrs["unit_of_measurement"] = unit
        if cls:
            attrs["device_class"] = cls
        if icon:
            attrs["icon"] = icon
        if kind == "number" and unit:
            attrs["state_class"] = "measurement"
        if not online:
            state = "unavailable"
        elif kind == "flag":
            state = "on" if clean[key] else "off"
        elif kind == "number":
            v = clean[key]
            state = str(int(v)) if float(v).is_integer() else str(v)
        else:
            state = clean[key]
        out.append((domain + ".car_relay_" + key, state, attrs))
    return out


# ---------------------------------------------------------------------------------------------
# Where the car is. Off by default: a report's position is dropped unless the owner set
# accept_position in the configuration. Then it is shown as a device tracker, and like the rest of
# what a car says about itself it is only ever shown.

def clean_position(data):
    """(lat, lon, accuracy in metres or None) from a car report, or None when there is no usable position."""
    if not isinstance(data, dict):
        return None
    lat, lon, acc = data.get("lat"), data.get("lon"), data.get("accuracy_m")

    def real(v):
        return isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and abs(v) != float("inf")

    if not real(lat) or not real(lon) or not -90 <= lat <= 90 or not -180 <= lon <= 180:
        return None
    if lat == 0 and lon == 0:
        return None                     # a receiver with no fix reports the middle of the ocean
    acc = round(float(acc), 1) if real(acc) and 0 <= acc <= 100000 else None
    return round(float(lat), 6), round(float(lon), 6), acc


# ---------------------------------------------------------------------------------------------
# What a tile may do. Besides the built-in actions (the table in __init__.py), an owner can give a
# tile actions of their own: a name, the Home Assistant service to call and the data to call it with.
# That is their house and their call. Two things stay off unless they say so in the configuration
# (allow_unlock): the built-in "unlock" of a lock tile, and a service of their own that releases a
# lock or disarms an alarm directly.

SENSITIVE_SERVICES = {"lock.unlock", "lock.open", "alarm_control_panel.alarm_disarm"}
MAX_CUSTOM_ACTIONS = 6


def service_parts(service):
    """("light", "turn_on") from "light.turn_on", or None when it is not a service name."""
    if not isinstance(service, str):
        return None
    parts = service.strip().lower().split(".")
    if len(parts) != 2 or not all(p and all(ch.isalnum() or ch == "_" for ch in p) for p in parts):
        return None
    return parts[0], parts[1]


def needs_unlock_permission(service) -> bool:
    parts = service_parts(service)
    return bool(parts) and ".".join(parts) in SENSITIVE_SERVICES


def custom_actions(spec, allow_unlock: bool) -> dict:
    """An owner's own actions for a tile, checked: {name: {"domain", "service", "data", "label", "confirm"}}.

    Anything malformed is left out, and so is a lock release or alarm disarm without allow_unlock.
    The second value returned lists what was left out and why, for the log."""
    out, dropped = {}, []
    if not isinstance(spec, dict):
        return out, dropped
    for name, a in list(spec.items())[:MAX_CUSTOM_ACTIONS * 4]:
        key = str(name).strip().lower()
        if not key or len(key) > 24 or not all(ch.isalnum() or ch == "_" for ch in key):
            dropped.append((str(name)[:24], "not a usable name"))
            continue
        if not isinstance(a, dict):
            dropped.append((key, "not an action"))
            continue
        parts = service_parts(a.get("service"))
        if not parts:
            dropped.append((key, "no service"))
            continue
        if needs_unlock_permission(a.get("service")) and not allow_unlock:
            dropped.append((key, "needs allow_unlock"))
            continue
        if len(out) >= MAX_CUSTOM_ACTIONS:
            dropped.append((key, "too many actions on one tile"))
            continue
        data = a.get("data") if isinstance(a.get("data"), dict) else {}
        label = str(a.get("label") or key.replace("_", " ").capitalize())[:24]
        out[key] = {"domain": parts[0], "service": parts[1], "data": dict(data), "label": label,
                    "confirm": a.get("confirm") is not False}
    return out, dropped
