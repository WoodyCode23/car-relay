"""Car Relay: a narrow, lockable window onto Home Assistant for an app on a car's head unit.

The car never holds a Home Assistant token. It pairs once (an allowed HA user scans the code on
its screen), then talks to the views in views.py with its own device token, which can only reach
the tiles and cameras named in the configuration, and only while an allowed phone is in the car.
The pairing / phone / lock rules are in core.py.

configuration.yaml:

  car_relay:
    allowed_users: ["<ha user id>", ...]     # who may scan and whose phone counts
    lock_after_minutes: 10
    scan_hours: { start: "23:00", end: "05:00" }     # optional
    tiles:
      - { id: big_garage, name: Big Garage, entity: cover.x, kind: cover, actions: [open, close] }
    cameras: { front_door: camera.front_door_snapshot }
    live_cameras: { front_door: camera.front_door_live }   # optional: moving pictures for the same name
    doorbell: { trigger: binary_sensor.front_door_ding, to: "on", camera: front_door, label: Front door }

The other way round, the car may report how it is doing (speed, temperatures, engine running: views.py
/car, core.py CAR_FIELDS). Each field shows up as sensor.car_relay_<field> or binary_sensor.car_relay_<field>.
It is read-only in both senses: Home Assistant cannot ask the car to do anything, and what the car says
about itself never decides a lock or an action.
"""
from __future__ import annotations

import asyncio
import logging
from collections import deque
from datetime import timedelta

import voluptuous as vol

from homeassistant.const import STATE_UNAVAILABLE, STATE_UNKNOWN
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.event import async_track_state_change_event, async_track_time_interval
from homeassistant.helpers.service import async_register_admin_service
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .core import CAR_STALE_S, Relay, car_entities, parse_hhmm
from .views import async_register_views

_LOGGER = logging.getLogger(__name__)

DOMAIN = "car_relay"
SCAN_EVENT = "car_relay_scan"
PHONE_EVENT = "car_relay_phone"
SESSION_ENTITY = "sensor.car_relay_session"

# (tile kind, action) -> (domain, service, state the entity must be in, or None).
# lock.unlock is deliberately absent: the car can never unlock a door.
ACTIONS = {
    ("cover", "open"): ("cover", "open_cover", "closed"),
    ("cover", "close"): ("cover", "close_cover", "open"),
    ("cover", "stop"): ("cover", "stop_cover", None),
    ("lock", "lock"): ("lock", "lock", None),
    ("light", "on"): ("light", "turn_on", None),
    ("light", "off"): ("light", "turn_off", None),
    ("switch", "on"): ("switch", "turn_on", None),
    ("switch", "off"): ("switch", "turn_off", None),
    ("scene", "activate"): ("scene", "turn_on", None),
    ("script", "run"): ("script", "turn_on", None),
    ("sensor", None): None,
}
# "camera" is a tile with nothing to press in the house: the car shows that camera when it is chosen.
KINDS = sorted({k for k, _ in ACTIONS} | {"camera"})

TILE = vol.Schema({
    vol.Required("id"): cv.slug,
    vol.Required("name"): cv.string,
    vol.Required("entity"): cv.entity_id,
    vol.Required("kind"): vol.In(KINDS),
    vol.Optional("actions", default=list): [cv.string],
    vol.Optional("camera"): cv.slug,   # kind camera: its name under cameras / live_cameras
    vol.Optional("info"): cv.entity_id,   # a line of text for the tile (and its picture): that entity's state
})

# The doorbell, and anything else that should pop the camera up in the car (motion, a person seen).
# person_only: only when the trigger's personDetected attribute is true. cooldown: seconds before it may fire again.
ALERT = vol.Schema({
    vol.Required("trigger"): cv.entity_id,
    vol.Optional("to", default="on"): cv.string,
    vol.Optional("camera"): cv.slug,
    vol.Optional("label", default="Front door"): cv.string,
    vol.Optional("person_only", default=False): cv.boolean,
    vol.Optional("cooldown", default=0): vol.All(vol.Coerce(float), vol.Range(min=0, max=3600)),
})

CONFIG_SCHEMA = vol.Schema({
    DOMAIN: vol.Schema({
        vol.Optional("allowed_users", default=list): [cv.string],
        vol.Optional("lock_after_minutes", default=10): vol.All(vol.Coerce(float), vol.Range(min=1, max=240)),
        vol.Optional("scan_hours"): vol.Schema({vol.Required("start"): cv.string, vol.Required("end"): cv.string}),
        vol.Optional("max_devices", default=1): vol.All(int, vol.Range(min=1, max=4)),
        vol.Optional("qr_template", default="homeassistant://fire_event/" + SCAN_EVENT + "?c={code}"): cv.string,
        vol.Optional("tiles", default=list): [TILE],
        vol.Optional("cameras", default=dict): {cv.slug: cv.entity_id},
        vol.Optional("live_cameras", default=dict): {cv.slug: cv.entity_id},
        vol.Optional("doorbell"): ALERT,
        vol.Optional("alerts", default=list): [ALERT],
    })
}, extra=vol.ALLOW_EXTRA)


class Runtime:
    """What the views and services share: the relay, the tiles, and the change counter."""

    def __init__(self, hass: HomeAssistant, conf, relay: Relay, store: Store):
        self.hass = hass
        self.conf = conf
        self.relay = relay
        self.store = store
        self.tiles = {t["id"]: t for t in conf["tiles"]}
        for t in self.tiles.values():
            bad = [a for a in t["actions"] if (t["kind"], a) not in ACTIONS]
            if bad:
                _LOGGER.warning("tile %s: dropping unsupported actions %s", t["id"], bad)
                t["actions"] = [a for a in t["actions"] if a not in bad]
        self.cameras = conf["cameras"]
        self.live_cameras = conf["live_cameras"]   # same names: a camera whose MJPEG stream is worth sending
        self.seq = 1
        self.events = deque(maxlen=20)
        self._changed = asyncio.Event()
        self._session = None
        self.car = {}
        self.car_at = 0.0
        self.car_online = False

    # ---- change tracking: every long-poll wakes on bump() ----

    @callback
    def bump(self):
        self.seq += 1
        ev, self._changed = self._changed, asyncio.Event()
        ev.set()

    async def wait_change(self, since: int, timeout: float):
        if self.seq != since:
            return
        try:
            await asyncio.wait_for(self._changed.wait(), timeout)
        except asyncio.TimeoutError:
            pass

    @callback
    def push_event(self, kind: str, data: dict):
        self.seq += 1
        self.events.append(dict(data, type=kind, seq=self.seq, at=int(self.relay.now())))
        ev, self._changed = self._changed, asyncio.Event()
        ev.set()

    @callback
    def changed(self):
        """Call after anything that may have altered the relay: saves, publishes, wakes polls."""
        if self.relay.dirty:
            self.relay.dirty = False
            self.store.async_delay_save(self.relay.to_store, 2)
        s = self.relay.session()
        if s != self._session:
            self._session = s
            self.bump()
        self.hass.states.async_set(SESSION_ENTITY, "unlocked" if s["unlocked"] else "locked", {
            "reason": s["reason"],
            "phones_in_car": len(self.relay.phones),
            "paired_cars": {k: v["name"] for k, v in self.relay.devices.items()},
            "last_seen": dt_util.utc_from_timestamp(self.relay.last_seen).isoformat() if self.relay.last_seen else None,
            "friendly_name": "Car relay session",
            "icon": "mdi:car-key",
        })

    # ---- what the car says about itself ----

    @callback
    def publish_car(self, clean: dict):
        """A report from the car: one state per field, plus the summary entity older dashboards use."""
        self.car = clean
        self.car_at = self.relay.now()
        self.car_online = True
        for entity_id, state, attrs in car_entities(clean):
            self.hass.states.async_set(entity_id, state, attrs)
        self.hass.states.async_set("sensor.car_relay_car", "online", dict(
            clean, friendly_name="Car (reported by the head unit)", icon="mdi:car-sports"))

    @callback
    def car_tick(self):
        """Called on the timer: a car that has said nothing for CAR_STALE_S is shown as unavailable."""
        if self.car_online and self.relay.now() - self.car_at > CAR_STALE_S:
            self.car_online = False
            for entity_id, state, attrs in car_entities({}, online=False):
                if self.hass.states.get(entity_id) is not None:
                    self.hass.states.async_set(entity_id, state, attrs)
            self.hass.states.async_set("sensor.car_relay_car", "offline", {
                "friendly_name": "Car (reported by the head unit)", "icon": "mdi:car-sports"})

    # ---- what the car is told ----

    def _info(self, entity):
        st = self.hass.states.get(entity)
        return "" if st is None or st.state in (STATE_UNAVAILABLE, STATE_UNKNOWN) else str(st.state)[:120]

    def tile_view(self, t):
        st = self.hass.states.get(t["entity"])
        state = st.state if st else STATE_UNAVAILABLE
        return {
            "id": t["id"], "name": t["name"], "kind": t["kind"], "state": state,
            "ok": state not in (STATE_UNAVAILABLE, STATE_UNKNOWN),
            "unit": (st.attributes.get("unit_of_measurement") if st else None) or "",
            "actions": t["actions"],
            **({"camera": t["camera"]} if t.get("camera") else {}),
            **({"info": self._info(t["info"])} if t.get("info") else {}),
        }

    def snapshot(self, since: int):
        s = self.relay.session()
        out = {"seq": self.seq, "session": s, "tiles": [], "events": []}
        if s["unlocked"]:
            out["tiles"] = [self.tile_view(t) for t in self.tiles.values()]
            out["events"] = [e for e in self.events if e["seq"] > since]
        return out


async def async_setup(hass: HomeAssistant, config) -> bool:
    conf = config.get(DOMAIN)
    if conf is None:
        return True

    hours = None
    if conf.get("scan_hours"):
        hours = (parse_hhmm(conf["scan_hours"]["start"]), parse_hhmm(conf["scan_hours"]["end"]))
    store = Store(hass, 1, DOMAIN)
    relay = Relay({
        "lock_after_s": conf["lock_after_minutes"] * 60,
        "scan_hours": hours,
        "allowed_users": set(conf["allowed_users"]),
        "max_devices": conf["max_devices"],
        "qr_template": conf["qr_template"],
    }, data=await store.async_load(), tz=dt_util.get_default_time_zone())
    if not conf["allowed_users"]:
        _LOGGER.warning("car_relay: allowed_users is empty, so ANY Home Assistant user can approve a car")
    rt = Runtime(hass, conf, relay, store)
    hass.data[DOMAIN] = rt

    # ---- scans and phone presence, from the companion app ----
    # Both arrive with the phone's own HA user in the context (mobile_app sets it), which is
    # what makes "an allowed user did this" checkable. An automation has no user and is refused.

    @callback
    def do_scan(code, user_id, how):
        result = relay.scan(code, user_id)
        _LOGGER.info("car_relay: scan via %s by %s -> %s", how, user_id, result)
        rt.changed()
        return result

    @callback
    def on_scan_event(event):
        do_scan(event.data.get("c") or event.data.get("code"), event.context.user_id, "event")

    @callback
    def on_phone_event(event):
        state = str(event.data.get("state", "")).lower()
        if state in ("connected", "disconnected"):
            relay.phone(event.context.user_id, state == "connected")
            rt.changed()

    hass.bus.async_listen(SCAN_EVENT, on_scan_event)
    hass.bus.async_listen(PHONE_EVENT, on_phone_event)

    async def svc_scan(call: ServiceCall):
        do_scan(call.data.get("code"), call.context.user_id, "service")

    async def svc_phone_on(call: ServiceCall):
        if not relay.phone(call.context.user_id, True):
            _LOGGER.warning("car_relay: phone_connected from a user that is not allowed (%s)", call.context.user_id)
        rt.changed()

    async def svc_phone_off(call: ServiceCall):
        relay.phone(call.context.user_id, False)
        rt.changed()

    async def svc_lock(call: ServiceCall):
        relay.lock("button")
        rt.changed()

    async def svc_open_pairing(call: ServiceCall):
        relay.open_pairing(float(call.data.get("minutes", 10)))
        _LOGGER.warning("car_relay: pairing window opened for %s minutes", call.data.get("minutes", 10))

    async def svc_unpair(call: ServiceCall):
        dev = call.data.get("device")
        if not dev:
            _LOGGER.warning("car_relay: paired cars: %s", {k: v["name"] for k, v in relay.devices.items()})
            return
        _LOGGER.warning("car_relay: unpair %s -> %s", dev, relay.unpair(str(dev)))
        rt.changed()

    hass.services.async_register(DOMAIN, "scan", svc_scan, vol.Schema({vol.Required("code"): cv.string}))
    hass.services.async_register(DOMAIN, "phone_connected", svc_phone_on)
    hass.services.async_register(DOMAIN, "phone_disconnected", svc_phone_off)
    hass.services.async_register(DOMAIN, "lock", svc_lock)
    async_register_admin_service(hass, DOMAIN, "open_pairing", svc_open_pairing,
                                 vol.Schema({vol.Optional("minutes", default=10): vol.Coerce(float)}))
    async_register_admin_service(hass, DOMAIN, "unpair", svc_unpair,
                                 vol.Schema({vol.Optional("device"): cv.string}))

    # ---- house state out to the car ----

    @callback
    def on_tile_state(event):
        rt.bump()

    watched = sorted({t["entity"] for t in rt.tiles.values()} | {t["info"] for t in rt.tiles.values() if t.get("info")})
    if watched:
        async_track_state_change_event(hass, watched, on_tile_state)

    def watch_alert(bell):
        last = [0.0]

        @callback
        def on_bell(event):
            new = event.data.get("new_state")
            old = event.data.get("old_state")
            if new is None or new.state != bell["to"] or (old is not None and old.state == new.state):
                return
            if bell["person_only"] and new.attributes.get("personDetected") is not True:
                return
            now = rt.relay.now()
            if bell["cooldown"] and now - last[0] < bell["cooldown"]:
                return
            last[0] = now
            # the car knows one kind of door alert; the label says which this was
            rt.push_event("doorbell", {"label": bell["label"], "camera": bell.get("camera")})

        async_track_state_change_event(hass, [bell["trigger"]], on_bell)

    for bell in ([conf["doorbell"]] if conf.get("doorbell") else []) + conf["alerts"]:
        watch_alert(bell)

    @callback
    def on_tick(now):
        relay.tick()
        rt.car_tick()
        rt.changed()

    async_track_time_interval(hass, on_tick, timedelta(seconds=30))

    async_register_views(hass, rt, ACTIONS)
    rt.changed()
    _LOGGER.info("car_relay: ready, %d tile(s), %d paired car(s)", len(rt.tiles), len(relay.devices))
    return True
