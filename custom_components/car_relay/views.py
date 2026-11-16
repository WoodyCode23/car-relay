"""The HTTP surface the car talks to, all under /api/car_relay/v1/.

None of these use Home Assistant's own login (requires_auth = False): the car has no HA token.
/pair and /pair/status are open to the internet but do nothing unless an admin opened a pairing
window, and a pairing only completes when an allowed HA user approves its code. Everything else
needs the device token in the X-Car-Token header. Failures return plain JSON errors rather than
raising, so a wrong token never feeds Home Assistant's own login-failure / IP-ban handling.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

from aiohttp import web

from homeassistant.components.http import HomeAssistantView
from homeassistant.core import Context, HomeAssistant

from .core import clean_car

_LOGGER = logging.getLogger(__name__)

BASE = "/api/car_relay/v1"
MAX_BODY = 4096
MAX_WAIT_S = 25


def _err(status: int, code: str):
    return web.json_response({"error": code}, status=status)


async def _body(request: web.Request):
    """The JSON object in the request body, or None. Never more than MAX_BODY bytes."""
    try:
        raw = await request.content.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            return None
        data = json.loads(raw.decode("utf-8") or "{}")
        return data if isinstance(data, dict) else None
    except (ValueError, UnicodeDecodeError):
        return None


class _View(HomeAssistantView):
    requires_auth = False
    cors_allowed = False

    def __init__(self, rt, actions):
        self.rt = rt
        self.actions = actions

    def device(self, request):
        dev = self.rt.relay.auth(request.headers.get("X-Car-Token", ""))
        return dev


class PairView(_View):
    url = BASE + "/pair"
    name = "api:car_relay:pair"

    async def post(self, request):
        data = await _body(request)
        if data is None:
            return _err(400, "bad-json")
        status, payload = self.rt.relay.pair_start(data.get("name"))
        if status != "ok":
            return _err(403 if status != "busy" else 429, status)
        _LOGGER.warning("car_relay: a car asked to pair (code %s)", payload["code"])
        return web.json_response(payload)


class PairStatusView(_View):
    url = BASE + "/pair/status"
    name = "api:car_relay:pair_status"

    async def post(self, request):
        data = await _body(request)
        if data is None:
            return _err(400, "bad-json")
        status, token = self.rt.relay.pair_status(data.get("pair_id"))
        out = {"status": status}
        if token:
            out["token"] = token
            self.rt.changed()
        return web.json_response(out)


class PollView(_View):
    url = BASE + "/poll"
    name = "api:car_relay:poll"

    async def get(self, request):
        if not self.device(request):
            return _err(401, "bad-token")
        try:
            since = int(request.query.get("since", "0"))
            wait = min(MAX_WAIT_S, max(0.0, float(request.query.get("wait", "0"))))
        except ValueError:
            return _err(400, "bad-query")
        if wait:
            await self.rt.wait_change(since, wait)
            self.rt.relay.auth(request.headers.get("X-Car-Token", ""))     # still here: refresh last_seen
        return web.json_response(self.rt.snapshot(since))


class ScanView(_View):
    url = BASE + "/scan"
    name = "api:car_relay:scan"

    async def post(self, request):
        if not self.device(request):
            return _err(401, "bad-token")
        return web.json_response(self.rt.relay.scan_new())


class LockView(_View):
    url = BASE + "/lock"
    name = "api:car_relay:lock"

    async def post(self, request):
        if not self.device(request):
            return _err(401, "bad-token")
        data = await _body(request) or {}
        self.rt.relay.lock("button" if data.get("reason") == "button" else "ignition-off")
        self.rt.changed()
        return web.json_response({"ok": True, "session": self.rt.relay.session()})


class ActionView(_View):
    url = BASE + "/action"
    name = "api:car_relay:action"

    async def post(self, request):
        if not self.device(request):
            return _err(401, "bad-token")
        data = await _body(request)
        if data is None:
            return _err(400, "bad-json")
        rt = self.rt
        if not rt.relay.session()["unlocked"]:
            return _err(403, "locked")
        tile = rt.tiles.get(str(data.get("tile")))
        action = str(data.get("action"))
        if not tile or action not in tile["actions"]:
            return _err(404, "no-such-action")
        spec = self.actions.get((tile["kind"], action))
        if not spec:
            return _err(404, "no-such-action")
        domain, service, need = spec
        if not data.get("nonce"):
            return _err(400, "nonce-required")
        if not rt.relay.nonce(data.get("nonce")):
            return web.json_response({"ok": True, "duplicate": True})
        st = rt.hass.states.get(tile["entity"])
        if need is not None and (st is None or st.state != need):
            return web.json_response(
                {"error": "wrong-state", "state": st.state if st else "unavailable", "need": need}, status=409)
        hass: HomeAssistant = rt.hass
        _LOGGER.info("car_relay: %s.%s on %s", domain, service, tile["entity"])
        try:
            await hass.services.async_call(
                domain, service, {"entity_id": tile["entity"]}, blocking=True, context=Context())
        except Exception as err:  # noqa: BLE001 - whatever the integration raised, the car gets a clean answer
            _LOGGER.warning("car_relay: %s.%s failed: %s", domain, service, err)
            return _err(502, "action-failed")
        return web.json_response({"ok": True})


class CarView(_View):
    url = BASE + "/car"
    name = "api:car_relay:car"

    async def post(self, request):
        if not self.device(request):
            return _err(401, "bad-token")
        data = await _body(request)
        if data is None:
            return _err(400, "bad-json")
        clean = clean_car(data)
        # Informational only. This comes from the car, so never let it gate a security action.
        self.rt.publish_car(clean)
        return web.json_response({"ok": True})


class CameraView(_View):
    url = BASE + "/camera/{camera}"
    name = "api:car_relay:camera"

    async def get(self, request, camera):
        if not self.device(request):
            return _err(401, "bad-token")
        if not self.rt.relay.session()["unlocked"]:
            return _err(403, "locked")
        entity = self.rt.cameras.get(camera)
        if not entity:
            return _err(404, "no-such-camera")
        from homeassistant.components.camera import async_get_image  # late: camera may load after us

        try:
            image = await async_get_image(self.rt.hass, entity, timeout=10, width=640)
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning("car_relay: camera %s: %s", entity, err)
            return _err(502, "camera-failed")
        return web.Response(body=image.content, content_type=image.content_type,
                            headers={"Cache-Control": "no-store"})


STREAM_MAX_S = 120   # a live view is cut off after this long, whatever the car does


class CameraStreamView(_View):
    """The camera as moving pictures: Home Assistant's own MJPEG stream of a camera named under live_cameras.

    The same gate as a still (paired and unlocked), checked every second while it runs: a lock ends the
    stream, and so does STREAM_MAX_S. 404 when no live camera has that name, so an older car app or a
    setup without one falls back to stills.
    """
    url = BASE + "/camera/{camera}/stream"
    name = "api:car_relay:camera_stream"

    async def get(self, request, camera):
        if not self.device(request):
            return _err(401, "bad-token")
        if not self.rt.relay.session()["unlocked"]:
            return _err(403, "locked")
        entity = self.rt.live_cameras.get(camera)
        if not entity:
            return _err(404, "no-such-camera")
        from homeassistant.components.camera import async_get_mjpeg_stream  # late: camera may load after us

        async def guard():
            end = time.monotonic() + STREAM_MAX_S
            while time.monotonic() < end and self.rt.relay.session()["unlocked"]:
                await asyncio.sleep(1)
            if request.transport is not None:
                request.transport.close()

        task = self.rt.hass.async_create_background_task(guard(), "car_relay stream guard")
        resp = None
        try:
            resp = await async_get_mjpeg_stream(self.rt.hass, request, entity)
        except (ConnectionError, asyncio.CancelledError):
            raise
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning("car_relay: live camera %s: %s", entity, err)
        finally:
            task.cancel()
        return resp if resp is not None else _err(502, "camera-failed")


def async_register_views(hass: HomeAssistant, rt, actions):
    for view in (PairView, PairStatusView, PollView, ScanView, LockView, ActionView, CarView, CameraView,
                 CameraStreamView):
        hass.http.register_view(view(rt, actions))
