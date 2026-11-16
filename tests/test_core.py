"""Plain-Python tests for the car_relay state machine: py -m unittest discover -s tests"""
import importlib.util
import os
import unittest
from datetime import datetime, timezone

_path = os.path.join(os.path.dirname(__file__), "..", "custom_components", "car_relay", "core.py")
_spec = importlib.util.spec_from_file_location("car_relay_core", _path)
core = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(core)

OWNER, PARTNER, STRANGER = "u-owner", "u-partner", "u-stranger"


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def make(scan_hours=None, start=None):
    # 2026-11-10 15:00 UTC unless told otherwise
    clock = Clock(start or datetime(2026, 11, 10, 15, 0, tzinfo=timezone.utc).timestamp())
    cfg = {
        "lock_after_s": 600, "scan_hours": scan_hours, "allowed_users": {OWNER, PARTNER},
        "max_devices": 1, "qr_template": "app://scan?c={code}",
    }
    return core.Relay(cfg, tz=timezone.utc, now=clock), clock


def pair(r):
    r.open_pairing(10)
    status, p = r.pair_start("M3")
    assert status == "ok"
    assert r.scan(p["code"], OWNER) == "paired"
    status, token = r.pair_status(p["pair_id"])
    assert status == "approved"
    return token


class Pairing(unittest.TestCase):
    def test_closed_by_default(self):
        r, _ = make()
        self.assertEqual(r.pair_start("x")[0], "pairing-closed")

    def test_full_flow_and_token_once(self):
        r, _ = make()
        r.open_pairing(10)
        _, p = r.pair_start("M3")
        self.assertEqual(p["qr"], "app://scan?c=" + p["code"])
        self.assertEqual(r.pair_status(p["pair_id"]), ("pending", None))
        self.assertEqual(r.scan(p["code"].lower(), OWNER), "paired")
        status, token = r.pair_status(p["pair_id"])
        self.assertEqual(status, "approved")
        self.assertEqual(r.pair_status(p["pair_id"]), ("unknown", None))
        self.assertIsNotNone(r.auth(token))
        self.assertNotIn(token.split(".", 1)[1], str(r.to_store()))    # only the hash is stored

    def test_stranger_cannot_approve(self):
        r, _ = make()
        r.open_pairing(10)
        _, p = r.pair_start("M3")
        self.assertEqual(r.scan(p["code"], STRANGER), "forbidden")
        self.assertEqual(r.scan(p["code"], None), "forbidden")
        self.assertEqual(r.pair_status(p["pair_id"]), ("pending", None))

    def test_window_closes_after_pairing_and_device_limit(self):
        r, _ = make()
        pair(r)
        self.assertEqual(r.pair_start("second")[0], "pairing-closed")
        r.open_pairing(10)
        self.assertEqual(r.pair_start("second")[0], "device-limit")

    def test_code_expires(self):
        r, clock = make()
        r.open_pairing(10)
        _, p = r.pair_start("M3")
        clock.t += core.PAIR_TTL_S + 1
        self.assertEqual(r.scan(p["code"], OWNER), "unknown")

    def test_pending_cap(self):
        r, _ = make()
        r.open_pairing(10)
        for _ in range(core.MAX_PENDING):
            self.assertEqual(r.pair_start("x")[0], "ok")
        self.assertEqual(r.pair_start("x")[0], "busy")

    def test_bad_tokens(self):
        r, _ = make()
        token = pair(r)
        dev = token.split(".")[0]
        for bad in ["", "nodot", dev + ".wrong", "nope." + token.split(".", 1)[1]]:
            self.assertIsNone(r.auth(bad))

    def test_unpair(self):
        r, _ = make()
        token = pair(r)
        self.assertTrue(r.unpair(token.split(".")[0]))
        self.assertIsNone(r.auth(token))


class Session(unittest.TestCase):
    def test_pairing_scan_unlocks(self):
        r, _ = make()
        pair(r)
        self.assertEqual(r.session(), {"unlocked": True, "reason": "ok"})

    def test_phone_presence(self):
        r, _ = make()
        pair(r)
        r.phone(OWNER, False)
        self.assertEqual(r.session()["reason"], "no-phone")
        self.assertTrue(r.phone(PARTNER, True))
        self.assertTrue(r.session()["unlocked"])
        self.assertFalse(r.phone(STRANGER, True))

    def test_stranger_phone_never_unlocks(self):
        r, _ = make()
        pair(r)
        r.lock("ignition-off")
        r.phone(STRANGER, True)
        self.assertFalse(r.session()["unlocked"])

    def test_button_lock_needs_scan(self):
        r, _ = make()
        pair(r)
        r.lock("button")
        r.phone(OWNER, True)                      # CarPlay alone is not enough
        self.assertEqual(r.session(), {"unlocked": False, "reason": "scan-required"})
        s = r.scan_new()
        self.assertEqual(r.scan(s["code"], STRANGER), "forbidden")
        self.assertEqual(r.scan(s["code"], PARTNER), "unlocked")
        self.assertTrue(r.session()["unlocked"])
        self.assertEqual(r.scan(s["code"], OWNER), "unknown")     # single use

    def test_ignition_off_is_undone_by_carplay(self):
        r, _ = make()
        pair(r)
        r.lock("ignition-off")
        self.assertEqual(r.session()["reason"], "no-phone")
        r.phone(OWNER, True)
        self.assertTrue(r.session()["unlocked"])

    def test_silence_forgets_phones(self):
        r, clock = make()
        token = pair(r)
        r.auth(token)
        clock.t += 300
        r.tick()
        self.assertTrue(r.session()["unlocked"])          # under lock_after
        clock.t += 400
        r.tick()
        self.assertEqual(r.session()["reason"], "no-phone")

    def test_fresh_connect_survives_before_car_speaks(self):
        r, clock = make()
        token = pair(r)
        r.auth(token)
        clock.t += 86400                                   # parked overnight
        r.tick()
        r.phone(OWNER, True)                                # CarPlay connects first
        clock.t += 30
        r.tick()
        self.assertTrue(r.session()["unlocked"])
        r.auth(token)
        clock.t += 500
        r.auth(token)
        clock.t += 500
        r.tick()
        self.assertTrue(r.session()["unlocked"])          # car kept talking

    def test_scan_code_expires(self):
        r, clock = make()
        pair(r)
        r.lock("button")
        s = r.scan_new()
        clock.t += core.SCAN_TTL_S + 1
        self.assertEqual(r.scan(s["code"], OWNER), "unknown")

    def test_scan_hours_wrapping(self):
        t = datetime(2026, 11, 10, 22, 0, tzinfo=timezone.utc).timestamp()
        r, clock = make(scan_hours=(23 * 60, 5 * 60), start=t)
        pair(r)                                            # scanned at 22:00
        self.assertTrue(r.session()["unlocked"])
        clock.t += 2 * 3600                                # 00:00, inside the window
        self.assertEqual(r.session()["reason"], "scan-required-hours")
        r.phone(OWNER, True)
        self.assertFalse(r.session()["unlocked"])
        s = r.scan_new()
        self.assertEqual(r.scan(s["code"], OWNER), "unlocked")
        self.assertTrue(r.session()["unlocked"])
        clock.t += 3 * 3600                                # 03:00, same window, still good
        self.assertTrue(r.session()["unlocked"])
        clock.t += 3 * 3600                                # 06:00, outside
        self.assertTrue(r.session()["unlocked"])
        clock.t += 18 * 3600                               # 00:00 next night
        self.assertEqual(r.session()["reason"], "scan-required-hours")

    def test_nonce(self):
        r, clock = make()
        self.assertTrue(r.nonce("a"))
        self.assertFalse(r.nonce("a"))
        self.assertFalse(r.nonce(""))
        clock.t += core.NONCE_TTL_S + 1
        self.assertTrue(r.nonce("a"))

    def test_persistence_round_trip(self):
        r, clock = make()
        token = pair(r)
        r.lock("button")
        r2 = core.Relay(r.cfg, data=r.to_store(), tz=timezone.utc, now=clock)
        self.assertIsNotNone(r2.auth(token))
        self.assertEqual(r2.session()["reason"], "scan-required")

class CarReport(unittest.TestCase):
    def test_known_fields_are_kept_and_rounded(self):
        got = core.clean_car({"speed_kmh": 88.26, "rpm": 2100, "coolant_c": 91.04, "moving": True, "engine": True, "stage": "D", "gear": 4})
        self.assertEqual(got, {"speed_kmh": 88.3, "rpm": 2100.0, "coolant_c": 91.0, "gear": 4.0, "stage": "D", "moving": True, "engine": True})

    def test_anything_else_is_dropped(self):
        bad = {"speed_kmh": 9999, "rpm": -5, "coolant_c": "hot", "oil_c": float("nan"), "battery_v": True, "moving": "yes",
               "engine": 1, "stage": "<b>D</b>\n" + "x" * 50, "lat": 40.1, "lon": -83.0, "vin": "X", "token": "t", "extra": {"a": 1}}
        got = core.clean_car(bad)
        self.assertEqual(set(got), {"stage"})
        self.assertEqual(got["stage"], ("bDb" + "x" * 50)[:16])
        for junk in (None, 5, "x", [1, 2], {"speed_kmh": None}):
            self.assertEqual(core.clean_car(junk), {})

    def test_no_position_field_exists(self):
        self.assertFalse(set(core.CAR_FIELDS) & {"lat", "lon", "latitude", "longitude", "gps", "position", "vin"})
        self.assertEqual(core.clean_car({"lat": 1.0, "longitude": 2.0, "position": "x", "vin": "X"}), {})

    def test_each_field_becomes_its_own_state(self):
        ents = {e: (s, a) for e, s, a in core.car_entities(core.clean_car({"speed_kmh": 50, "oil_c": 98.5, "engine": True, "moving": False, "stage": "P"}))}
        self.assertEqual(ents["sensor.car_relay_speed_kmh"][0], "50")
        self.assertEqual(ents["sensor.car_relay_speed_kmh"][1]["unit_of_measurement"], "km/h")
        self.assertEqual(ents["sensor.car_relay_speed_kmh"][1]["state_class"], "measurement")
        self.assertEqual(ents["sensor.car_relay_oil_c"][0], "98.5")
        self.assertEqual(ents["sensor.car_relay_oil_c"][1]["device_class"], "temperature")
        self.assertEqual(ents["binary_sensor.car_relay_engine"][0], "on")
        self.assertEqual(ents["binary_sensor.car_relay_moving"][0], "off")
        self.assertEqual(ents["sensor.car_relay_stage"][0], "P")
        self.assertNotIn("sensor.car_relay_rpm", ents)

    def test_a_quiet_car_is_unavailable_not_frozen(self):
        ents = core.car_entities({}, online=False)
        self.assertEqual(len(ents), len(core.CAR_FIELDS))
        self.assertTrue(all(state == "unavailable" for _e, state, _a in ents))


if __name__ == "__main__":
    unittest.main()
