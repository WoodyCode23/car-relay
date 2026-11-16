# Car Relay

A Home Assistant custom component that gives an app on a car's head unit a narrow, lockable window onto your
house, and gives Home Assistant a read-only view of the car.

It was built for the BMW iDrive 7 app `woodr_hass` in
[woody-apps](https://github.com/WoodyCode23/woody-apps), on one car (a 2022 G80 M3). Nothing in it is specific to
that car: anything that can make HTTPS requests can be the "car".

## What it does

**The house, from the car**
- Tiles you choose: garage doors, a lock, lights, switches, scenes, scripts, sensors, cameras.
- A doorbell or motion alert that brings a camera picture up in the car.

**The car, in Home Assistant**
- What the car reports about itself becomes sensors: speed, engine speed, coolant and oil temperature, battery
  voltage, gear, and whether the engine is running and the car is moving.
- A car that has said nothing for 15 minutes shows as unavailable, not as its last value.

## What it will not do

- **The car never holds a Home Assistant token or password.** It pairs once and gets a token that only this
  component understands.
- **The car can never unlock a door.** There is no unlock action in the code, whatever you configure.
- **Home Assistant cannot control the car.** The car only reports; nothing here sends it a command.
- **No position.** The car's report has no location field, and one sent anyway is dropped.
- **What the car says about itself decides nothing.** It is shown, never used to allow an action.

## Install

With HACS: add this repository as a custom repository (type "Integration"), install "Car Relay", restart Home
Assistant.

By hand: copy `custom_components/car_relay` into your Home Assistant `config/custom_components` folder and
restart.

Take a backup first. Your Home Assistant has to be reachable from the car over HTTPS (Home Assistant Cloud, or
your own domain with a certificate).

## Configure

Add this to `configuration.yaml`, with your own entities, then restart:

```yaml
car_relay:
  allowed_users: ["<home assistant user id>"]   # who may approve a car, and whose phone counts
  lock_after_minutes: 10
  tiles:
    - { id: garage, name: Garage, entity: cover.garage_door, kind: cover, actions: [open, close] }
    - { id: front_door, name: Front door, entity: lock.front_door, kind: lock, actions: [lock] }
    - { id: porch, name: Porch light, entity: light.porch, kind: light, actions: [on, off] }
    - { id: outside, name: Outside, entity: sensor.outdoor_temperature, kind: sensor }
  cameras: { front_door: camera.front_door }
  doorbell: { trigger: binary_sensor.front_door_ding, to: "on", camera: front_door, label: Front door }
```

- **`allowed_users`** are Home Assistant user ids (Settings, People, Users, pick a user, the id is at the bottom).
  Leave it empty and any Home Assistant user can approve a car, which the log warns about.
- **Tile kinds and actions:** `cover` (open, close, stop), `lock` (lock), `light` and `switch` (on, off),
  `scene` (activate), `script` (run), `sensor` and `camera` (nothing to press).
- **Optional:** `scan_hours: { start: "23:00", end: "05:00" }` asks for a fresh scan during those hours;
  `live_cameras` gives moving pictures for a camera name; `alerts` is a list of further triggers shaped like
  `doorbell`; `max_devices` (1 to 4) is how many cars may be paired.

## Pair a car

1. In Home Assistant, call the service `car_relay.open_pairing` (admin only). Pairing is closed at all other times.
2. On the car, choose to pair. It shows a QR code.
3. Scan it with the Home Assistant companion app on a phone signed in as an allowed user, and approve.

To remove a car, call `car_relay.unpair`. It takes effect at once.

## The lock

A paired car shows its tiles only while an allowed phone is in the car.

- **Scan:** scanning the code on the car's lock screen with an allowed phone opens the tiles. This always works.
- **Automatic:** two phone automations that call `car_relay.phone_connected` and `car_relay.phone_disconnected`
  when the phone joins and leaves the car (on iPhone, Shortcuts triggered by CarPlay) do it without scanning.
- **Lock button:** the car's Lock button hides the house until the next scan.
- After `lock_after_minutes` without a word from the car, it locks by itself.

An automation cannot open the tiles: the component checks which Home Assistant user a request came from.

## Entities

| Entity | What it is |
|---|---|
| `sensor.car_relay_session` | locked or unlocked, with the reason, the paired cars and when one was last heard |
| `sensor.car_relay_speed_kmh`, `_rpm`, `_coolant_c`, `_oil_c`, `_battery_v`, `_gear`, `_stage`, `_condition` | what the car reports |
| `binary_sensor.car_relay_engine`, `binary_sensor.car_relay_moving` | engine running, car moving |
| `sensor.car_relay_car` | the same report in one entity's attributes (kept for older dashboards) |

The car reports only while its head unit is on and has a way to the internet (a phone's hotspot or a cable).

## The address on the car

The car app needs to be told where this component lives (`https://<your address>/api/car_relay/v1`). On iDrive 7
that is a small file in the app's data folder today, which needs a shell on the head unit. A way to enter it
from the car's own screen is being worked on.

## For developers

The rules (pairing, phone presence, the lock, what a car report may contain) are in `core.py`, which imports
nothing from Home Assistant. `py -m unittest discover -s tests` runs its tests. The HTTP surface is in `views.py`:
everything is under `/api/car_relay/v1/`, and everything but pairing needs the car's token in `X-Car-Token`.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE). It comes with no warranty of any kind: it opens garage doors, so read
it before you run it.
