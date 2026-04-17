#!/usr/bin/env python3
"""Tesla CLI — talk to a running teslad over cereal.

Usage:
  tesla.py setup <VIN>            write VIN + generate key
  tesla.py status                 show local VIN/key state
  tesla.py state                  subscribe to teslaState (live, ctrl-C to exit)
  tesla.py <command> [args...]    send command to teslad, wait for state update

Commands (teslad must be running with an active BLE connection):
  whitelist                       send whitelist request (tap NFC card on console, 60s)
  reconnect                       re-negotiate VCSEC + infotainment sessions
  get_status                      request fresh VCSEC VehicleStatus
  data [kinds]                    fetch VehicleData. kinds: comma-separated subset of
                                  charge,climate,drive,location,closures,tires,media,
                                  media_detail,software  (or "all"). Default: charge,
                                  climate,drive,location,media

  unlock | lock
  trunk | close_trunk | frunk
  charge_port | close_charge_port
  wake | auto_secure | remote_drive
  door_<fd|fp|rd|rp>_<open|close>
  tonneau_<open|close>
  honk | flash | homelink | ping
  sentry <on|off> | bioweapon <on|off> | steering_heat <on|off>
  hvac <on|off>
  vent | close_windows
  temp <driver>[,<passenger>]
  seat_heat <fl|fr|rl|rc|rr|driver|passenger>,<off|low|med|high>
  media <play|next|prev>
  charge <start|stop>
  charge_limit <pct>
  name <name>
"""
import hashlib
import logging
import os
import sys
import time

import cereal.messaging as messaging
from openpilot.system.teslable.crypto import load_or_create_key, key_id
from openpilot.system.teslable.teslad import TESLA_VIN_PATH, TESLA_KEY_PATH

logging.basicConfig(level=logging.INFO, format='%(message)s', stream=sys.stdout)
log = logging.getLogger("tesla")


SESSION_COMMANDS = {
  "whitelist", "reconnect", "get_status", "data",
  "unlock", "lock", "trunk", "close_trunk", "frunk",
  "charge_port", "close_charge_port", "wake", "auto_secure", "remote_drive",
  "door_fd_open", "door_fd_close", "door_fp_open", "door_fp_close",
  "door_rd_open", "door_rd_close", "door_rp_open", "door_rp_close",
  "tonneau_open", "tonneau_close",
  "honk", "flash", "homelink", "ping",
  "sentry", "bioweapon", "steering_heat", "hvac",
  "vent", "close_windows",
  "temp", "seat_heat", "media", "charge", "charge_limit", "name",
}

# commands that take longer than the default response window
LONG_COMMANDS = {"whitelist": 70, "reconnect": 15}
DEFAULT_TIMEOUT = 10


def cmd_setup(vin):
  vin = vin.upper()
  os.makedirs(os.path.dirname(TESLA_VIN_PATH), exist_ok=True)
  with open(TESLA_VIN_PATH, "w") as f:
    f.write(vin)
  _, pub = load_or_create_key(TESLA_KEY_PATH)
  log.info(f"VIN:         {vin}")
  log.info(f"BLE name:    S{hashlib.sha1(vin.encode()).hexdigest()[:16]}C")
  log.info(f"key id:      {key_id(pub).hex()}")
  log.info(f"wrote {TESLA_VIN_PATH} and {TESLA_KEY_PATH}")


def cmd_status():
  try:
    with open(TESLA_VIN_PATH) as f:
      vin = f.read().strip()
    ble_name = "S" + hashlib.sha1(vin.encode()).hexdigest()[:16] + "C"
  except FileNotFoundError:
    vin = ble_name = "(not set)"
  try:
    _, pub = load_or_create_key(TESLA_KEY_PATH)
    kid = key_id(pub).hex()
  except Exception:
    kid = "(not set)"
  log.info(f"VIN:      {vin}")
  log.info(f"BLE name: {ble_name}")
  log.info(f"key id:   {kid}")


LOCK_NAMES = {0: "unlocked", 1: "locked", 2: "internal_locked", 3: "selective_unlocked"}
SLEEP_NAMES = {0: "unknown", 1: "awake", 2: "asleep"}
PRESENCE_NAMES = {0: "unknown", 1: "not_present", 2: "present"}
CLOSURE_NAMES = {0: "closed", 1: "open", 2: "ajar", 3: "unknown",
                 4: "failed_unlatch", 5: "opening", 6: "closing"}


def format_state(s):
  c = s.car
  lines = [f"connected={s.connected} whitelisted={s.whitelisted} "
           f"infotainment={s.infotainmentReady} event={s.lastEvent!r}"]
  if c.vcsecUpdatedAt > 0:
    lines.append(f"  lock={LOCK_NAMES.get(c.lockState, c.lockState)} "
                 f"sleep={SLEEP_NAMES.get(c.sleepStatus, c.sleepStatus)} "
                 f"presence={PRESENCE_NAMES.get(c.userPresence, c.userPresence)}")
    lines.append("  " + " ".join(f"{k}={CLOSURE_NAMES.get(getattr(c, f), getattr(c, f))}"
                                 for k, f in [("FD", "frontDriverDoor"), ("FP", "frontPassengerDoor"),
                                              ("RD", "rearDriverDoor"), ("RP", "rearPassengerDoor"),
                                              ("trunk", "rearTrunk"), ("frunk", "frontTrunk"),
                                              ("charge_port", "chargePort"), ("tonneau", "tonneau")]))
  if c.infotainmentUpdatedAt > 0:
    if c.chargePercent or c.chargingState:
      lines.append(f"  charge: {c.chargePercent}% range={c.batteryRangeMiles:.0f}mi "
                   f"state={c.chargingState} limit={c.chargeLimitSoc}%")
    if c.insideTempC or c.outsideTempC:
      lines.append(f"  climate: inside={c.insideTempC}C outside={c.outsideTempC}C "
                   f"hvac={'on' if c.hvacOn else 'off'}")
    if c.speedMph or c.gear:
      lines.append(f"  drive: speed={c.speedMph:.1f}mph gear={c.gear} heading={c.heading:.0f}°")
    if c.latitude or c.longitude:
      lines.append(f"  location: {c.latitude:.5f},{c.longitude:.5f} odo={c.odometerMiles:.0f}mi")
    if c.mediaTrack:
      lines.append(f"  media: playing={c.mediaPlaying} {c.mediaTrack!r} by {c.mediaArtist!r}")
  return "\n".join(lines)


def cmd_state():
  sm = messaging.SubMaster(['teslaState'])
  log.info("subscribed to teslaState (ctrl-C to exit)")
  try:
    while True:
      sm.update(1000)
      if sm.updated.get('teslaState'):
        log.info(format_state(sm['teslaState']))
  except KeyboardInterrupt:
    pass


def cmd_send(command, args):
  arg = " ".join(args) if args else ""
  pm = messaging.PubMaster(['teslaCommand'])
  sm = messaging.SubMaster(['teslaState'])
  time.sleep(0.3)  # let sockets bind

  msg = messaging.new_message('teslaCommand')
  msg.teslaCommand.command = command
  msg.teslaCommand.arg = arg
  pm.send('teslaCommand', msg)
  log.info(f"sent: {command}" + (f" {arg!r}" if arg else ""))

  timeout = LONG_COMMANDS.get(command, DEFAULT_TIMEOUT)
  deadline = time.time() + timeout
  while time.time() < deadline:
    sm.update(500)
    if sm.updated.get('teslaState'):
      s = sm['teslaState']
      if s.lastEvent == "whitelist=awaiting_tap":
        log.info(">>> TAP NFC KEY CARD ON CENTER CONSOLE <<<")
        continue
      log.info(format_state(s))
      if s.lastEvent.startswith(f"{command}=") and s.lastEvent != f"{command}=awaiting_tap":
        return
  log.warning(f"no response within {timeout}s — is teslad running and connected?")


def usage():
  print(__doc__.strip())


def main():
  if len(sys.argv) < 2:
    usage()
    sys.exit(1)

  sub, rest = sys.argv[1], sys.argv[2:]

  if sub in ("-h", "--help", "help"):
    usage()
    return

  if sub == "setup":
    if not rest:
      log.error("setup requires a VIN")
      sys.exit(1)
    cmd_setup(rest[0])
  elif sub == "status":
    cmd_status()
  elif sub == "state":
    cmd_state()
  elif sub in SESSION_COMMANDS:
    cmd_send(sub, rest)
  else:
    log.error(f"unknown command: {sub}")
    usage()
    sys.exit(1)


if __name__ == "__main__":
  main()
