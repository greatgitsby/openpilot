#!/usr/bin/env python3
"""Tesla CLI — setup the connection and send commands to teslad over cereal.

Usage:
  tesla.py setup <VIN>            write VIN + generate key
  tesla.py whitelist              whitelist key with Tesla (tap NFC card)
  tesla.py status                 show current VIN and key id

  tesla.py <command> [args...]    send command to teslad via cereal

Commands (session must be established by a running teslad):
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
  seat_heat <seat>,<level>
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


def cmd_whitelist():
  import asyncio
  from openpilot.system.teslable.whitelist import main as wl_main
  asyncio.run(wl_main())


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


def cmd_send(command, args):
  arg = " ".join(args) if args else ""
  pm = messaging.PubMaster(['teslaCommand'])
  msg = messaging.new_message('teslaCommand')
  msg.teslaCommand.command = command
  msg.teslaCommand.arg = arg
  time.sleep(0.2)  # let subscriber bind
  pm.send('teslaCommand', msg)
  log.info(f"sent: {command}" + (f" {arg!r}" if arg else ""))


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
  elif sub == "whitelist":
    cmd_whitelist()
  elif sub == "status":
    cmd_status()
  elif sub in SESSION_COMMANDS:
    cmd_send(sub, rest)
  else:
    log.error(f"unknown command: {sub}")
    usage()
    sys.exit(1)


if __name__ == "__main__":
  main()
