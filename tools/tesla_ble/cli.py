#!/usr/bin/env python3
"""Tesla BLE CLI — control a Tesla vehicle over Bluetooth Low Energy.

Usage:
  python -m openpilot.tools.tesla_ble.cli <command> [options]

Examples:
  # Generate a key pair for your VIN
  python -m openpilot.tools.tesla_ble.cli keygen --vin 5YJ3E1EA1NF000001

  # Pair key with vehicle (tap NFC card on center console when prompted)
  python -m openpilot.tools.tesla_ble.cli pair --vin 5YJ3E1EA1NF000001

  # Lock the vehicle
  python -m openpilot.tools.tesla_ble.cli lock --vin 5YJ3E1EA1NF000001

  # Set climate to 21°C
  python -m openpilot.tools.tesla_ble.cli set-temp --vin 5YJ3E1EA1NF000001 --driver-temp 21
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys

from openpilot.tools.tesla_ble.key_store import (
  generate_key_pair,
  get_public_key_bytes,
  has_key,
  load_key,
  save_key,
)
from openpilot.tools.tesla_ble.messages import (
  ClimateKeeperAction,
  ClosureState,
  KeyFormFactor,
  KeyRole,
  SeatHeaterLevel,
  SeatPosition,
  VehicleLockState,
  VehicleSleepStatus,
  UserPresence,
)
from openpilot.tools.tesla_ble.transport import scan_for_teslas
from openpilot.tools.tesla_ble.vehicle import TeslaVehicle

logger = logging.getLogger(__name__)


def _get_vin(args: argparse.Namespace) -> str:
  vin = args.vin or os.environ.get('TESLA_VIN', '')
  if not vin:
    print("Error: VIN required. Use --vin or set TESLA_VIN env var.", file=sys.stderr)
    sys.exit(1)
  return vin


async def _get_vehicle(args: argparse.Namespace) -> TeslaVehicle:
  vin = _get_vin(args)
  key = load_key(vin, args.key_path)
  vehicle = TeslaVehicle(vin, key)
  await vehicle.connect()
  return vehicle


def _print_status(status: dict) -> None:
  """Pretty-print vehicle status."""
  vs = status.get('vehicle_status', {})
  cs = vs.get('closure_statuses', {})

  lock_state = vs.get('vehicle_lock_state', 0)
  sleep_status = vs.get('vehicle_sleep_status', 0)
  user_presence = vs.get('user_presence', 0)

  print(f"Lock state:    {VehicleLockState(lock_state).name}")
  print(f"Sleep status:  {VehicleSleepStatus(sleep_status).name}")
  print(f"User presence: {UserPresence(user_presence).name}")

  if cs:
    print("\nClosure statuses:")
    for name, field in [
      ("Front driver door", 'front_driver_door'),
      ("Front passenger door", 'front_passenger_door'),
      ("Rear driver door", 'rear_driver_door'),
      ("Rear passenger door", 'rear_passenger_door'),
      ("Rear trunk", 'rear_trunk'),
      ("Front trunk", 'front_trunk'),
      ("Charge port", 'charge_port'),
      ("Tonneau", 'tonneau'),
    ]:
      val = cs.get(field, 0)
      try:
        state_name = ClosureState(val).name
      except ValueError:
        state_name = str(val)
      print(f"  {name:24s} {state_name}")


def _print_result(result: dict, label: str = "Command") -> None:
  cmd_status = result.get('command_status', {})
  op = cmd_status.get('operation_status', 0)
  if op == 0:
    print(f"{label}: OK")
  elif op == 1:
    print(f"{label}: WAIT (vehicle processing)")
  else:
    print(f"{label}: ERROR (status={op})")
    if cmd_status:
      print(f"  Details: {json.dumps(cmd_status, indent=2, default=str)}")


# ===================================================================
# Command handlers
# ===================================================================

async def cmd_scan(args: argparse.Namespace) -> None:
  """Scan for nearby Tesla vehicles."""
  print(f"Scanning for Tesla vehicles ({args.timeout}s)...")
  devices = await scan_for_teslas(timeout=args.timeout)
  if not devices:
    print("No Tesla vehicles found.")
    return
  for d in devices:
    print(f"  {d.name or 'Unknown':20s}  {d.address}  RSSI={d.rssi}")


async def cmd_keygen(args: argparse.Namespace) -> None:
  """Generate a new key pair."""
  vin = _get_vin(args)
  if has_key(vin, args.key_path) and not args.force:
    print(f"Key already exists for VIN {vin}. Use --force to overwrite.", file=sys.stderr)
    sys.exit(1)

  key = generate_key_pair()
  path = save_key(key, vin, args.key_path)
  pub_hex = get_public_key_bytes(key).hex()
  print(f"Key pair generated and saved to {path}")
  print(f"Public key: {pub_hex}")


async def cmd_pair(args: argparse.Namespace) -> None:
  """Pair a key with the vehicle (requires NFC card tap on center console)."""
  vin = _get_vin(args)
  if not has_key(vin, args.key_path):
    print(f"No key found for VIN {vin}. Run 'keygen' first.", file=sys.stderr)
    sys.exit(1)

  key = load_key(vin, args.key_path)
  pub_bytes = get_public_key_bytes(key)

  vehicle = TeslaVehicle(vin, key)
  # For pairing, we only need the BLE connection — no session needed
  print(f"Scanning for VIN {vin}...")
  devices = await scan_for_teslas(vin=vin, timeout=15.0)
  if not devices:
    print("Vehicle not found.", file=sys.stderr)
    sys.exit(1)

  await vehicle.transport.connect(devices[0])
  await vehicle.vcsec_session.perform_handshake(vehicle.transport)

  role_map = {'owner': KeyRole.OWNER, 'driver': KeyRole.DRIVER}
  form_map = {
    'nfc': KeyFormFactor.NFC_CARD,
    'ios': KeyFormFactor.IOS_DEVICE,
    'android': KeyFormFactor.ANDROID_DEVICE,
    'cloud': KeyFormFactor.CLOUD_KEY,
  }
  role = role_map.get(args.role, KeyRole.OWNER)
  form = form_map.get(args.form_factor, KeyFormFactor.CLOUD_KEY)

  print("\n*** Tap your NFC key card on the center console now ***\n")
  result = await vehicle.add_key(pub_bytes, role, form)
  _print_result(result, "Pair")
  await vehicle.disconnect()


async def cmd_list_keys(args: argparse.Namespace) -> None:
  """List paired keys on the vehicle."""
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.get_whitelist_info()
    wi = result.get('whitelist_info', {})
    n = wi.get('number_of_entries', 0)
    print(f"Keys on whitelist: {n}")
    for i, entry_hash in enumerate(wi.get('entries', [])):
      print(f"  [{i}] {entry_hash}")
  finally:
    await vehicle.disconnect()


# --- VCSEC commands ---

async def cmd_lock(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.lock()
    _print_result(result, "Lock")
  finally:
    await vehicle.disconnect()


async def cmd_unlock(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.unlock()
    _print_result(result, "Unlock")
  finally:
    await vehicle.disconnect()


async def cmd_wake(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.wake()
    _print_result(result, "Wake")
  finally:
    await vehicle.disconnect()


async def cmd_remote_start(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.remote_start()
    _print_result(result, "Remote start")
  finally:
    await vehicle.disconnect()


async def cmd_open_trunk(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.open_trunk()
    _print_result(result, "Open trunk")
  finally:
    await vehicle.disconnect()


async def cmd_close_trunk(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.close_trunk()
    _print_result(result, "Close trunk")
  finally:
    await vehicle.disconnect()


async def cmd_open_frunk(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.open_frunk()
    _print_result(result, "Open frunk")
  finally:
    await vehicle.disconnect()


async def cmd_open_charge_port(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.open_charge_port()
    _print_result(result, "Open charge port")
  finally:
    await vehicle.disconnect()


async def cmd_close_charge_port(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.close_charge_port()
    _print_result(result, "Close charge port")
  finally:
    await vehicle.disconnect()


async def cmd_status(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.get_vehicle_status()
    _print_status(result)
  finally:
    await vehicle.disconnect()


# --- Climate commands ---

async def cmd_climate_on(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.climate_on()
    _print_result(result, "Climate on")
  finally:
    await vehicle.disconnect()


async def cmd_climate_off(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.climate_off()
    _print_result(result, "Climate off")
  finally:
    await vehicle.disconnect()


async def cmd_set_temp(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    passenger = args.passenger_temp if args.passenger_temp is not None else args.driver_temp
    result = await vehicle.set_temperature(args.driver_temp, passenger)
    _print_result(result, "Set temperature")
  finally:
    await vehicle.disconnect()


async def cmd_seat_heater(args: argparse.Namespace) -> None:
  seat_map = {
    'front-left': SeatPosition.FRONT_LEFT,
    'front-right': SeatPosition.FRONT_RIGHT,
    'rear-left': SeatPosition.REAR_LEFT,
    'rear-center': SeatPosition.REAR_CENTER,
    'rear-right': SeatPosition.REAR_RIGHT,
  }
  level_map = {'off': SeatHeaterLevel.OFF, 'low': SeatHeaterLevel.LOW,
                'med': SeatHeaterLevel.MED, 'high': SeatHeaterLevel.HIGH}

  vehicle = await _get_vehicle(args)
  try:
    seat = seat_map[args.seat]
    level = level_map[args.level]
    result = await vehicle.set_seat_heater(seat, level)
    _print_result(result, "Seat heater")
  finally:
    await vehicle.disconnect()


async def cmd_steering_heater(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.steering_wheel_heater(args.on)
    _print_result(result, "Steering wheel heater")
  finally:
    await vehicle.disconnect()


async def cmd_climate_keeper(args: argparse.Namespace) -> None:
  mode_map = {
    'off': ClimateKeeperAction.OFF,
    'on': ClimateKeeperAction.ON,
    'dog': ClimateKeeperAction.DOG,
    'camp': ClimateKeeperAction.CAMP,
  }
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.set_climate_keeper(mode_map[args.mode])
    _print_result(result, "Climate keeper")
  finally:
    await vehicle.disconnect()


async def cmd_bioweapon_mode(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.set_bioweapon_mode(args.on)
    _print_result(result, "Bioweapon defense mode")
  finally:
    await vehicle.disconnect()


async def cmd_precondition_max(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.set_preconditioning_max(args.on)
    _print_result(result, "Max preconditioning")
  finally:
    await vehicle.disconnect()


async def cmd_cabin_overheat(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.set_cabin_overheat_protection(args.on, args.fan_only)
    _print_result(result, "Cabin overheat protection")
  finally:
    await vehicle.disconnect()


# --- Charging commands ---

async def cmd_start_charge(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.start_charging()
    _print_result(result, "Start charging")
  finally:
    await vehicle.disconnect()


async def cmd_stop_charge(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.stop_charging()
    _print_result(result, "Stop charging")
  finally:
    await vehicle.disconnect()


async def cmd_charge_limit(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.set_charge_limit(args.percent)
    _print_result(result, "Charge limit")
  finally:
    await vehicle.disconnect()


async def cmd_charge_amps(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.set_charging_amps(args.amps)
    _print_result(result, "Charging amps")
  finally:
    await vehicle.disconnect()


# --- Vehicle control commands ---

async def cmd_honk(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.honk_horn()
    _print_result(result, "Honk horn")
  finally:
    await vehicle.disconnect()


async def cmd_flash(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.flash_lights()
    _print_result(result, "Flash lights")
  finally:
    await vehicle.disconnect()


async def cmd_vent_windows(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.vent_windows()
    _print_result(result, "Vent windows")
  finally:
    await vehicle.disconnect()


async def cmd_close_windows(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.close_windows()
    _print_result(result, "Close windows")
  finally:
    await vehicle.disconnect()


async def cmd_sentry_mode(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.set_sentry_mode(args.on)
    _print_result(result, "Sentry mode")
  finally:
    await vehicle.disconnect()


async def cmd_valet_mode(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.set_valet_mode(args.on, args.password or '')
    _print_result(result, "Valet mode")
  finally:
    await vehicle.disconnect()


async def cmd_speed_limit(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    if args.set is not None:
      result = await vehicle.set_speed_limit(args.set)
      _print_result(result, "Set speed limit")
    elif args.activate:
      if not args.pin:
        print("Error: --pin required to activate speed limit", file=sys.stderr)
        sys.exit(1)
      result = await vehicle.activate_speed_limit(args.pin)
      _print_result(result, "Activate speed limit")
    elif args.deactivate:
      if not args.pin:
        print("Error: --pin required to deactivate speed limit", file=sys.stderr)
        sys.exit(1)
      result = await vehicle.deactivate_speed_limit(args.pin)
      _print_result(result, "Deactivate speed limit")
    else:
      print("Error: specify --set, --activate, or --deactivate", file=sys.stderr)
      sys.exit(1)
  finally:
    await vehicle.disconnect()


async def cmd_pin_to_drive(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.set_pin_to_drive(args.on, args.pin or '')
    _print_result(result, "PIN to drive")
  finally:
    await vehicle.disconnect()


async def cmd_set_name(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.set_vehicle_name(args.name)
    _print_result(result, "Set vehicle name")
  finally:
    await vehicle.disconnect()


async def cmd_homelink(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.trigger_homelink()
    _print_result(result, "Homelink")
  finally:
    await vehicle.disconnect()


async def cmd_schedule_update(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.schedule_software_update(args.delay)
    _print_result(result, "Schedule software update")
  finally:
    await vehicle.disconnect()


async def cmd_cancel_update(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    result = await vehicle.cancel_software_update()
    _print_result(result, "Cancel software update")
  finally:
    await vehicle.disconnect()


# --- Media commands ---

async def cmd_media(args: argparse.Namespace) -> None:
  vehicle = await _get_vehicle(args)
  try:
    if args.play:
      result = await vehicle.media_toggle_playback()
      _print_result(result, "Media toggle")
    elif args.next:
      result = await vehicle.media_next_track()
      _print_result(result, "Next track")
    elif args.prev:
      result = await vehicle.media_previous_track()
      _print_result(result, "Previous track")
    elif args.vol_up:
      result = await vehicle.media_volume_up()
      _print_result(result, "Volume up")
    elif args.vol_down:
      result = await vehicle.media_volume_down()
      _print_result(result, "Volume down")
    else:
      print("Error: specify a media action (--play, --next, --prev, --vol-up, --vol-down)", file=sys.stderr)
      sys.exit(1)
  finally:
    await vehicle.disconnect()


# ===================================================================
# CLI argument parser
# ===================================================================

def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog='tesla-ble',
    description='Control a Tesla vehicle over Bluetooth Low Energy',
  )
  parser.add_argument('--vin', help='Vehicle VIN (or set TESLA_VIN env var)')
  parser.add_argument('--key-path', help='Key storage directory')
  parser.add_argument('--debug', action='store_true', help='Enable debug logging')

  sub = parser.add_subparsers(dest='command', required=True)

  # Scan
  p = sub.add_parser('scan', help='Scan for nearby Tesla vehicles')
  p.add_argument('--timeout', type=float, default=10.0, help='Scan timeout in seconds')
  p.set_defaults(func=cmd_scan)

  # Key management
  p = sub.add_parser('keygen', help='Generate a new key pair')
  p.add_argument('--force', action='store_true', help='Overwrite existing key')
  p.set_defaults(func=cmd_keygen)

  p = sub.add_parser('pair', help='Pair key with vehicle (tap NFC card when prompted)')
  p.add_argument('--role', choices=['owner', 'driver'], default='owner', help='Key role')
  p.add_argument('--form-factor', choices=['nfc', 'ios', 'android', 'cloud'], default='cloud', help='Key form factor')
  p.set_defaults(func=cmd_pair)

  p = sub.add_parser('list-keys', help='List paired keys on vehicle')
  p.set_defaults(func=cmd_list_keys)

  # VCSEC commands
  sub.add_parser('lock', help='Lock the vehicle').set_defaults(func=cmd_lock)
  sub.add_parser('unlock', help='Unlock the vehicle').set_defaults(func=cmd_unlock)
  sub.add_parser('wake', help='Wake the vehicle').set_defaults(func=cmd_wake)
  sub.add_parser('remote-start', help='Enable keyless driving').set_defaults(func=cmd_remote_start)
  sub.add_parser('open-trunk', help='Open the rear trunk').set_defaults(func=cmd_open_trunk)
  sub.add_parser('close-trunk', help='Close the rear trunk').set_defaults(func=cmd_close_trunk)
  sub.add_parser('open-frunk', help='Open the front trunk (frunk)').set_defaults(func=cmd_open_frunk)
  sub.add_parser('open-charge-port', help='Open the charge port').set_defaults(func=cmd_open_charge_port)
  sub.add_parser('close-charge-port', help='Close the charge port').set_defaults(func=cmd_close_charge_port)
  sub.add_parser('status', help='Get vehicle closure/lock status').set_defaults(func=cmd_status)

  # Climate commands
  sub.add_parser('climate-on', help='Turn on climate control').set_defaults(func=cmd_climate_on)
  sub.add_parser('climate-off', help='Turn off climate control').set_defaults(func=cmd_climate_off)

  p = sub.add_parser('set-temp', help='Set cabin temperature (Celsius)')
  p.add_argument('--driver-temp', type=float, required=True, help='Driver side temperature')
  p.add_argument('--passenger-temp', type=float, help='Passenger side temperature (defaults to driver)')
  p.set_defaults(func=cmd_set_temp)

  p = sub.add_parser('seat-heater', help='Set seat heater level')
  p.add_argument('--seat', required=True,
                 choices=['front-left', 'front-right', 'rear-left', 'rear-center', 'rear-right'])
  p.add_argument('--level', required=True, choices=['off', 'low', 'med', 'high'])
  p.set_defaults(func=cmd_seat_heater)

  p = sub.add_parser('steering-heater', help='Toggle steering wheel heater')
  grp = p.add_mutually_exclusive_group(required=True)
  grp.add_argument('--on', action='store_true')
  grp.add_argument('--off', dest='on', action='store_false')
  p.set_defaults(func=cmd_steering_heater)

  p = sub.add_parser('climate-keeper', help='Set climate keeper mode')
  p.add_argument('--mode', required=True, choices=['off', 'on', 'dog', 'camp'])
  p.set_defaults(func=cmd_climate_keeper)

  p = sub.add_parser('bioweapon-mode', help='Toggle bioweapon defense mode')
  grp = p.add_mutually_exclusive_group(required=True)
  grp.add_argument('--on', action='store_true')
  grp.add_argument('--off', dest='on', action='store_false')
  p.set_defaults(func=cmd_bioweapon_mode)

  p = sub.add_parser('precondition-max', help='Toggle max preconditioning')
  grp = p.add_mutually_exclusive_group(required=True)
  grp.add_argument('--on', action='store_true')
  grp.add_argument('--off', dest='on', action='store_false')
  p.set_defaults(func=cmd_precondition_max)

  p = sub.add_parser('cabin-overheat', help='Set cabin overheat protection')
  grp = p.add_mutually_exclusive_group(required=True)
  grp.add_argument('--on', action='store_true')
  grp.add_argument('--off', dest='on', action='store_false')
  p.add_argument('--fan-only', action='store_true', help='Fan-only mode (no A/C)')
  p.set_defaults(func=cmd_cabin_overheat)

  # Charging commands
  sub.add_parser('start-charge', help='Start charging').set_defaults(func=cmd_start_charge)
  sub.add_parser('stop-charge', help='Stop charging').set_defaults(func=cmd_stop_charge)

  p = sub.add_parser('charge-limit', help='Set charge limit percentage')
  p.add_argument('--percent', type=int, required=True, help='Charge limit (50-100)')
  p.set_defaults(func=cmd_charge_limit)

  p = sub.add_parser('charge-amps', help='Set charging amperage')
  p.add_argument('--amps', type=int, required=True, help='Charging amps')
  p.set_defaults(func=cmd_charge_amps)

  # Vehicle control commands
  sub.add_parser('honk', help='Honk the horn').set_defaults(func=cmd_honk)
  sub.add_parser('flash', help='Flash the lights').set_defaults(func=cmd_flash)
  sub.add_parser('vent-windows', help='Vent all windows').set_defaults(func=cmd_vent_windows)
  sub.add_parser('close-windows', help='Close all windows').set_defaults(func=cmd_close_windows)

  p = sub.add_parser('sentry-mode', help='Enable/disable sentry mode')
  grp = p.add_mutually_exclusive_group(required=True)
  grp.add_argument('--on', action='store_true')
  grp.add_argument('--off', dest='on', action='store_false')
  p.set_defaults(func=cmd_sentry_mode)

  p = sub.add_parser('valet-mode', help='Enable/disable valet mode')
  grp = p.add_mutually_exclusive_group(required=True)
  grp.add_argument('--on', action='store_true')
  grp.add_argument('--off', dest='on', action='store_false')
  p.add_argument('--password', help='Valet mode password')
  p.set_defaults(func=cmd_valet_mode)

  p = sub.add_parser('speed-limit', help='Set/activate/deactivate speed limit')
  grp = p.add_mutually_exclusive_group(required=True)
  grp.add_argument('--set', type=float, help='Speed limit in mph')
  grp.add_argument('--activate', action='store_true')
  grp.add_argument('--deactivate', action='store_true')
  p.add_argument('--pin', help='Speed limit PIN (required for activate/deactivate)')
  p.set_defaults(func=cmd_speed_limit)

  p = sub.add_parser('pin-to-drive', help='Enable/disable PIN to drive')
  grp = p.add_mutually_exclusive_group(required=True)
  grp.add_argument('--on', action='store_true')
  grp.add_argument('--off', dest='on', action='store_false')
  p.add_argument('--pin', help='PIN')
  p.set_defaults(func=cmd_pin_to_drive)

  p = sub.add_parser('set-name', help='Set vehicle name')
  p.add_argument('--name', required=True, help='New vehicle name')
  p.set_defaults(func=cmd_set_name)

  sub.add_parser('homelink', help='Trigger Homelink (garage door)').set_defaults(func=cmd_homelink)

  p = sub.add_parser('schedule-update', help='Schedule a software update')
  p.add_argument('--delay', type=int, default=0, help='Delay in seconds before starting update')
  p.set_defaults(func=cmd_schedule_update)

  sub.add_parser('cancel-update', help='Cancel a pending software update').set_defaults(func=cmd_cancel_update)

  # Media commands
  p = sub.add_parser('media', help='Media controls')
  grp = p.add_mutually_exclusive_group(required=True)
  grp.add_argument('--play', action='store_true', help='Toggle playback')
  grp.add_argument('--next', action='store_true', help='Next track')
  grp.add_argument('--prev', action='store_true', help='Previous track')
  grp.add_argument('--vol-up', action='store_true', help='Volume up')
  grp.add_argument('--vol-down', action='store_true', help='Volume down')
  p.set_defaults(func=cmd_media)

  return parser


def main() -> None:
  parser = build_parser()
  args = parser.parse_args()

  level = logging.DEBUG if args.debug else logging.INFO
  logging.basicConfig(level=level, format='%(levelname)s: %(message)s')

  try:
    asyncio.run(args.func(args))
  except FileNotFoundError as e:
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)
  except ConnectionError as e:
    print(f"Connection error: {e}", file=sys.stderr)
    sys.exit(1)
  except RuntimeError as e:
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)
  except KeyboardInterrupt:
    print("\nInterrupted.")
    sys.exit(130)


if __name__ == '__main__':
  main()
