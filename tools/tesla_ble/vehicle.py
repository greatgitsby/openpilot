"""High-level async API for controlling a Tesla vehicle over BLE.

Ties together key management, BLE transport, session handshakes, and command
encoding to provide a clean interface for each vehicle capability.
"""

from __future__ import annotations

import logging

from Crypto.PublicKey import ECC

from openpilot.tools.tesla_ble.messages import (
  ClimateKeeperAction,
  ClosureMoveType,
  Domain,
  InformationRequestType,
  KeyFormFactor,
  KeyRole,
  OperationStatus,
  RKEAction,
  SeatHeaterLevel,
  SeatPosition,
  build_cabin_overheat_protection_action,
  build_cancel_software_update_action,
  build_charge_port_door_close,
  build_charge_port_door_open,
  build_charging_set_limit_action,
  build_charging_start_stop_action,
  build_closure_move_request,
  build_flash_lights_action,
  build_honk_horn_action,
  build_hvac_auto_action,
  build_hvac_bioweapon_mode_action,
  build_hvac_climate_keeper_action,
  build_hvac_preconditioning_max_action,
  build_hvac_seat_heater_actions,
  build_hvac_steering_wheel_heater_action,
  build_hvac_temperature_action,
  build_information_request,
  build_media_next_track,
  build_media_play_action,
  build_media_previous_track,
  build_media_update_volume,
  build_pin_to_drive_action,
  build_schedule_software_update_action,
  build_set_charging_amps_action,
  build_set_sentry_mode_action,
  build_set_speed_limit_action,
  build_set_valet_mode_action,
  build_set_vehicle_name_action,
  build_speed_limit_activate_action,
  build_trigger_homelink_action,
  build_unsigned_message,
  build_whitelist_operation_add,
  build_whitelist_operation,
  build_window_action,
  parse_from_vcsec_message,
  parse_routable_message,
)
from openpilot.tools.tesla_ble.session import TeslaSession
from openpilot.tools.tesla_ble.transport import TeslaBLETransport, scan_for_teslas

logger = logging.getLogger(__name__)


class TeslaVehicle:
  """Async interface to a Tesla vehicle over BLE."""

  def __init__(self, vin: str, private_key: ECC.EccKey) -> None:
    self.vin = vin
    self.private_key = private_key
    self.transport = TeslaBLETransport()
    self.vcsec_session = TeslaSession(private_key, Domain.VEHICLE_SECURITY)
    self.infotainment_session = TeslaSession(private_key, Domain.INFOTAINMENT)

  # ------------------------------------------------------------------
  # Connection lifecycle
  # ------------------------------------------------------------------

  async def connect(self, timeout: float = 15.0) -> None:
    """Scan for the vehicle, connect, and establish crypto sessions."""
    logger.info("Scanning for VIN %s ...", self.vin)
    devices = await scan_for_teslas(vin=self.vin, timeout=timeout)
    if not devices:
      raise RuntimeError(f"Could not find Tesla with VIN {self.vin} via BLE")

    device = devices[0]
    logger.info("Found %s (%s), connecting...", device.name, device.address)
    await self.transport.connect(device, timeout=timeout)

    # Handshake with VCSEC (always available)
    await self.vcsec_session.perform_handshake(self.transport)

    # Handshake with Infotainment (may fail if vehicle is asleep)
    try:
      await self.infotainment_session.perform_handshake(self.transport)
    except Exception as e:
      logger.warning("Infotainment handshake failed (vehicle may be asleep): %s", e)

  async def disconnect(self) -> None:
    await self.transport.disconnect()

  async def _ensure_infotainment(self) -> None:
    """Ensure infotainment session is up; retry handshake if needed."""
    if not self.infotainment_session.is_established:
      await self.infotainment_session.perform_handshake(self.transport)

  # ------------------------------------------------------------------
  # Low-level send/receive
  # ------------------------------------------------------------------

  async def _send_vcsec(self, unsigned_message: bytes) -> dict:
    """Encrypt and send a VCSEC command, return the parsed response."""
    msg = self.vcsec_session.encrypt_command(unsigned_message)
    await self.transport.send(msg)

    # VCSEC may send up to 3 responses; we want the final one
    last_response: dict = {}
    for _ in range(3):
      try:
        resp_data = await self.transport.receive(timeout=5.0)
      except TimeoutError:
        break
      resp = parse_routable_message(resp_data)
      payload, _ = self.vcsec_session.decrypt_response(resp_data)
      if payload:
        last_response = parse_from_vcsec_message(payload)
      # Check if this is a final (non-WAIT) response
      op_status = resp.get('operation_status', 0)
      if op_status != OperationStatus.WAIT:
        break

    return last_response

  async def _send_infotainment(self, action_payload: bytes) -> dict:
    """Encrypt and send an infotainment action, return the parsed response."""
    await self._ensure_infotainment()
    msg = self.infotainment_session.encrypt_command(action_payload)
    await self.transport.send(msg)

    try:
      resp_data = await self.transport.receive(timeout=10.0)
      _, resp = self.infotainment_session.decrypt_response(resp_data)
      return resp
    except TimeoutError:
      logger.warning("No response from infotainment (command may have succeeded)")
      return {}

  # ------------------------------------------------------------------
  # VCSEC commands
  # ------------------------------------------------------------------

  async def lock(self) -> dict:
    """Lock the vehicle."""
    return await self._send_vcsec(build_unsigned_message(rke_action=RKEAction.LOCK))

  async def unlock(self) -> dict:
    """Unlock the vehicle."""
    return await self._send_vcsec(build_unsigned_message(rke_action=RKEAction.UNLOCK))

  async def wake(self) -> dict:
    """Wake the vehicle."""
    return await self._send_vcsec(build_unsigned_message(rke_action=RKEAction.WAKE_VEHICLE))

  async def remote_start(self) -> dict:
    """Enable keyless driving."""
    return await self._send_vcsec(build_unsigned_message(rke_action=RKEAction.REMOTE_DRIVE))

  async def open_trunk(self) -> dict:
    """Open the rear trunk."""
    cmr = build_closure_move_request(rear_trunk=ClosureMoveType.OPEN)
    return await self._send_vcsec(build_unsigned_message(closure_move_request=cmr))

  async def close_trunk(self) -> dict:
    """Close the rear trunk."""
    cmr = build_closure_move_request(rear_trunk=ClosureMoveType.CLOSE)
    return await self._send_vcsec(build_unsigned_message(closure_move_request=cmr))

  async def open_frunk(self) -> dict:
    """Open the front trunk (frunk)."""
    cmr = build_closure_move_request(front_trunk=ClosureMoveType.OPEN)
    return await self._send_vcsec(build_unsigned_message(closure_move_request=cmr))

  async def open_charge_port(self) -> dict:
    """Open the charge port."""
    cmr = build_closure_move_request(charge_port=ClosureMoveType.OPEN)
    return await self._send_vcsec(build_unsigned_message(closure_move_request=cmr))

  async def close_charge_port(self) -> dict:
    """Close the charge port."""
    cmr = build_closure_move_request(charge_port=ClosureMoveType.CLOSE)
    return await self._send_vcsec(build_unsigned_message(closure_move_request=cmr))

  async def get_vehicle_status(self) -> dict:
    """Query vehicle closure/lock status."""
    ir = build_information_request(InformationRequestType.GET_STATUS)
    return await self._send_vcsec(build_unsigned_message(information_request=ir))

  async def get_whitelist_info(self) -> dict:
    """Query the key whitelist."""
    ir = build_information_request(InformationRequestType.GET_WHITELIST_INFO)
    return await self._send_vcsec(build_unsigned_message(information_request=ir))

  async def add_key(
    self,
    public_key: bytes,
    role: KeyRole = KeyRole.DRIVER,
    form_factor: KeyFormFactor = KeyFormFactor.CLOUD_KEY,
  ) -> dict:
    """Add a public key to the vehicle whitelist."""
    wl = build_whitelist_operation_add(public_key, role, form_factor)
    return await self._send_vcsec(build_unsigned_message(whitelist_operation=wl))

  async def remove_key(self, public_key: bytes) -> dict:
    """Remove a public key from the vehicle whitelist."""
    wl = build_whitelist_operation(remove_public_key=public_key)
    return await self._send_vcsec(build_unsigned_message(whitelist_operation=wl))

  # ------------------------------------------------------------------
  # Infotainment commands — Climate
  # ------------------------------------------------------------------

  async def climate_on(self) -> dict:
    """Turn on climate control (HVAC auto)."""
    return await self._send_infotainment(build_hvac_auto_action(power_on=True))

  async def climate_off(self) -> dict:
    """Turn off climate control."""
    return await self._send_infotainment(build_hvac_auto_action(power_on=False))

  async def set_temperature(self, driver_temp: float, passenger_temp: float | None = None) -> dict:
    """Set cabin temperature in Celsius."""
    return await self._send_infotainment(
      build_hvac_temperature_action(driver_temp, passenger_temp))

  async def set_seat_heater(self, seat: SeatPosition, level: SeatHeaterLevel) -> dict:
    """Set a seat heater level."""
    return await self._send_infotainment(
      build_hvac_seat_heater_actions([(seat, level)]))

  async def steering_wheel_heater(self, on: bool) -> dict:
    """Toggle the steering wheel heater."""
    return await self._send_infotainment(build_hvac_steering_wheel_heater_action(on))

  async def set_climate_keeper(self, mode: ClimateKeeperAction) -> dict:
    """Set climate keeper mode (off/on/dog/camp)."""
    return await self._send_infotainment(build_hvac_climate_keeper_action(mode))

  async def set_bioweapon_mode(self, on: bool) -> dict:
    """Toggle bioweapon defense mode."""
    return await self._send_infotainment(build_hvac_bioweapon_mode_action(on))

  async def set_preconditioning_max(self, on: bool) -> dict:
    """Toggle max preconditioning."""
    return await self._send_infotainment(build_hvac_preconditioning_max_action(on))

  async def set_cabin_overheat_protection(self, on: bool, fan_only: bool = False) -> dict:
    """Set cabin overheat protection."""
    return await self._send_infotainment(build_cabin_overheat_protection_action(on, fan_only))

  # ------------------------------------------------------------------
  # Infotainment commands — Charging
  # ------------------------------------------------------------------

  async def start_charging(self) -> dict:
    """Start charging."""
    return await self._send_infotainment(build_charging_start_stop_action(start=True))

  async def stop_charging(self) -> dict:
    """Stop charging."""
    return await self._send_infotainment(build_charging_start_stop_action(start=False))

  async def set_charge_limit(self, percent: int) -> dict:
    """Set charge limit percentage."""
    return await self._send_infotainment(build_charging_set_limit_action(percent))

  async def set_charging_amps(self, amps: int) -> dict:
    """Set charging amperage."""
    return await self._send_infotainment(build_set_charging_amps_action(amps))

  async def charge_port_door_open(self) -> dict:
    """Open charge port door (via infotainment)."""
    return await self._send_infotainment(build_charge_port_door_open())

  async def charge_port_door_close(self) -> dict:
    """Close charge port door (via infotainment)."""
    return await self._send_infotainment(build_charge_port_door_close())

  # ------------------------------------------------------------------
  # Infotainment commands — Vehicle controls
  # ------------------------------------------------------------------

  async def honk_horn(self) -> dict:
    """Honk the horn."""
    return await self._send_infotainment(build_honk_horn_action())

  async def flash_lights(self) -> dict:
    """Flash the lights."""
    return await self._send_infotainment(build_flash_lights_action())

  async def vent_windows(self) -> dict:
    """Vent all windows."""
    return await self._send_infotainment(build_window_action(vent=True))

  async def close_windows(self) -> dict:
    """Close all windows."""
    return await self._send_infotainment(build_window_action(close=True))

  async def set_sentry_mode(self, on: bool) -> dict:
    """Enable/disable sentry mode."""
    return await self._send_infotainment(build_set_sentry_mode_action(on))

  async def set_valet_mode(self, on: bool, password: str = '') -> dict:
    """Enable/disable valet mode."""
    return await self._send_infotainment(build_set_valet_mode_action(on, password))

  async def set_pin_to_drive(self, on: bool, pin: str = '') -> dict:
    """Enable/disable PIN to drive."""
    return await self._send_infotainment(build_pin_to_drive_action(on, pin))

  async def set_speed_limit(self, limit_mph: float) -> dict:
    """Set the speed limit (mph)."""
    return await self._send_infotainment(build_set_speed_limit_action(limit_mph))

  async def activate_speed_limit(self, pin: str) -> dict:
    """Activate the speed limit."""
    return await self._send_infotainment(build_speed_limit_activate_action(True, pin))

  async def deactivate_speed_limit(self, pin: str) -> dict:
    """Deactivate the speed limit."""
    return await self._send_infotainment(build_speed_limit_activate_action(False, pin))

  async def trigger_homelink(self) -> dict:
    """Trigger Homelink (garage door)."""
    return await self._send_infotainment(build_trigger_homelink_action())

  async def set_vehicle_name(self, name: str) -> dict:
    """Set the vehicle name."""
    return await self._send_infotainment(build_set_vehicle_name_action(name))

  async def schedule_software_update(self, offset_sec: int) -> dict:
    """Schedule a software update."""
    return await self._send_infotainment(build_schedule_software_update_action(offset_sec))

  async def cancel_software_update(self) -> dict:
    """Cancel a pending software update."""
    return await self._send_infotainment(build_cancel_software_update_action())

  # ------------------------------------------------------------------
  # Infotainment commands — Media
  # ------------------------------------------------------------------

  async def media_toggle_playback(self) -> dict:
    """Toggle media playback."""
    return await self._send_infotainment(build_media_play_action())

  async def media_next_track(self) -> dict:
    """Skip to next track."""
    return await self._send_infotainment(build_media_next_track())

  async def media_previous_track(self) -> dict:
    """Skip to previous track."""
    return await self._send_infotainment(build_media_previous_track())

  async def media_volume_up(self) -> dict:
    """Increase volume."""
    return await self._send_infotainment(build_media_update_volume(1))

  async def media_volume_down(self) -> dict:
    """Decrease volume."""
    return await self._send_infotainment(build_media_update_volume(-1))
