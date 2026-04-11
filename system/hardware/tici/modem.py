#!/usr/bin/env python3
"""
Modem manager replacement for mici (Quectel EG916Q-GL).

Uses AT commands directly over serial ports and pppd for data connection.
Writes state to /dev/shm/modem for openpilot consumption.

Ports:
  /dev/modem_at0 (ttyUSB2) - AT commands (status, signal, config)
  /dev/modem_at1 (ttyUSB3) - PPP data connection
"""

import json
import os
import signal
import subprocess
import sys
import time
import threading

# add openpilot root to path for imports
OPENPILOT_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if OPENPILOT_ROOT not in sys.path:
  sys.path.insert(0, OPENPILOT_ROOT)

from system.hardware.tici.lpa import AtClient

AT_PORT = "/dev/modem_at0"
PPP_PORT = "/dev/modem_at1"
STATE_PATH = "/dev/shm/modem"
SWITCH_SIGNAL = "/dev/shm/modem_switch"
POLL_INTERVAL = 10

# pppd args for cellular connection via ATD*99***1#
PPPD_ARGS = [
  "sudo", "pppd",
  PPP_PORT,
  "460800",           # baud - fast for data
  "noauth",           # don't require peer to auth
  "nodetach",         # stay in foreground
  "noipdefault",      # get IP from peer
  "usepeerdns",       # use carrier DNS
  "defaultroute",     # add default route
  "replacedefaultroute",
  "connect", f"/usr/sbin/chat -v -f /dev/shm/modem_chat",
  "lcp-echo-interval", "30",
  "lcp-echo-failure", "4",
  "mtu", "1500",
  "mru", "1500",
  "novj",
  "novjccomp",
  "ipcp-accept-local",
  "ipcp-accept-remote",
  "nomagic",
  "user", '""',       # empty user for PAP
  "password", '""',   # empty password for PAP
]

CHAT_SCRIPT = """\
ABORT 'NO CARRIER'
ABORT 'NO DIALTONE'
ABORT 'BUSY'
ABORT 'NO ANSWER'
ABORT 'ERROR'
TIMEOUT 30
'' AT
OK ATD*99***1#
CONNECT ''
"""


class ModemState:
  """Tracks and writes modem state to /dev/shm/modem."""

  def __init__(self):
    self.state = "initializing"
    self.signal_strength = 0
    self.signal_quality = 0
    self.network_type = "unknown"
    self.operator = ""
    self.operator_id = ""
    self.band = ""
    self.channel = 0
    self.registration = "unknown"
    self.temperatures = []
    self.ip_address = ""
    self.connected = False
    self.error = ""
    self.imei = ""
    self.iccid = ""
    self.extra = ""

  def write(self):
    data = {
      "state": self.state,
      "signal_strength": self.signal_strength,
      "signal_quality": self.signal_quality,
      "network_type": self.network_type,
      "operator": self.operator,
      "operator_id": self.operator_id,
      "band": self.band,
      "channel": self.channel,
      "registration": self.registration,
      "temperatures": self.temperatures,
      "ip_address": self.ip_address,
      "connected": self.connected,
      "error": self.error,
      "imei": self.imei,
      "iccid": self.iccid,
      "extra": self.extra,
    }
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as f:
      json.dump(data, f)
    os.rename(tmp, STATE_PATH)


def timed(label):
  """Decorator that logs elapsed time for a method call."""
  def decorator(fn):
    def wrapper(self, *args, **kwargs):
      t0 = time.monotonic()
      result = fn(self, *args, **kwargs)
      elapsed = (time.monotonic() - t0) * 1000
      print(f"[timing] {label}: {elapsed:.1f}ms")
      return result
    return wrapper
  return decorator


class Modem:
  def __init__(self):
    self.at: AtClient | None = None
    self.state = ModemState()
    self.pppd_proc: subprocess.Popen | None = None
    self.inhibit_proc: subprocess.Popen | None = None
    self.running = True
    self.boot_start: float = 0.0
    self._ppp_connect_time: float | None = None
    self._ppp_thread: threading.Thread | None = None
    self._needs_reset = threading.Event()

  def _open_at(self):
    """Open or reopen the AT command port."""
    if self.at is not None:
      try:
        self.at.close()
      except Exception:
        pass
    self.at = AtClient(AT_PORT, 9600, 5.0)

  def at_query(self, cmd: str) -> list[str]:
    """Send AT command and return response lines."""
    return self.at.query(cmd)

  def at_query_safe(self, cmd: str) -> list[str]:
    """Send AT command, return [] on error."""
    try:
      t0 = time.monotonic()
      result = self.at.query(cmd)
      elapsed = (time.monotonic() - t0) * 1000
      print(f"[at] {cmd} -> {len(result)} lines ({elapsed:.1f}ms)")
      return result
    except (RuntimeError, TimeoutError, OSError) as e:
      print(f"[at] {cmd} FAILED: {e}")
      return []

  # -- inhibit modem manager --

  @timed("inhibit_modem_manager")
  def start_inhibit(self):
    """Run mmcli --inhibit in a background thread to keep MM away from the modem."""
    inhibit_ready = threading.Event()

    def _inhibit_thread():
      while self.running:
        print("[inhibit] starting mmcli inhibit...")
        try:
          self.inhibit_proc = subprocess.Popen(
            ["sudo", "mmcli", "-m", "any", "--inhibit"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
          )
          # read first line to confirm inhibit is active
          line = self.inhibit_proc.stdout.readline()
          if line:
            print(f"[inhibit] {line.decode().strip()}")
          inhibit_ready.set()
          self.inhibit_proc.wait()
          if self.running:
            print("[inhibit] mmcli inhibit exited, restarting in 5s...")
            time.sleep(5)
        except Exception as e:
          print(f"[inhibit] error: {e}")
          inhibit_ready.set()
          time.sleep(5)

    t = threading.Thread(target=_inhibit_thread, daemon=True)
    t.start()
    # wait for inhibit to confirm, with timeout
    if not inhibit_ready.wait(timeout=5):
      print("[inhibit] WARNING: timed out waiting for inhibit confirmation")

  # -- tear down existing MM connection --

  @timed("teardown_existing")
  def teardown_existing(self):
    """Disconnect any existing MM bearers and kill pppd."""
    print("[setup] tearing down existing connections...")
    # kill any existing pppd
    os.system("sudo killall pppd 2>/dev/null")

  # -- modem init --

  @timed("init_modem")
  def init_modem(self):
    """Initialize modem with basic AT commands."""
    print("[setup] initializing modem...")

    # basic init sequence (same as MM does)
    for cmd in ["ATE0", "ATV1", "AT+CMEE=1", "ATX4", "AT&C1"]:
      self.at_query_safe(cmd)

    # disable SIM sleep for EG916
    for cmd in ["AT$QCSIMSLEEP=0", "AT$QCSIMCFG=SimPowerSave,0"]:
      self.at_query_safe(cmd)

    # enable registration URCs
    self.at_query_safe("AT+CREG=2")
    self.at_query_safe("AT+CGREG=2")

    # get IMEI
    lines = self.at_query_safe("AT+CGSN")
    if lines:
      self.state.imei = lines[0].strip()

    # get ICCID
    lines = self.at_query_safe("AT+QCCID")
    if lines:
      for line in lines:
        if "+QCCID:" in line:
          self.state.iccid = line.split(":", 1)[1].strip()
          break

  # -- PDP context setup --

  @timed("setup_pdp")
  def setup_pdp(self):
    """Ensure PDP context 1 is configured and activated."""
    print("[setup] configuring PDP context...")
    self.at_query_safe('AT+CGDCONT=1,"IPV4V6",""')
    # activate the PDP context — needed after CFUN cycle / profile switch
    self.at_query_safe('AT+CGACT=1,1')

  # -- registration --

  def wait_for_registration(self, timeout=60):
    """Wait until modem is registered on a network."""
    print("[setup] waiting for network registration...")
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
      reg = self._get_registration()
      if reg in ("home", "roaming"):
        elapsed = (time.monotonic() - t0) * 1000
        print(f"[timing] wait_for_registration: {elapsed:.1f}ms (status: {reg})")
        self.state.registration = reg
        self.state.state = "registered"
        self.state.write()
        return True
      time.sleep(0.1)

    elapsed = (time.monotonic() - t0) * 1000
    print(f"[timing] wait_for_registration: {elapsed:.1f}ms (TIMEOUT)")
    self.state.error = "registration timeout"
    self.state.write()
    return False

  def _get_registration(self) -> str:
    """Parse +CREG response for registration status."""
    lines = self.at_query_safe("AT+CREG?")
    for line in lines:
      if "+CREG:" in line:
        parts = line.split(":", 1)[1].strip().split(",")
        if len(parts) >= 2:
          stat = int(parts[1])
          return {0: "not_registered", 1: "home", 2: "searching",
                  3: "denied", 4: "unknown", 5: "roaming"}.get(stat, "unknown")
    return "unknown"

  # -- PPP --

  def write_chat_script(self):
    """Write the chat script for pppd connect."""
    with open("/dev/shm/modem_chat", "w") as f:
      f.write(CHAT_SCRIPT)

  def kill_ppp(self):
    """Kill any running pppd process."""
    os.system("sudo killall pppd 2>/dev/null")
    if self._ppp_thread and self._ppp_thread.is_alive():
      # wait for thread to notice pppd died
      self._ppp_thread.join(timeout=5)
    self.pppd_proc = None

  def start_ppp(self):
    """Start pppd in a background thread. Signals _needs_reset on repeated failures."""
    print("[ppp] starting pppd...")
    self.write_chat_script()
    self._ppp_connect_time = time.monotonic()

    def _ppp_thread():
      consecutive_failures = 0
      while self.running and not self._needs_reset.is_set():
        ppp_start = time.monotonic()
        print(f"[ppp] launching pppd... (T+{(ppp_start - self.boot_start)*1000:.0f}ms)")
        try:
          self.pppd_proc = subprocess.Popen(
            PPPD_ARGS,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
          )
          connected_this_session = False
          # read pppd output
          for raw_line in self.pppd_proc.stdout:
            line = raw_line.decode(errors="ignore").strip()
            if line:
              elapsed_boot = (time.monotonic() - self.boot_start) * 1000
              elapsed_ppp = (time.monotonic() - ppp_start) * 1000
              print(f"[pppd T+{elapsed_boot:.0f}ms] {line}")
              # detect IP assignment
              if "local  IP address" in line:
                ip = line.split("local  IP address")[-1].strip()
                self.state.ip_address = ip
                self.state.connected = True
                self.state.state = "connected"
                self.state.write()
                connected_this_session = True
                consecutive_failures = 0
                print(f"[timing] ppp_connect: {elapsed_ppp:.1f}ms (IP: {ip})")
                print(f"[timing] TOTAL_BOOT_TO_DATA: {elapsed_boot:.1f}ms")
              elif "Connection terminated" in line or "Modem hangup" in line:
                self.state.connected = False
                self.state.state = "disconnected"
                self.state.ip_address = ""
                self.state.write()

          self.pppd_proc.wait()
          rc = self.pppd_proc.returncode
          print(f"[ppp] pppd exited with code {rc}")

          if not connected_this_session:
            consecutive_failures += 1
            print(f"[ppp] consecutive dial failures: {consecutive_failures}")
          else:
            consecutive_failures = 0

        except Exception as e:
          print(f"[ppp] error: {e}")
          consecutive_failures += 1

        self.state.connected = False
        self.state.state = "reconnecting"
        self.state.write()

        if consecutive_failures >= 3:
          print(f"[ppp] {consecutive_failures} consecutive failures, triggering modem reset")
          self._needs_reset.set()
          return

        if self.running and not self._needs_reset.is_set():
          print("[ppp] retrying...")

    self._ppp_thread = threading.Thread(target=_ppp_thread, daemon=True)
    self._ppp_thread.start()

  # -- modem reset / recovery --

  def _port_responsive(self) -> bool:
    """Check if the AT port is actually responsive (not a stale symlink)."""
    try:
      import serial as ser
      s = ser.Serial(AT_PORT, 9600, timeout=2)
      s.reset_input_buffer()
      s.write(b"AT\r")
      resp = s.read(50)
      s.close()
      return b"OK" in resp
    except Exception:
      return False

  def _has_signal(self) -> bool:
    """Check if the modem has actual radio signal (CSQ != 99)."""
    try:
      import serial as ser
      s = ser.Serial(AT_PORT, 9600, timeout=2)
      s.reset_input_buffer()
      s.write(b"AT+CSQ\r")
      resp = s.read(100).decode(errors="ignore")
      s.close()
      if "+CSQ:" in resp:
        rssi = int(resp.split("+CSQ:")[1].strip().split(",")[0])
        return rssi != 99
    except Exception:
      pass
    return False

  def wait_for_modem_port(self, timeout=30):
    """Wait for modem USB to re-enumerate and port to become responsive with signal."""
    t0 = time.monotonic()

    # wait for port to disappear (USB re-enumeration from CFUN cycle)
    print("[reset] waiting for modem USB to re-enumerate...")
    while time.monotonic() - t0 < 10:
      if not os.path.exists(AT_PORT):
        elapsed = (time.monotonic() - t0) * 1000
        print(f"[reset] port disappeared ({elapsed:.0f}ms)")
        break
      time.sleep(0.2)

    # wait for port to come back and respond to AT
    print("[reset] waiting for port to reappear...")
    while time.monotonic() - t0 < timeout:
      if os.path.exists(AT_PORT) and self._port_responsive():
        elapsed = (time.monotonic() - t0) * 1000
        print(f"[reset] port responsive ({elapsed:.0f}ms)")

        # wait for actual signal before proceeding
        print("[reset] waiting for radio signal...")
        while time.monotonic() - t0 < timeout:
          if self._has_signal():
            elapsed = (time.monotonic() - t0) * 1000
            print(f"[timing] modem_ready_with_signal: {elapsed:.1f}ms")
            return True
          time.sleep(0.5)
      time.sleep(0.5)

    print(f"[reset] modem did not become ready within {timeout}s")
    return False

  def reset_and_reconnect(self):
    """Fast modem reconnect after profile switch.

    No CFUN cycle needed — the modem detects the eSIM profile change
    automatically and re-attaches to the network. We just need to kill
    PPP (which is on the old profile's PDP context), re-init, and redial.
    """
    reset_start = time.monotonic()
    triggered_by = "profile switch" if os.path.exists(SWITCH_SIGNAL) else "ppp failure"

    # consume the signal file
    try:
      os.remove(SWITCH_SIGNAL)
    except FileNotFoundError:
      pass

    print(f"\n{'=' * 60}")
    print(f"[reset] triggered by {triggered_by}, reconnecting...")
    print(f"{'=' * 60}")

    self.state.state = "reconnecting"
    self.state.connected = False
    self.state.ip_address = ""
    self.state.write()

    # kill pppd hard — the process and any lingering thread
    self._needs_reset.set()  # signal ppp thread to stop retrying
    os.system("sudo killall -9 pppd 2>/dev/null")
    if self._ppp_thread and self._ppp_thread.is_alive():
      self._ppp_thread.join(timeout=3)
    self.pppd_proc = None

    # reopen AT client (old serial may have buffered URCs from profile switch)
    self._open_at()

    # wait briefly for modem to settle after profile switch
    # (URCs like +CPIN: READY, +CGEV: ME PDN ACT fire within ~1s)
    time.sleep(1)

    # re-init modem
    self.state.state = "initializing"
    self.state.write()
    self.init_modem()

    # setup PDP
    self.setup_pdp()

    # wait for registration
    if not self.wait_for_registration(timeout=30):
      print("[reset] registration failed, trying hardware reset...")
      # fallback to lte.sh if modem is truly stuck
      try:
        if self.at:
          self.at.close()
          self.at = None
        subprocess.run(["sudo", "/usr/comma/lte/lte.sh", "start"],
                        capture_output=True, timeout=30)
        self.wait_for_modem_port(timeout=30)
        self._open_at()
        self.init_modem()
        self.setup_pdp()
        if not self.wait_for_registration(timeout=30):
          self.state.error = "registration failed after hardware reset"
          self.state.write()
          return False
      except Exception as e:
        print(f"[reset] hardware reset failed: {e}")
        return False

    # restart PPP
    self._needs_reset.clear()
    self.state.state = "connecting"
    self.state.write()
    self.start_ppp()

    # wait for connection
    ppp_wait_start = time.monotonic()
    while not self.state.connected and (time.monotonic() - ppp_wait_start) < 30:
      time.sleep(0.2)

    elapsed = (time.monotonic() - reset_start) * 1000
    if self.state.connected:
      print(f"\n[timing] reset_and_reconnect: {elapsed:.1f}ms (success)")
      return True
    else:
      print(f"\n[timing] reset_and_reconnect: {elapsed:.1f}ms (PPP failed)")
      return False

  def check_modem_health(self) -> bool:
    """Check if modem needs a reset. Returns True if healthy."""
    # check if LPA signaled a profile switch (fastest path)
    if os.path.exists(SWITCH_SIGNAL):
      print("[health] profile switch signal detected")
      return False

    # check if port still exists
    if not os.path.exists(AT_PORT):
      print("[health] modem port disappeared")
      return False

    # check if ppp thread signaled a reset
    if self._needs_reset.is_set():
      print("[health] PPP thread signaled reset needed")
      return False

    return True

  # -- status polling --

  def poll_status(self):
    """Poll modem status and update state."""
    # signal quality (AT+CSQ)
    lines = self.at_query_safe("AT+CSQ")
    for line in lines:
      if "+CSQ:" in line:
        parts = line.split(":", 1)[1].strip().split(",")
        rssi = int(parts[0])
        if rssi != 99:
          # convert CSQ to dBm: dBm = -113 + 2*rssi
          # convert to percentage: rough mapping
          self.state.signal_strength = rssi
          self.state.signal_quality = min(100, max(0, int((rssi / 31.0) * 100)))

    # registration
    self.state.registration = self._get_registration()

    # network info (AT+COPS?)
    lines = self.at_query_safe("AT+COPS?")
    for line in lines:
      if "+COPS:" in line:
        parts = line.split(":", 1)[1].strip().split(",")
        if len(parts) >= 3:
          self.state.operator = parts[2].strip('"')
        if len(parts) >= 4:
          act = int(parts[3])
          self.state.network_type = {0: "gsm", 2: "utran", 3: "gsm_egprs",
                                     4: "utran_hsdpa", 5: "utran_hsupa",
                                     6: "utran_hsdpa_hsupa", 7: "lte"}.get(act, "unknown")

    # serving cell info for band/channel
    lines = self.at_query_safe('AT+QNWINFO')
    for line in lines:
      if "+QNWINFO:" in line:
        info = line.split(":", 1)[1].strip().replace('"', '').split(",")
        if len(info) >= 4:
          self.state.band = info[2]
          try:
            self.state.channel = int(info[3])
          except ValueError:
            pass

    # detailed serving cell
    lines = self.at_query_safe('AT+QENG="servingcell"')
    for line in lines:
      if "+QENG:" in line:
        self.state.extra = line.split(":", 1)[1].strip().replace('"', '')

    # temperature
    lines = self.at_query_safe("AT+QTEMP")
    for line in lines:
      if "+QTEMP:" in line:
        try:
          temps_str = line.split(":", 1)[1].strip()
          temps = [int(t) for t in temps_str.split(",") if t.strip()]
          self.state.temperatures = [t for t in temps if t != 255]
        except (ValueError, IndexError):
          pass

    # check ppp0 interface for IP
    try:
      result = subprocess.run(["ip", "-4", "addr", "show", "ppp0"],
                              capture_output=True, text=True, timeout=2)
      for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("inet "):
          ip = line.split()[1].split("/")[0]
          self.state.ip_address = ip
          self.state.connected = True
          self.state.state = "connected"
          break
      else:
        if self.state.state == "connected":
          self.state.connected = False
          self.state.state = "registered"
          self.state.ip_address = ""
    except Exception:
      pass

    self.state.write()

  # -- main loop --

  def run(self):
    self.boot_start = time.monotonic()

    print("=" * 60)
    print("modem.py - modem manager replacement")
    print(f"boot started at {time.strftime('%H:%M:%S')}")
    print("=" * 60)

    # step 1: inhibit ModemManager
    t0 = time.monotonic()
    print(f"\n[1/5 T+{(t0 - self.boot_start)*1000:.0f}ms] inhibiting ModemManager...")
    self.state.state = "inhibiting"
    self.state.write()
    self.start_inhibit()

    # step 2: tear down existing connections
    t0 = time.monotonic()
    print(f"\n[2/5 T+{(t0 - self.boot_start)*1000:.0f}ms] tearing down existing connections...")
    self.teardown_existing()

    # step 3: initialize modem
    t0 = time.monotonic()
    print(f"\n[3/5 T+{(t0 - self.boot_start)*1000:.0f}ms] initializing modem...")
    self.state.state = "initializing"
    self.state.write()
    self._open_at()
    self.init_modem()

    # step 4: setup PDP and wait for registration
    t0 = time.monotonic()
    print(f"\n[4/5 T+{(t0 - self.boot_start)*1000:.0f}ms] setting up PDP and waiting for registration...")
    self.setup_pdp()
    if not self.wait_for_registration():
      print("[error] failed to register, continuing anyway...")

    # step 5: start PPP
    t0 = time.monotonic()
    print(f"\n[5/5 T+{(t0 - self.boot_start)*1000:.0f}ms] starting PPP connection...")
    self.state.state = "connecting"
    self.state.write()
    self.start_ppp()

    # wait for PPP to connect before entering poll loop, with timeout
    ppp_wait_start = time.monotonic()
    while not self.state.connected and (time.monotonic() - ppp_wait_start) < 30:
      time.sleep(0.2)

    if self.state.connected:
      total = (time.monotonic() - self.boot_start) * 1000
      print(f"\n{'=' * 60}")
      print(f"BOOT COMPLETE - data connection established")
      print(f"Total time: {total:.0f}ms ({total/1000:.1f}s)")
      print(f"{'=' * 60}")
    else:
      print(f"\n[warning] PPP did not connect within 30s, entering poll loop anyway")

    # poll loop
    print("\n[running] entering poll loop...")
    last_poll = 0.0
    while self.running:
      try:
        # check for profile switch signal every iteration (fast path)
        if os.path.exists(SWITCH_SIGNAL) or self._needs_reset.is_set() or not os.path.exists(AT_PORT):
          if not self.check_modem_health():
            self.reset_and_reconnect()
            last_poll = time.monotonic()
            continue

        # full status poll every POLL_INTERVAL
        if time.monotonic() - last_poll >= POLL_INTERVAL:
          self.poll_status()
          last_poll = time.monotonic()
      except Exception as e:
        print(f"[poll] error: {e}")
      time.sleep(0.5)  # check signal file every 500ms

  def stop(self):
    print("\n[shutdown] stopping...")
    self.running = False
    self._needs_reset.set()  # unblock ppp thread if waiting

    if self.pppd_proc:
      print("[shutdown] killing pppd...")
      os.system("sudo killall pppd 2>/dev/null")

    if self.inhibit_proc:
      print("[shutdown] killing mmcli inhibit...")
      self.inhibit_proc.terminate()

    if self.at:
      self.at.close()
    print("[shutdown] done.")


def main():
  modem = Modem()

  def signal_handler(sig, frame):
    modem.stop()
    sys.exit(0)

  signal.signal(signal.SIGINT, signal_handler)
  signal.signal(signal.SIGTERM, signal_handler)

  modem.run()


if __name__ == "__main__":
  main()
