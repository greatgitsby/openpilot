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
QMI_DEV = "/dev/cdc-wdm0"
QMI_IFACE = "wwan0"
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

CHAT_SCRIPT_TEMPLATE = """\
ABORT 'NO CARRIER'
ABORT 'NO DIALTONE'
ABORT 'BUSY'
ABORT 'NO ANSWER'
ABORT 'ERROR'
TIMEOUT 30
'' AT
OK ATD*99***{cid}#
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
    self._data_thread: threading.Thread | None = None
    self._needs_reset = threading.Event()
    self._dial_cid = 1
    with open("/sys/firmware/devicetree/base/model") as f:
      self._device_type = f.read().strip('\x00').split('comma ')[-1]
    print(f"[init] device: {self._device_type}")

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

  @timed("stop_modem_manager")
  def stop_modem_manager(self):
    """Stop ModemManager. On mici we use inhibit (keeps MM alive for LPA), on tizi we fully stop it."""
    if self._device_type == "tizi":
      # fully stop MM so we own the QMI device
      os.system("sudo systemctl stop ModemManager 2>/dev/null")
      print("[mm] ModemManager stopped")
      return

    # mici: use inhibit to keep MM process alive for LPA dbus queries
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
    if not inhibit_ready.wait(timeout=5):
      print("[inhibit] WARNING: timed out waiting for inhibit confirmation")

  # -- tear down existing MM connection --

  @timed("teardown_existing")
  def teardown_existing(self):
    """Disconnect any existing data connections."""
    print("[setup] tearing down existing connections...")
    os.system("sudo killall pppd 2>/dev/null")
    if self._device_type == "tizi":
      os.system(f"sudo ip link set {QMI_IFACE} down 2>/dev/null")

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
    """Configure PDP context and set dial CID based on device type."""
    print("[setup] configuring PDP context...")
    self.at_query_safe('AT+CGDCONT=1,"IPV4V6",""')
    # activate the PDP context — needed after profile switch
    self.at_query_safe('AT+CGACT=1,1')
    # EG916 (mici) dials on CID 1, EG25 (tizi) on CID 3
    self._dial_cid = 3 if self._device_type == "tizi" else 1
    print(f"[setup] using CID {self._dial_cid} for PPP dial")

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

  # -- data connection (PPP for mici, QMI for tizi) --

  def kill_data(self):
    """Kill the active data connection."""
    if self._device_type == "tizi":
      os.system(f"sudo ip link set {QMI_IFACE} down 2>/dev/null")
    else:
      os.system("sudo killall pppd 2>/dev/null")
    if self._data_thread and self._data_thread.is_alive():
      self._data_thread.join(timeout=5)
    self.pppd_proc = None

  def start_data(self):
    """Start the data connection in a background thread."""
    if self._device_type == "tizi":
      self._start_qmi()
    else:
      self._start_ppp()

  def _qmi_cmd(self, args: str) -> subprocess.CompletedProcess:
    """Run a qmicli command."""
    return subprocess.run(
      ["sudo", "qmicli", "-d", QMI_DEV] + args.split(),
      capture_output=True, text=True, timeout=10,
    )

  def _qmi_configure_interface(self) -> str | None:
    """Get IP settings from QMI WDS and configure wwan0 statically. Returns IP or None."""
    result = self._qmi_cmd("--wds-get-current-settings")
    if result.returncode != 0:
      print(f"[qmi] get-current-settings failed: {result.stderr.strip()}")
      return None

    ip, prefix, gw, dns1, dns2, mtu = None, "29", None, None, None, "1500"
    for line in result.stdout.splitlines():
      line = line.strip()
      if "IPv4 address:" in line:
        ip = line.split(":")[-1].strip()
      elif "IPv4 subnet mask:" in line:
        # convert mask to prefix
        mask = line.split(":")[-1].strip()
        prefix = str(sum(bin(int(x)).count('1') for x in mask.split('.')))
      elif "IPv4 gateway address:" in line:
        gw = line.split(":")[-1].strip()
      elif "IPv4 primary DNS:" in line:
        dns1 = line.split(":")[-1].strip()
      elif "IPv4 secondary DNS:" in line:
        dns2 = line.split(":")[-1].strip()
      elif "MTU:" in line:
        mtu = line.split(":")[-1].strip()

    if not ip or not gw:
      print(f"[qmi] incomplete IP settings: ip={ip} gw={gw}")
      return None

    print(f"[qmi] IP: {ip}/{prefix} gw: {gw} dns: {dns1},{dns2} mtu: {mtu}")

    # configure interface
    subprocess.run(["sudo", "ip", "addr", "flush", "dev", QMI_IFACE], capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "addr", "add", f"{ip}/{prefix}", "dev", QMI_IFACE], capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", QMI_IFACE, "mtu", mtu], capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", QMI_IFACE, "up"], capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "route", "replace", "default", "dev", QMI_IFACE, "metric", "100"], capture_output=True, timeout=5)

    # set DNS
    dns_lines = []
    if dns1:
      dns_lines.append(f"nameserver {dns1}")
    if dns2:
      dns_lines.append(f"nameserver {dns2}")
    if dns_lines:
      try:
        with open("/tmp/resolv_modem.conf", "w") as f:
          f.write("\n".join(dns_lines) + "\n")
      except Exception:
        pass

    return ip

  def _start_qmi(self):
    """Start QMI data connection for tizi (EG25)."""
    print("[qmi] starting QMI data connection...")

    def _qmi_thread():
      consecutive_failures = 0
      while self.running and not self._needs_reset.is_set():
        qmi_start = time.monotonic()
        elapsed_boot = (qmi_start - self.boot_start) * 1000
        print(f"[qmi] connecting... (T+{elapsed_boot:.0f}ms)")
        try:
          # set raw_ip mode (must be done while interface is down)
          subprocess.run(["sudo", "ip", "link", "set", QMI_IFACE, "down"], capture_output=True, timeout=5)
          try:
            with open(f"/sys/class/net/{QMI_IFACE}/qmi/raw_ip", "w") as f:
              f.write("Y")
          except Exception:
            pass

          # deactivate stale PDP contexts from modem autoconnect
          self.at_query_safe("AT+CGACT=0,1")
          self.at_query_safe("AT+CGACT=0,3")

          # start QMI WDS network
          result = self._qmi_cmd("--wds-start-network=ip-type=4 --client-no-release-cid")
          if result.returncode == 0:
            print(f"[qmi] network started")
          elif "interface-in-use" in result.stderr or "already-started" in (result.stderr + result.stdout).lower():
            print(f"[qmi] data call already active")
          elif "CallFailed" in result.stderr:
            print(f"[qmi] call failed: {result.stderr.strip()}")
            consecutive_failures += 1
            if consecutive_failures >= 3:
              self._needs_reset.set()
              return
            time.sleep(1)
            continue
          else:
            print(f"[qmi] error: {result.stderr.strip()}")
            consecutive_failures += 1
            if consecutive_failures >= 3:
              self._needs_reset.set()
              return
            time.sleep(1)
            continue

          # bring up interface first, then try DHCP as fallback for static config
          subprocess.run(["sudo", "ip", "link", "set", QMI_IFACE, "up"], capture_output=True, timeout=5)

          # try static config from QMI first
          ip = self._qmi_configure_interface()

          # fallback to DHCP if static config fails
          if not ip:
            print("[qmi] static config failed, trying DHCP...")
            dhcp = subprocess.run(
              ["sudo", "udhcpc", "-q", "-f", "-n", "-i", QMI_IFACE],
              capture_output=True, text=True, timeout=15,
            )
            for line in dhcp.stdout.splitlines():
              if "lease of" in line:
                ip = line.split("lease of")[1].split("obtained")[0].strip()
          if ip:
            elapsed = (time.monotonic() - qmi_start) * 1000
            elapsed_boot = (time.monotonic() - self.boot_start) * 1000
            self.state.ip_address = ip
            self.state.connected = True
            self.state.state = "connected"
            self.state.write()
            consecutive_failures = 0
            print(f"[timing] qmi_connect: {elapsed:.1f}ms (IP: {ip})")
            print(f"[timing] TOTAL_BOOT_TO_DATA: {elapsed_boot:.1f}ms")

            # monitor — wait until interface loses IP or reset signaled
            while self.running and not self._needs_reset.is_set():
              r = subprocess.run(["ip", "-4", "addr", "show", QMI_IFACE],
                                 capture_output=True, text=True, timeout=2)
              if "inet " not in r.stdout:
                print("[qmi] interface lost IP, reconnecting...")
                self.state.connected = False
                self.state.state = "disconnected"
                self.state.ip_address = ""
                self.state.write()
                break
              time.sleep(5)
          else:
            consecutive_failures += 1
            print(f"[qmi] IP config failed, consecutive failures: {consecutive_failures}")

        except Exception as e:
          print(f"[qmi] error: {e}")
          consecutive_failures += 1

        if consecutive_failures >= 3:
          print(f"[qmi] {consecutive_failures} consecutive failures, triggering modem reset")
          self._needs_reset.set()
          return

        self.state.connected = False
        self.state.state = "reconnecting"
        self.state.write()

        if self.running and not self._needs_reset.is_set():
          print("[qmi] retrying...")
          time.sleep(1)

    self._data_thread = threading.Thread(target=_qmi_thread, daemon=True)
    self._data_thread.start()

  def _start_ppp(self):
    """Start PPP data connection for mici (EG916)."""
    print("[ppp] starting pppd...")
    cid = getattr(self, '_dial_cid', 1)
    with open("/dev/shm/modem_chat", "w") as f:
      f.write(CHAT_SCRIPT_TEMPLATE.format(cid=cid))
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
          for raw_line in self.pppd_proc.stdout:
            line = raw_line.decode(errors="ignore").strip()
            if line:
              elapsed_boot = (time.monotonic() - self.boot_start) * 1000
              elapsed_ppp = (time.monotonic() - ppp_start) * 1000
              print(f"[pppd T+{elapsed_boot:.0f}ms] {line}")
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

    self._data_thread = threading.Thread(target=_ppp_thread, daemon=True)
    self._data_thread.start()

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

    # kill data connection hard — the process and any lingering thread
    self._needs_reset.set()  # signal data thread to stop retrying
    if self._device_type == "tizi":
      os.system(f"sudo ip link set {QMI_IFACE} down 2>/dev/null")
    else:
      os.system("sudo killall -9 pppd 2>/dev/null")
    if self._data_thread and self._data_thread.is_alive():
      self._data_thread.join(timeout=3)
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
    self.start_data()

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

    # check data interface for IP
    iface = QMI_IFACE if self._device_type == "tizi" else "ppp0"
    try:
      result = subprocess.run(["ip", "-4", "addr", "show", iface],
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
    self.stop_modem_manager()

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
    self.start_data()

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
    self._needs_reset.set()  # unblock data thread if waiting

    print("[shutdown] killing data connection...")
    self.kill_data()

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
