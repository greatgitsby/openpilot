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
  "persist",          # reconnect on drop
  "maxfail", "0",     # retry forever
  "holdoff", "5",     # 5s between retries
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


class Modem:
  def __init__(self):
    self.at = AtClient(AT_PORT, 9600, 5.0)
    self.state = ModemState()
    self.pppd_proc: subprocess.Popen | None = None
    self.inhibit_proc: subprocess.Popen | None = None
    self.running = True

  def at_query(self, cmd: str) -> list[str]:
    """Send AT command and return response lines."""
    return self.at.query(cmd)

  def at_query_safe(self, cmd: str) -> list[str]:
    """Send AT command, return [] on error."""
    try:
      return self.at.query(cmd)
    except (RuntimeError, TimeoutError, OSError) as e:
      print(f"AT command failed ({cmd}): {e}")
      return []

  # -- inhibit modem manager --

  def start_inhibit(self):
    """Run mmcli --inhibit in a background thread to keep MM away from the modem."""
    def _inhibit_thread():
      while self.running:
        print("[inhibit] starting mmcli inhibit...")
        try:
          self.inhibit_proc = subprocess.Popen(
            ["sudo", "mmcli", "-m", "any", "--inhibit"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
          )
          self.inhibit_proc.wait()
          if self.running:
            print("[inhibit] mmcli inhibit exited, restarting in 2s...")
            time.sleep(2)
        except Exception as e:
          print(f"[inhibit] error: {e}")
          time.sleep(2)

    t = threading.Thread(target=_inhibit_thread, daemon=True)
    t.start()
    # wait for inhibit to take effect
    time.sleep(2)

  # -- tear down existing MM connection --

  def teardown_existing(self):
    """Disconnect any existing MM bearers and kill pppd."""
    print("[setup] tearing down existing connections...")
    # kill any existing pppd
    os.system("sudo killall pppd 2>/dev/null")
    time.sleep(1)

  # -- modem init --

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

  def setup_pdp(self):
    """Ensure PDP context 1 is configured for IPV4V6 with empty APN (carrier default)."""
    print("[setup] configuring PDP context...")
    self.at_query_safe('AT+CGDCONT=1,"IPV4V6",""')

  # -- registration --

  def wait_for_registration(self, timeout=60):
    """Wait until modem is registered on a network."""
    print("[setup] waiting for network registration...")
    start = time.monotonic()
    while time.monotonic() - start < timeout:
      reg = self._get_registration()
      if reg in ("home", "roaming"):
        print(f"[setup] registered: {reg}")
        self.state.registration = reg
        self.state.state = "registered"
        self.state.write()
        return True
      time.sleep(2)

    print("[setup] registration timeout")
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

  def start_ppp(self):
    """Start pppd in a background thread."""
    print("[ppp] starting pppd...")
    self.write_chat_script()

    def _ppp_thread():
      while self.running:
        print("[ppp] launching pppd...")
        try:
          self.pppd_proc = subprocess.Popen(
            PPPD_ARGS,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
          )
          # read pppd output
          for raw_line in self.pppd_proc.stdout:
            line = raw_line.decode(errors="ignore").strip()
            if line:
              print(f"[pppd] {line}")
              # detect IP assignment
              if "local  IP address" in line:
                ip = line.split("local  IP address")[-1].strip()
                self.state.ip_address = ip
                self.state.connected = True
                self.state.state = "connected"
                self.state.write()
                print(f"[ppp] connected with IP: {ip}")
              elif "remote IP address" in line:
                pass  # peer IP, not needed
              elif "Connection terminated" in line or "Modem hangup" in line:
                self.state.connected = False
                self.state.state = "disconnected"
                self.state.ip_address = ""
                self.state.write()

          self.pppd_proc.wait()
          print(f"[ppp] pppd exited with code {self.pppd_proc.returncode}")
        except Exception as e:
          print(f"[ppp] error: {e}")

        self.state.connected = False
        self.state.state = "reconnecting"
        self.state.write()

        if self.running:
          print("[ppp] restarting in 5s...")
          time.sleep(5)

    t = threading.Thread(target=_ppp_thread, daemon=True)
    t.start()

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
    print("=" * 60)
    print("modem.py - modem manager replacement")
    print("=" * 60)

    # step 1: inhibit ModemManager
    print("\n[1/5] inhibiting ModemManager...")
    self.state.state = "inhibiting"
    self.state.write()
    self.start_inhibit()

    # step 2: tear down existing connections
    print("\n[2/5] tearing down existing connections...")
    self.teardown_existing()

    # step 3: initialize modem
    print("\n[3/5] initializing modem...")
    self.state.state = "initializing"
    self.state.write()
    self.init_modem()

    # step 4: setup PDP and wait for registration
    print("\n[4/5] setting up PDP and waiting for registration...")
    self.setup_pdp()
    if not self.wait_for_registration():
      print("[error] failed to register, continuing anyway...")

    # step 5: start PPP
    print("\n[5/5] starting PPP connection...")
    self.state.state = "connecting"
    self.state.write()
    self.start_ppp()

    # poll loop
    print("\n[running] entering poll loop...")
    while self.running:
      try:
        self.poll_status()
      except Exception as e:
        print(f"[poll] error: {e}")
      time.sleep(POLL_INTERVAL)

  def stop(self):
    print("\n[shutdown] stopping...")
    self.running = False

    if self.pppd_proc:
      print("[shutdown] killing pppd...")
      os.system("sudo killall pppd 2>/dev/null")

    if self.inhibit_proc:
      print("[shutdown] killing mmcli inhibit...")
      self.inhibit_proc.terminate()

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
