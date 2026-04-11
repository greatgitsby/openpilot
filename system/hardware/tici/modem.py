#!/usr/bin/env python3
import json, os, signal, subprocess, sys, time, threading

sys.path.insert(0, os.path.realpath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))
from system.hardware.tici.lpa import AtClient

AT_PORT, PPP_PORT, STATE_PATH = "/dev/modem_at0", "/dev/modem_at1", "/dev/shm/modem"
CREG = {0: "not_registered", 1: "home", 2: "searching", 3: "denied", 4: "unknown", 5: "roaming"}
PPPD = ["sudo", "pppd", PPP_PORT, "460800", "noauth", "nodetach", "noipdefault", "usepeerdns",
        "defaultroute", "replacedefaultroute", "connect", "/usr/sbin/chat -v -f /dev/shm/modem_chat",
        "lcp-echo-interval", "30", "lcp-echo-failure", "4", "mtu", "1500", "mru", "1500",
        "novj", "novjccomp", "ipcp-accept-local", "ipcp-accept-remote", "nomagic", "user", '""', "password", '""']
CHAT = "ABORT 'NO CARRIER'\nABORT 'NO DIALTONE'\nABORT 'BUSY'\nABORT 'NO ANSWER'\nABORT 'ERROR'\nTIMEOUT 30\n'' AT\nOK ATD*99***{cid}#\nCONNECT ''\n"


class Modem:
  def __init__(self):
    self.at, self.running, self._t0 = None, True, time.monotonic()
    self._ppp, self._reset = None, threading.Event()
    self._cid = 1
    self.S = {"state": "init", "connected": False, "ip_address": "", "iccid": "", "imei": "",
              "signal_quality": 0, "network_type": "unknown", "operator": "", "registration": "unknown",
              "temperatures": [], "error": ""}

  def _ms(self): return (time.monotonic() - self._t0) * 1000
  def _ws(self):
    with open(STATE_PATH + ".tmp", "w") as f: json.dump(self.S, f)
    os.rename(STATE_PATH + ".tmp", STATE_PATH)

  def _open(self):
    if self.at:
      try: self.at.close()
      except Exception: pass
    self.at = AtClient(AT_PORT, 9600, 5.0)

  def _at(self, cmd):
    try:
      t = time.monotonic()
      r = self.at.query(cmd)
      print(f"[at] {cmd} -> {len(r)} ({(time.monotonic()-t)*1000:.0f}ms)")
      return r
    except (RuntimeError, TimeoutError, OSError) as e:
      print(f"[at] {cmd} FAIL: {e}")
      return []

  def _atv(self, cmd, pfx):
    for l in self._at(cmd):
      if pfx in l and ":" in l: return l.split(":", 1)[1].strip()
    return None

  @staticmethod
  def _unbind_qmi():
    if os.path.exists("/dev/cdc-wdm0"):
      os.system("echo '1-1:1.4' | sudo tee /sys/bus/usb/drivers/qmi_wwan/unbind 2>/dev/null")

  def _inhibit(self):
    e = threading.Event()
    def run():
      while self.running:
        try:
          p = subprocess.Popen(["sudo", "mmcli", "-m", "any", "--inhibit"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
          p.stdout.readline(); e.set(); p.wait()
          if self.running: time.sleep(5)
        except Exception:
          e.set(); time.sleep(5)
    threading.Thread(target=run, daemon=True).start()
    e.wait(timeout=5)

  def _init(self):
    for c in ["ATE0","ATV1","AT+CMEE=1","ATX4","AT&C1","AT$QCSIMSLEEP=0","AT$QCSIMCFG=SimPowerSave,0","AT+CREG=2","AT+CGREG=2"]:
      self._at(c)
    r = self._at("AT+CGSN")
    if r: self.S["imei"] = r[0].strip()
    v = self._atv("AT+QCCID", "+QCCID:")
    if v: self.S["iccid"] = v

  def _pdp(self):
    # find highest CID with carrier APN, TODO: read from config instead
    self._cid, best = 1, None
    for l in self._at("AT+CGDCONT?"):
      if "+CGDCONT:" not in l: continue
      p = l.split(":", 1)[1].strip().split(",")
      if len(p) >= 3:
        c, a = int(p[0]), p[2].strip('"')
        if a and a != "ims": best = (c, a)
    if best:
      self._cid = best[0]
      print(f"[pdp] APN '{best[1]}' CID {self._cid}")
    else:
      self._at('AT+CGDCONT=1,"IP",""')
    self._at(f'AT+CGACT=1,{self._cid}')

  def _wait_reg(self, timeout=60):
    t = time.monotonic()
    while time.monotonic() - t < timeout:
      v = self._atv("AT+CREG?", "+CREG:")
      if v:
        try:
          reg = CREG.get(int(v.split(",")[1].strip('"')), "unknown")
        except (ValueError, IndexError): reg = "unknown"
        if reg in ("home", "roaming"):
          print(f"[timing] reg: {(time.monotonic()-t)*1000:.0f}ms ({reg})")
          self.S["registration"] = reg
          return True
      time.sleep(0.5)
    return False

  def _boot(self):
    self._open(); time.sleep(1); self._init(); self._pdp()
    return self._wait_reg(timeout=30)

  def _probe(self):
    try:
      import serial
      s = serial.Serial(AT_PORT, 9600, timeout=2)
      s.reset_input_buffer(); s.write(b"AT\r"); ok = b"OK" in s.read(50); s.close()
      return ok
    except Exception: return False

  def _wait_port(self, timeout=30):
    t = time.monotonic()
    while time.monotonic() - t < timeout:
      if os.path.exists(AT_PORT) and self._probe(): return True
      time.sleep(0.5)
    return False

  def _hw_reset(self):
    if self.at:
      try: self.at.close()
      except Exception: pass
      self.at = None
    try: subprocess.run(["sudo", "/usr/comma/lte/lte.sh", "start"], capture_output=True, timeout=30)
    except Exception: pass
    self._unbind_qmi()

  # -- PPP --

  def _kill_ppp(self):
    os.system("sudo killall pppd 2>/dev/null")
    if self._ppp and self._ppp.is_alive(): self._ppp.join(timeout=5)

  def _start_ppp(self):
    with open("/dev/shm/modem_chat", "w") as f: f.write(CHAT.format(cid=self._cid))
    def run():
      fails = 0
      while self.running and not self._reset.is_set():
        print(f"[ppp] dial (T+{self._ms():.0f}ms)")
        try:
          proc = subprocess.Popen(PPPD, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
          ok = False
          for raw in proc.stdout:
            line = raw.decode(errors="ignore").strip()
            if not line: continue
            print(f"[pppd T+{self._ms():.0f}ms] {line}")
            if "local  IP address" in line:
              ip = line.split("local  IP address")[-1].strip()
              self.S.update(ip_address=ip, connected=True, state="connected"); self._ws()
              ok, fails = True, 0
              print(f"[timing] ppp: {self._ms():.0f}ms (IP: {ip})")
            elif "Connection terminated" in line or "Modem hangup" in line:
              self.S.update(connected=False, state="disconnected", ip_address=""); self._ws()
          proc.wait()
          if not ok: fails += 1; print(f"[ppp] fail {fails}/3")
        except Exception as e:
          print(f"[ppp] {e}"); fails += 1
        self.S.update(connected=False, state="reconnecting"); self._ws()
        if fails >= 3: self._reset.set(); return
    self._ppp = threading.Thread(target=run, daemon=True)
    self._ppp.start()

  # -- health / recovery --

  def _healthy(self):
    if not os.path.exists(AT_PORT): return False
    if self._reset.is_set(): return False
    if self.S["iccid"]:
      v = self._atv("AT+QCCID", "+QCCID:")
      if v and v != self.S["iccid"]:
        print(f"[health] ICCID {self.S['iccid']} -> {v}")
        return False
    return True

  def _reconnect(self):
    print(f"\n{'='*60}\n[reset] reconnecting\n{'='*60}")
    self.S.update(state="reconnecting", connected=False, ip_address=""); self._ws()
    self._reset.set()
    os.system("sudo killall -9 pppd 2>/dev/null")
    if self._ppp and self._ppp.is_alive(): self._ppp.join(timeout=3)
    if self.at:
      try: self.at.close()
      except Exception: pass
      self.at = None
    self._unbind_qmi()
    if not os.path.exists(AT_PORT) and not self._wait_port(): self._hw_reset(); self._wait_port()
    if not self._boot(): self._hw_reset(); self._wait_port(); self._boot()
    self._reset.clear(); self.S["state"] = "connecting"; self._ws(); self._start_ppp()
    t = time.monotonic()
    while not self.S["connected"] and time.monotonic() - t < 30: time.sleep(0.2)

  def _poll(self):
    v = self._atv("AT+CSQ", "+CSQ:")
    if v:
      try:
        rssi = int(v.split(",")[0])
        if rssi != 99: self.S["signal_quality"] = min(100, int(rssi / 31.0 * 100))
      except (ValueError, IndexError): pass
    v = self._atv("AT+COPS?", "+COPS:")
    if v:
      p = v.split(",")
      try:
        if len(p) >= 3: self.S["operator"] = p[2].strip('"')
        if len(p) >= 4: self.S["network_type"] = {0:"gsm",2:"utran",7:"lte"}.get(int(p[3]),"unknown")
      except (ValueError, IndexError): pass
    v = self._atv("AT+QTEMP", "+QTEMP:")
    if v:
      try: self.S["temperatures"] = [t for t in (int(x) for x in v.split(",") if x.strip()) if t != 255]
      except (ValueError, IndexError): pass
    try:
      r = subprocess.run(["ip", "-4", "addr", "show", "ppp0"], capture_output=True, text=True, timeout=2)
      ip = next((l.strip().split()[1].split("/")[0] for l in r.stdout.splitlines() if "inet " in l), None)
      if ip: self.S.update(ip_address=ip, connected=True, state="connected")
      elif self.S["connected"]: self.S.update(connected=False, state="registered", ip_address="")
    except Exception: pass
    self._ws()

  def run(self):
    print(f"{'='*60}\nmodem.py {time.strftime('%H:%M:%S')}\n{'='*60}")
    print(f"[1/4 T+{self._ms():.0f}ms] inhibit + teardown")
    self._inhibit(); os.system("sudo killall pppd 2>/dev/null"); self._unbind_qmi()
    print(f"[2/4 T+{self._ms():.0f}ms] init"); self._open(); self._init()
    print(f"[3/4 T+{self._ms():.0f}ms] PDP + reg"); self._pdp(); self._wait_reg()
    print(f"[4/4 T+{self._ms():.0f}ms] PPP"); self.S["state"] = "connecting"; self._ws(); self._start_ppp()
    t = time.monotonic()
    while not self.S["connected"] and time.monotonic() - t < 30: time.sleep(0.2)
    if self.S["connected"]: print(f"\n{'='*60}\nBOOT {self._ms():.0f}ms\n{'='*60}")
    while self.running:
      try:
        if not self._healthy(): self._reconnect()
        else: self._poll()
      except Exception as e: print(f"[err] {e}")
      time.sleep(10)

  def stop(self):
    self.running = False; self._reset.set(); self._kill_ppp()
    if self.at: self.at.close()


if __name__ == "__main__":
  m = Modem()
  for s in (signal.SIGINT, signal.SIGTERM): signal.signal(s, lambda *_: (m.stop(), sys.exit(0)))
  m.run()
