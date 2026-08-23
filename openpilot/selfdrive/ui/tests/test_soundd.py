import threading

from openpilot.common.test import OpenpilotTestCase
from openpilot.cereal import log, messaging
from openpilot.cereal.messaging import SubMaster, PubMaster
from openpilot.selfdrive.ui.soundd import NAV_LANE_ADVICE_ALERT, SELFDRIVE_STATE_TIMEOUT, Soundd, check_selfdrive_timeout_alert

AudibleAlert = log.SelfdriveState.AudibleAlert


class TestSoundd(OpenpilotTestCase):
  def test_check_selfdrive_timeout_alert(self, mocker):
    sm = SubMaster(['selfdriveState'])
    pm = PubMaster(['selfdriveState'])

    cs = messaging.new_message('selfdriveState')
    cs.selfdriveState.enabled = True
    threading.Timer(0.01, pm.send, args=("selfdriveState", cs)).start()
    sm.update(100)
    assert sm.updated['selfdriveState']

    sm.recv_time['selfdriveState'] = 0
    clock = mocker.patch("openpilot.selfdrive.ui.soundd.time.monotonic", return_value=SELFDRIVE_STATE_TIMEOUT)
    assert not check_selfdrive_timeout_alert(sm)

    clock.return_value = SELFDRIVE_STATE_TIMEOUT + 0.1
    assert check_selfdrive_timeout_alert(sm)

    clock.return_value = SELFDRIVE_STATE_TIMEOUT + 10
    assert not check_selfdrive_timeout_alert(sm)

  def test_nav_lane_advice_chime(self):
    sm = SubMaster(['modelV2'])
    pm = PubMaster(['modelV2'])
    s = Soundd()

    def send_advice(advice):
      msg = messaging.new_message('modelV2')
      msg.modelV2.meta.navLaneAdvice = advice
      threading.Timer(0.01, pm.send, args=("modelV2", msg)).start()
      sm.update(100)
      s.update_nav_lane_advice(sm)

    # one chime on the rising edge, none while the advice is held
    send_advice('moveLeft')
    assert s.current_alert == NAV_LANE_ADVICE_ALERT
    s.current_alert = AudibleAlert.none
    send_advice('moveLeft')
    assert s.current_alert == AudibleAlert.none

    # a new advice chimes again, clearing it does not
    send_advice('moveRight')
    assert s.current_alert == NAV_LANE_ADVICE_ALERT
    s.current_alert = AudibleAlert.none
    send_advice('none')
    assert s.current_alert == AudibleAlert.none

  def test_nav_lane_advice_does_not_override_alert(self):
    sm = SubMaster(['modelV2'])
    pm = PubMaster(['modelV2'])
    s = Soundd()
    s.current_alert = AudibleAlert.warningImmediate

    msg = messaging.new_message('modelV2')
    msg.modelV2.meta.navLaneAdvice = 'moveLeft'
    threading.Timer(0.01, pm.send, args=("modelV2", msg)).start()
    sm.update(100)
    s.update_nav_lane_advice(sm)

    assert s.current_alert == AudibleAlert.warningImmediate

  # TODO: add test with micd for checking that soundd actually outputs sounds
