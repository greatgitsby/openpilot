import sounddevice as _
import speech_recognition as sr
from speech_recognition.recognizers.pocketsphinx import recognize

def callback(recognizer: sr.Recognizer, audio: sr.AudioData):
  try:
    out = recognize(recognizer, audio, keyword_entries=[("hey comma", 1.,), ('bookmark', 1.)])
    print('phrase: ' + out)
  except sr.exceptions.UnknownValueError:
    pass


if __name__ == '__main__':
  r = sr.Recognizer()
  m = sr.Microphone()
  with m as source:
    r.adjust_for_ambient_noise(source)

  stop_listening = r.listen_in_background(m, callback, phrase_time_limit=2.)

  input("listening... press enter to stop.\n")
  stop_listening(wait_for_stop=False)
