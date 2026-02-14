# Debugging on device -- run shell commands

source .venv/bin/activate
tools/scripts/adb_ssh.sh <command>

# Debugging system/hardware/tici/lpa.py on device

source .venv/bin/activate
tools/scripts/adb_ssh.sh /usr/local/venv/bin/python /data/openpilot/system/hardware/tici/lpa.py <flags>
