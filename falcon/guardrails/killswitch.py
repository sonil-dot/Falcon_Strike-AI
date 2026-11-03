"""Kill switch: a file flag (works across terminals) + in-process flag + Ctrl+C.
The live runner checks it between actions and inside the beacon loop."""
import os
import signal


class KillSwitch:
    def __init__(self, path="KILL"):
        self.path = path
        self._flag = False

    def trip(self, reason="manual"):
        self._flag = True
        with open(self.path, "w") as f:
            f.write(reason)

    def is_set(self):
        return self._flag or os.path.exists(self.path)

    def clear(self):
        self._flag = False
        if os.path.exists(self.path):
            os.remove(self.path)

    def install_signal_handler(self):
        def handler(signum, frame):
            self._flag = True
        signal.signal(signal.SIGINT, handler)
