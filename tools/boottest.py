#!/usr/bin/env python3
"""Boot a ROM in Azahar for a few seconds and report whether it crashed.

  boottest.py ROM.3ds [seconds]

Opens the ROM with Azahar.app (its window appears), quits it cleanly so the log is
flushed, then scans Azahar's log for a panic (svcBreak) or CPU exception.
Only one Azahar instance should run meanwhile: they share the log file.
"""
import os
import re
import signal
import subprocess
import sys
import time

APP = "/Applications/Azahar.app"
LOG = os.path.expanduser("~/Library/Application Support/Azahar/log/azahar_log.txt")


def main():
    rom = os.path.abspath(sys.argv[1])
    seconds = float(sys.argv[2]) if len(sys.argv) > 2 else 8
    # launch through the app bundle: running the executable directly shows a modal
    # warning that can hold up emulation
    subprocess.run(["open", "-n", "-a", APP, "--args", rom], check=True)
    time.sleep(seconds)
    pids = [int(x) for x in subprocess.run(["pgrep", "-f", rom], capture_output=True, text=True).stdout.split()]
    for pid in pids:
        os.kill(pid, signal.SIGTERM)
    deadline = time.time() + 10
    while time.time() < deadline and subprocess.run(["pgrep", "-f", rom], capture_output=True).returncode == 0:
        time.sleep(0.2)
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    bad = []
    with open(LOG, errors="replace") as f:
        for line in f:
            if re.search(r"broke execution|Exception Type|unmapped (Read|Write)", line):
                bad.append(line.strip())
                if len(bad) >= 4:
                    break
    print(f"{os.path.basename(rom)}: {'CRASH' if bad else 'ok'} after {seconds:.0f}s")
    for line in bad:
        print("   ", line[:200])
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
