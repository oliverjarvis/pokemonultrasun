#!/usr/bin/env python3
"""Boot a ROM in Azahar for a few seconds and report whether it crashed.

  boottest.py ROM.3ds [seconds] [movie.ctm]

With a movie (recorded with `azahar -r`), the recorded button presses are
replayed, e.g. title -> Continue -> overworld, to reach code a plain boot
doesn't run.

Opens the ROM with Azahar.app (its window appears), quits it cleanly so the log is
flushed, then scans Azahar's log for a panic (svcBreak) or CPU exception.
Only one Azahar instance should run meanwhile: they share the log file.
"""
import os
import re
import shutil
import signal
import subprocess
import sys
import time

APP = "/Applications/Azahar.app"
LOG = os.path.expanduser("~/Library/Application Support/Azahar/log/azahar_log.txt")


def running(rom):
    out = subprocess.run(["pgrep", "-f", rom], capture_output=True, text=True).stdout
    return {int(x) for x in out.split()}


def main():
    rom = os.path.abspath(sys.argv[1])
    seconds = float(sys.argv[2]) if len(sys.argv) > 2 else 8
    movie = ["-p", os.path.abspath(sys.argv[3])] if len(sys.argv) > 3 else []
    before = running(rom)  # never touch an instance someone else is playing
    # launch through the app bundle: running the executable directly shows a modal
    # warning that can hold up emulation
    subprocess.run(["open", "-n", "-a", APP, "--args", *movie, rom], check=True)
    time.sleep(seconds)
    # read the log while the emulator still runs: Azahar writes it as it goes, but
    # a hung game won't quit on SIGTERM and killing it loses whatever is unflushed
    bad = []
    booted = False
    last = 0.0
    with open(LOG, errors="replace") as f:
        for line in f:
            booted = booted or "BootGame" in line
            m = re.match(r"\[\s*([0-9.]+)\]", line)
            if m:
                last = float(m.group(1))
            if re.search(r"broke execution|Exception Type|unmapped (Read|Write)", line):
                bad.append(line.strip())
                if len(bad) >= 4:
                    break
    for pid in running(rom) - before:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    name = os.path.basename(rom)
    if bad or not booted or last < 1.0:
        # keep the evidence: the next launch overwrites the log
        keep = os.path.join(os.path.dirname(rom), "boottest-logs")
        os.makedirs(keep, exist_ok=True)
        shutil.copy(LOG, os.path.join(keep, f"{name}.{time.strftime('%H%M%S')}.txt"))
    if not bad and (not booted or last < 1.0):
        # a good boot reaches the game's service setup at ~1.5s, then the log goes quiet
        print(f"{name}: HANG (log stops at {last:.1f}s)")
        return 3
    print(f"{name}: {'CRASH' if bad else 'ok'} after {seconds:.0f}s")
    for line in bad:
        print("   ", line[:200])
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
