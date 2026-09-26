#!/usr/bin/env python3
"""Minimal GDB remote-protocol client for Azahar's GDB stub (debugging aid).

  gdbrsp.py regs                 print r0-r15 and cpsr
  gdbrsp.py mem ADDR LEN         hex dump memory
  gdbrsp.py break ADDR           set a breakpoint, continue, print registers when hit
"""
import socket
import struct
import sys


class Stub:
    def __init__(self, host="127.0.0.1", port=24689, timeout=30):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.buf = b""

    def _read_packet(self):
        while True:
            while b"$" not in self.buf or b"#" not in self.buf[self.buf.index(b"$"):]:
                chunk = self.s.recv(65536)
                if not chunk:
                    raise EOFError("stub closed the connection")
                self.buf += chunk
            start = self.buf.index(b"$")
            end = self.buf.index(b"#", start)
            if len(self.buf) < end + 3:
                self.buf += self.s.recv(65536)
                continue
            body = self.buf[start + 1 : end]
            self.buf = self.buf[end + 3 :]
            self.s.sendall(b"+")
            return body.decode("latin-1")

    def cmd(self, body, reply=True):
        pkt = f"${body}#{sum(body.encode()) & 0xFF:02x}".encode()
        self.s.sendall(pkt)
        return self._read_packet() if reply else None

    def regs(self):
        raw = bytes.fromhex(self.cmd("g"))
        vals = struct.unpack_from("<16I", raw)
        return {f"r{i}": v for i, v in enumerate(vals)}

    def mem(self, addr, n):
        return bytes.fromhex(self.cmd(f"m{addr:x},{n:x}"))

    def brk(self, addr):
        return self.cmd(f"Z0,{addr:x},4")

    def cont(self):
        return self.cmd("c")


def show(regs):
    names = [f"r{i}" for i in range(13)] + ["sp", "lr", "pc"]
    print("  " + "  ".join(f"{n}={regs[f'r{i}']:08x}" for i, n in enumerate(names)))


if __name__ == "__main__":
    st = Stub()
    print("status:", st.cmd("?"))
    if sys.argv[1] == "regs":
        show(st.regs())
    elif sys.argv[1] == "mem":
        a, n = int(sys.argv[2], 0), int(sys.argv[3], 0)
        d = st.mem(a, n)
        for i in range(0, len(d), 16):
            print(f"  {a + i:08x}: {d[i:i + 16].hex(' ')}")
    elif sys.argv[1] == "break":
        a = int(sys.argv[2], 0)
        print("break:", st.brk(a))
        print("stop:", st.cont())
        show(st.regs())
