from bcc import BPF
import sys
import time
import ctypes as ct
from collections import defaultdict
from psutil import Process

ARGSIZE = 128
MAXARG = 3
TASK_COMM_LEN = 16


class Event(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("uid", ct.c_uint),
        ("type", ct.c_int),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("arg", ct.c_char * ARGSIZE),
    ]

class EventType:
    EVENT_ARG = 0
    EVENT_RET = 1

execs = defaultdict(list)

shells = ["bash", "fish", "zsh", "sh", "dash"]

with open("./shellguard.bpf.c") as f:
    prog_text = f.read()

# Define BPF Program
b = BPF(text=prog_text)


def callback(ctx, data, size):

    event = ct.cast(data, ct.POINTER(Event)).contents
    comm = event.comm.decode()
    pid = event.pid
    uid = event.uid
    if event.type == EventType.EVENT_ARG:
        execs[event.pid].append(event.arg.decode())
    elif event.type == EventType.EVENT_RET:
        argv = " ".join(execs[pid])
        if comm.split("/")[-1] in shells:
            if uid > 0 and uid < 1000:
                msg = "UNAUTHORIZED SHELL DETECTED: "
                if "-k" in sys.argv:
                    proc = Process(pid)
                    print(f"KILL MODE ACTIVATED ON {pid}")
                    proc.kill()
            else:
                msg = "New Shell Executed: "
            print(f"{msg} {pid} [{uid}] {comm} {argv}")
            
            del execs[pid]

b["events"].open_ring_buffer(callback)

print("Printing execs() calls, ctrl-c to exit.")


try:
    while 1:
        # b.kprobe_poll()
        b.ring_buffer_poll()
        # b.trace_print()
        time.sleep(0.5)
except KeyboardInterrupt:
    sys.exit()
