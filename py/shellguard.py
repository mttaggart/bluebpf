from bcc import BPF
import sys
import time
import ctypes as ct

ARGSIZE = 128
MAXARG = 3
TASK_COMM_LEN = 16


class EventArg(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("uid", ct.c_uint),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("argv", ct.c_char * ARGSIZE),
    ]

class EventType:
    EVENT_ARG = 0
    EVENT_RET = 1


shells = ["bash", "fish", "zsh", "sh", "dash"]
shells = ["bash", "fish", "zsh", "sh", "dash"]
shells = ["bash", "fish", "zsh", "sh", "dash"]
shells = ["bash", "fish", "zsh", "sh", "dash"]

with open("./shellguard.bpf.c") as f:
    prog_text = f.read()

# Define BPF Program
b = BPF(text=prog_text)


def callback(ctx, data, size):
    event = b["events"].event(data)
    comm = event.comm.decode()
    arg = event.arg.decode()
    if comm.split("/")[-1] in shells:
        print(f"New Shell Exec: {event.pid} [{event.uid}] {comm} {arg}")


b["events"].open_ring_buffer(callback)

print("Printing execs() calls, ctrl-c to exit.")


try:
    while 1:
        b.ring_buffer_consume()
        time.sleep(0.5)
        # b.trace_print()
except KeyboardInterrupt:
    sys.exit()
