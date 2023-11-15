from bcc import BPF
import sys
import time

shells = ["bash", "fish", "zsh", "sh", "dash"]
with open("./shellguard.bpf.c") as f:
    prog_text = f.read()

# Define BPF Program
b = BPF(text=prog_text)


def callback(ctx, data, size):
    event = b["events"].event(data)
    comm = event.comm.decode()
    argv = event.argv.decode()
    if comm.split("/")[-1] in shells:
        print(f"New Shell Exec: {event.pid} [{event.uid}] {comm} {argv}")


b["events"].open_ring_buffer(callback)

print("Printing execs() calls, ctrl-c to exit.")


try:
    while 1:
        b.ring_buffer_consume()
        time.sleep(0.5)
        b.trace_print()
except KeyboardInterrupt:
    sys.exit()
