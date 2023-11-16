#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <uapi/linux/ptrace.h>
#define MAXARG 20
#define ARGSIZE 128

BPF_RINGBUF_OUTPUT(events, 16);

/*
 ========EXECVE ARGS=========
 field:unsigned short common_type;	offset:0;	size:2;	signed:0;
 field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
 field:unsigned char common_preempt_count;	offset:3;	size:1;
 signed:0; field:int common_pid;	offset:4;	size:4;	signed:1;

 field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 field:const char * filename;	offset:16;	size:8;	signed:0;
 field:const char *const * argv;	offset:24;	size:8;	signed:0;
 field:const char *const * envp;	offset:32;	size:8;	signed:0
*/

enum event_type { EVENT_ARG, EVENT_RET };

struct event_t {
  int pid;
  int uid;
  enum event_type type;
  char comm[TASK_COMM_LEN];
  char arg[ARGSIZE];
};

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {

  // Create our event struct to hold exec info
  struct event_t event = {};

  // Set event type
  // We will fire one of these off for each arg
  // Why? Because the args are long and the eBPF stack is only 512b
  event.type = EVENT_ARG;

  // Read the command fileneme into our struct
  bpf_probe_read_user_str(event.comm, sizeof(event.comm), args->filename);

  // Read the PID/UID in
  event.pid = bpf_get_current_pid_tgid() >> 32;
  event.uid = bpf_get_current_uid_gid();

  // Add trace printing for debug purposes
  bpf_trace_printk("%s", event.comm);
  bpf_trace_printk("%d", event.pid);
  bpf_trace_printk("%s", event.arg);

  // Now for the arg loop
  // eBPF doesn't do for loops, so this has to be a while
  // We start at 1 because we already have the filename
  int i = 1;
  while (i < MAXARG) {
    // Initialize the safe pointer for our string
    const char *arg = NULL;

    // Read from the context argv pointer
    bpf_probe_read(&arg, sizeof(arg), &args->argv[i]);
    // Attempt to writte to our event struct from the save pointer.
    // If it fails, we're done with the loop.
    int res = bpf_probe_read_user_str(event.arg, sizeof(event.arg), arg);
    if (res < 0) {
      break;
    }
    // Submit to the Ring Buffer
    events.ringbuf_output(&event, sizeof(event), 0);
    i++;
  }
  return 0;
}

int kretprobe__sys_execve(struct pt_regs *ctx) {
  struct event_t event = {};
  event.pid = bpf_get_current_pid_tgid() >> 32;
  event.uid = bpf_get_current_uid_gid();
  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  event.type = EVENT_RET;
  events.ringbuf_output(&event, sizeof(event), 0);

  return 0;
}
