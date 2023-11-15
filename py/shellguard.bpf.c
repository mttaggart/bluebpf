#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <uapi/linux/ptrace.h>
#define MAXARG 3
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

struct event_t {
  int pid;
  int uid;
  char comm[TASK_COMM_LEN];
  char arg[ARGSIZE];
};

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {

  struct event_t event = {};

  bpf_probe_read_user_str(event.comm, sizeof(event.comm), args->filename);

  event.pid = bpf_get_current_pid_tgid() >> 32;
  event.uid = bpf_get_current_uid_gid();

  bpf_trace_printk("%s", event.comm);
  bpf_trace_printk("%d", event.pid);
  // bpf_trace_printk("%s", event.argv[1]);
  int i = 1;
  while (i < 2) {
    const char *arg = NULL;
    bpf_probe_read(&arg, sizeof(arg), &args->argv[i]);
    int res = bpf_probe_read_user_str(event.arg, sizeof(event.arg), arg);
    if (res < 0) {
      break;
    }
    i++;
  }
  events.ringbuf_output(&event, sizeof(event), 0);
  return 0;
}
