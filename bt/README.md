# BPFTrace Tools

The scripts in this folder require `bpftrace` to run. They are sort of "training wheels" scripts using the awk-like bpftrace script. They may have limited functionality to their Python/Rust counterparts, and there are some things you just can't do from bpftrace. Nevertheless, it's a fantastic introduction to the technology, and even with this limited set of features, you can pull off some nifty tricks.

## `keylogger.bt`

This script logs physical keyboard inputs on a device. It doesn't do you any favors for output formatting—for example, a capital "A" would be logged as `LEFTSHIFT\n\A`, whereas a lowercase "a" would be `A`. It accounts for the 248 base keyboard event codes, but that's it. No weirdo device codes or outlandish feature buttons.

### Usage

```bash
sudo ./keylogger.bt
```

## `portmon.bt`

This light modification of `tcpconnect.bt` from the BPFtrace examples focuses on alerting on new connections by command, pid and destination port. Useful for network monitoring and collecting all connections in a more meaningful way than perhaps netstat.

### Usage

```
sudo ./portmon.bt
```
## `shellguardian.bt`

Definitely my favorite one. This gem watches for all shell executions and alerts on any non-standard user (like, say `www-data`) starting a shell. It can also be launched in **KILL MODE**, which sends `SIGKILL` to that process and prevents the shell from being useful at all. This tool is great for use in attack-defense CTFs or for active threat hunting. It makes the endpoint actively hostile to attackers.

### Usage

```bash
sudo ./shellguardiant.bt --unsafe -k # -k for KILL MODE
```

## `sshspy.bt`

Hooks `read()` on `sshd` to capture user input from SSH sessions. It's messy due to the nature of SSH communication, but the text is there. You may want to experiment with `strace` to see what file descriptor `sshd` is using for reads. In my testing, FD 10 was pretty consistent, but your mileage may vary. Luckily, this tool will print out the total reads from each file descriptor it sees, so if you appear to be missing the user input, check to see the noisiest FD.

### Usage

```bash
sudo ./sshspy.bt
```
