import os
import datetime
from bcc import BPF
import json

Chook = open("hook.c", "r").read()

bcchook = BPF(text=Chook)
bcchook.attach_kprobe(event=bcchook.get_syscall_fnname("execve"), fn_name="hook_execve")

def print_event(cpu, data, size):
    event = bcchook["events"].event(data)
    log_entry = {
        "pid": event.pid,
        "ppid": event.ppid,
        "uid": event.uid,
        "gid": event.gid,
        "cmd": event.cmd.decode('utf-8'),
        "time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    log_file_path = "execve_log.json"
    with open(log_file_path, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")
    print(log_entry)
bcchook["events"].open_perf_buffer(print_event)

def main():
    while True:
        try:
            bcchook.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()



if __name__ == "__main__":
    main()