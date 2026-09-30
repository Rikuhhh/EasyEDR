import os
import datetime
from bcc import BPF

Chook = open("hook.c", "r").read()

bcchook = BPF(text=Chook)
bcchook.attach_kprobe(event=bcchook.get_syscall_fnname("execve"), fn_name="hook_execve")

def print_event(cpu, data, size):
    event = bcchook["events"].event(data)
    print(f"PID: {event.pid}, PPID: {event.ppid}, UID: {event.uid}, GID: {event.gid}, CMD: {event.cmd.decode('utf-8')}, TIME: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

bcchook["events"].open_perf_buffer(print_event)

def main():
    while True:
        try:
            bcchook.perf_buffer_poll(print_event)
        except KeyboardInterrupt:
            exit()



if __name__ == "__main__":
    main()