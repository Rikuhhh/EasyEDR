import os
import datetime
import json
from bcc import BPF
from config_loader import config
from rules import run_all_rules

OWN_PID = os.getpid()

Chook = open("hook.c", "r").read()

bcchook = BPF(text=Chook)
bcchook.attach_kprobe(event=bcchook.get_syscall_fnname("execve"), fn_name="hook_execve")

def should_ignore(log_entry):
    if config.get("filters", "ignore_own_pid", default=True):
        if log_entry["pid"] == OWN_PID:
            return True
    ignore_cmds = config.get("filters", "ignore_commands", default=[])
    if log_entry["cmd"] in ignore_cmds:
        return True
    return False

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
    if should_ignore(log_entry):
        return
    if config.get("logging", "console", default=True):
        print(log_entry)
    log_file_path = config.get("logging", "output_file", default="/var/log/easyedr/edr_events.jsonl")
    with open(log_file_path, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")
    for alert in run_all_rules(log_entry):
        print(alert)
bcchook["events"].open_perf_buffer(print_event)

def main():
    while True:
        try:
            bcchook.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

if __name__ == "__main__":
    main()