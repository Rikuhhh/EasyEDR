import os
import datetime
import json
import socket
import struct
from bcc import BPF
from config_loader import config
from rules import run_connect_rules, run_execve_rules, run_fork_rules

OWN_PID = os.getpid()

Chook = open("hook.c", "r").read()

bcchook = BPF(text=Chook)

def should_ignore(log_entry):
    if config.get("filters", "ignore_own_pid", default=True):
        if log_entry["pid"] == OWN_PID:
            return True
    ignore_cmds = config.get("filters", "ignore_commands", default=[])
    if log_entry["cmd"] in ignore_cmds:
        return True
    return False

def write_log(entry):
    if config.get("logging", "console", default=True):
        print(entry)
    log_file_path = config.get("logging", "output_file", default="/var/log/easyedr/edr_events.jsonl")
    with open(log_file_path, "a") as log_file:
        log_file.write(json.dumps(entry) + "\n")

def write_alerts(alerts):
    for alert in alerts:
        write_log({"type": "warning", "message": alert})

def print_execve_event(cpu, data, size):
    event = bcchook["events"].event(data)
    log_entry = {
        "type": "execve",
        "pid": event.pid,
        "ppid": event.ppid,
        "uid": event.uid,
        "gid": event.gid,
        "cmd": event.cmd.decode("utf-8", "replace"),
        "filename": event.filename.decode("utf-8", "replace"),
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    if should_ignore(log_entry):
        return
    write_log(log_entry)
    write_alerts(run_execve_rules(log_entry))

def print_fork_event(cpu, data, size):
    event = bcchook["fork_events"].event(data)
    log_entry = {
        "type": "fork",
        "parent_pid": event.parent_pid,
        "child_pid": event.child_pid,
        "parent_comm": event.parent_comm.decode("utf-8", "replace"),
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    ignore_cmds = config.get("filters", "ignore_commands", default=[])
    if log_entry["parent_comm"] in ignore_cmds:
        return
    write_log(log_entry)
    write_alerts(run_fork_rules(log_entry))

def print_connect_event(cpu, data, size):
    event = bcchook["connect_events"].event(data)
    log_entry = {
        "type": "connect",
        "pid": event.pid,
        "uid": event.uid,
        "command": event.comm.decode("utf-8", "replace"),
        "destination": socket.inet_ntoa(struct.pack("!I", event.daddr)),
        "port": event.dport,
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    if config.get("hooks", "connect", "enabled", default=True):
        write_log(log_entry)
        write_alerts(run_connect_rules(log_entry))


bcchook["events"].open_perf_buffer(print_execve_event)
bcchook["fork_events"].open_perf_buffer(print_fork_event)
bcchook["connect_events"].open_perf_buffer(print_connect_event)

def main():
    while True:
        try:
            bcchook.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

if __name__ == "__main__":
    main()