import time
from collections import defaultdict, deque
from config_loader import config

_fork_history = defaultdict(deque)
_execve_history = defaultdict(deque)
_pid_to_cmd = {}

def check_fork_bomb(fork_event):
    cfg = config.get("rules", "fork_bomb", default={})
    if not cfg.get("enabled"):
        return None

    parent_comm = fork_event.get("parent_comm", "")
    whitelist = cfg.get("whitelist_commands", [])
    if parent_comm in whitelist:
        return None

    threshold = cfg.get("threshold", 15)
    window = cfg.get("window_seconds", 2)
    group_key = fork_event.get("parent_pid")

    now = time.time()
    history = _fork_history[group_key]
    history.append(now)

    while history and now - history[0] > window:
        history.popleft()

    if len(history) >= threshold:
        return f"Warning: FORK BOMB: parent_pid={group_key} ({parent_comm}) created {len(history)} processus in {window}s"
    return None


def check_exec_from_tmp(execve_event):
    cfg = config.get("rules", "exec_from_tmp", default={})
    if not cfg.get("enabled"):
        return None

    paths = cfg.get("paths", [])
    filename = execve_event.get("filename", "")
    if any(filename.startswith(p) for p in paths):
        return f"Warning: Suspect execution pattern: {filename} (pid={execve_event.get('pid')})"
    return None


def run_execve_rules(event):
    alerts = []
    for check in [check_exec_from_tmp]:
        result = check(event)
        if result:
            alerts.append(result)
    return alerts


def run_fork_rules(event):
    alerts = []
    for check in [check_fork_bomb]:
        result = check(event)
        if result:
            alerts.append(result)
    return alerts