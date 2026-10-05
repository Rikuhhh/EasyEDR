import time
from collections import defaultdict, deque
from config_loader import config

_execve_history = defaultdict(deque)
_pid_to_cmd = {}

def check_fork_bomb(event):
    cfg = config.get("rules", "fork_bomb", default={})
    if not cfg.get("enabled"):
        return None

    cmd = event.get("cmd", "")
    whitelist = cfg.get("whitelist_commands", [])
    if cmd in whitelist:
        return None

    threshold = cfg.get("threshold", 15)
    window = cfg.get("window_seconds", 2)
    group_key = event.get(cfg.get("group_by", "ppid"))

    now = time.time()
    history = _execve_history[group_key]
    history.append(now)

    while history and now - history[0] > window:
        history.popleft()

    _pid_to_cmd[event.get("pid")] = cmd
    parent_cmd = _pid_to_cmd.get(group_key)
    self_replicating = parent_cmd is not None and parent_cmd == cmd

    if len(history) >= threshold and self_replicating:
        return f"Warning: FORK BOMB: ppid={group_key} a lancé {len(history)} execve en {window}s"
    return None

def check_exec_from_tmp(event):
    cfg = config.get("rules", "exec_from_tmp", default={})
    if not cfg.get("enabled"):
        return None

    paths = cfg.get("paths", [])
    filename = event.get("filename", "")
    if any(filename.startswith(p) for p in paths):
        return f"Warning: Suspect execution pattern: {filename} (pid={event.get('pid')})"
    return None


def run_all_rules(event):
    alerts = []
    for check in [check_fork_bomb, check_exec_from_tmp]:
        result = check(event)
        if result:
            alerts.append(result)
    return alerts