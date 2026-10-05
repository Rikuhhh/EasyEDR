import yaml
import os

class Config:
    def __init__(self, path="config.yaml"):
        with open(path, "r") as f:
            self._raw = yaml.safe_load(f)

    def get(self, *keys, default=None):
        node = self._raw
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

config = Config(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml"))