#!/usr/bin/env python3
"""Run a command using an AIRS CLI tenant credential file, without logging secrets.

Usage: python3 scripts/with_tenant.py /path/to/tenant.json -- go test ...
The file remains external; credentials are passed only in the child environment.
"""
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        raise SystemExit(__doc__)
    config = json.loads(Path(sys.argv[1]).read_text())
    env = os.environ.copy()
    for source, destination in [("mgmtClientId", "PANW_MGMT_CLIENT_ID"),
                                ("mgmtClientSecret", "PANW_MGMT_CLIENT_SECRET"),
                                ("mgmtTsgId", "PANW_MGMT_TSG_ID")]:
        if not config.get(source):
            raise SystemExit("Missing tenant configuration field: " + source)
        env[destination] = str(config[source])
    raise SystemExit(subprocess.call(sys.argv[3:], env=env))


if __name__ == "__main__":
    main()
