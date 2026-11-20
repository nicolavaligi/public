#!/usr/bin/env python3
"""Report files and directories writable by any local user."""
import argparse
from pathlib import Path
import stat
import sys

from integrity import entries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    found = False
    try:
        for path, metadata in entries(args.root):
            mode = metadata.st_mode
            if mode & stat.S_IWOTH:
                print(f"{stat.S_IMODE(mode):04o} {str(path)!r}")
                found = True
    except OSError as error:
        print(error, file=sys.stderr)
        return 2
    return int(found)


if __name__ == "__main__":
    sys.exit(main())
