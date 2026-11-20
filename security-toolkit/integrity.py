#!/usr/bin/env python3
"""Capture and compare SHA-256 manifests of regular files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


def entries(root):
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise NotADirectoryError(str(root))
    pending = [(root, metadata)]
    while pending:
        path, metadata = pending.pop()
        if stat.S_ISDIR(metadata.st_mode):
            pending.extend(
                (child, child.lstat()) for child in sorted(path.iterdir(), reverse=True)
            )
        if stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode):
            yield path, metadata


def snapshot(root):
    result = {}
    for path, metadata in entries(root):
        if stat.S_ISREG(metadata.st_mode):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                current = os.fstat(stream.fileno())
                if not stat.S_ISREG(current.st_mode):
                    raise OSError(f"File sostituito durante la scansione: {path}")
                result[path.relative_to(root).as_posix()] = hashlib.file_digest(
                    stream, "sha256"
                ).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["capture", "check"])
    parser.add_argument("root", type=Path)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        if args.manifest.resolve().is_relative_to(args.root.resolve()):
            raise ValueError("Salva il manifest fuori dalla directory controllata.")
        current = snapshot(args.root)
        if args.action == "capture":
            payload = json.dumps(current, indent=2, sort_keys=True) + "\n"
            with args.manifest.open("x", encoding="utf-8") as stream:
                stream.write(payload)
            return 0
        baseline = json.loads(args.manifest.read_text(encoding="utf-8"))
        if not isinstance(baseline, dict) or any(
            not isinstance(value, str)
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
            for value in baseline.values()
        ):
            raise ValueError("Manifest non valido.")
        changed = False
        for name in sorted(baseline.keys() | current.keys()):
            if baseline.get(name) != current.get(name):
                status = "aggiunto" if name not in baseline else (
                    "rimosso" if name not in current else "modificato"
                )
                print(f"{status}: {name!r}")
                changed = True
        return int(changed)
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
