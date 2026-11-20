#!/usr/bin/env python3
"""Controlla gli header di una risposta HTTPS salvata in un file."""
import argparse
from pathlib import Path
import re
import sys


STATUS_LINE = re.compile(r"HTTP/[0-9]+(?:\.[0-9]+)?\s+([1-5][0-9]{2})(?:\s.*)?")
HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def parse_headers(raw):
    responses = re.split(r"\n[ \t]*\n", raw.strip())
    headers = {}
    status = 0
    for response in responses:
        first, *lines = response.splitlines()
        match = STATUS_LINE.fullmatch(first)
        if not match:
            raise ValueError("Riga di stato HTTP mancante o non valida.")
        status = int(match[1])
        headers = {}
        for line in lines:
            name, separator, value = line.partition(":")
            if not separator or not HEADER_NAME.fullmatch(name):
                raise ValueError("Riga header non valida. Esporta solo gli header.")
            headers.setdefault(name.lower(), []).append(value.strip())
    if not 200 <= status < 300:
        raise ValueError("Il controllo richiede una risposta finale HTTPS 2xx.")
    return headers


def findings(headers):
    hsts = headers.get("strict-transport-security", [])
    directives = hsts[0].split(";") if hsts else []
    max_age = [
        value.strip()
        for directive in directives
        for name, separator, value in [directive.partition("=")]
        if name.strip().lower() == "max-age" and separator
    ]
    if (
        len(hsts) != 1
        or len(max_age) != 1
        or not re.fullmatch(r"[0-9]+", max_age[0])
        or not max_age[0].strip("0")
    ):
        yield "HSTS: serve un solo header con max-age positivo."
    csp = headers.get("content-security-policy", [])
    if not any(value.strip() for value in csp):
        yield "CSP: manca una policy applicata alla risposta."
    nosniff = headers.get("x-content-type-options", [])
    if [value.lower() for value in nosniff] != ["nosniff"]:
        yield "X-Content-Type-Options: atteso il valore nosniff."


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="File con gli header HTTP")
    args = parser.parse_args()
    try:
        issues = list(findings(parse_headers(args.file.read_text(encoding="latin-1"))))
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 2
    for issue in issues:
        print(issue)
    if not issues:
        print("Controlli di base superati.")
    return int(bool(issues))


if __name__ == "__main__":
    sys.exit(main())
