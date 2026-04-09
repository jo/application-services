#!/usr/bin/env python3
"""Convert STMO pwmgr_origin_failure CSV export to nd-json for validate_logins.

The event_extra column uses BigQuery's ARRAY<STRUCT<key,value>> CSV format:
  [{'f': [{'v': 'key'}, {'v': 'value'}]}, ...]

Usage:
  python3 tools/stmo_to_ndjson.py src/bin/<file>.csv \
    | NSS_DIR=... cargo run --bin validate_logins
"""

import ast
import csv
import json
import sys


def parse_event_extra(raw: str) -> dict:
    """Parse BigQuery STRUCT serialization into a plain dict."""
    structs = ast.literal_eval(raw)
    result = {}
    for struct in structs:
        fields = struct["f"]
        key = fields[0]["v"]
        value = fields[1]["v"]
        result[key] = value
    return result


def extra_to_login_entry(extra: dict) -> dict:
    """Build a LoginEntry dict from the event_extra fields.

    We only have origin and form_action_origin from the telemetry.
    password is filled with a dummy value to satisfy the non-empty requirement —
    we're only interested in origin/form_action_origin validation behaviour.
    """
    entry = {
        "origin": extra.get("origin", ""),
        "password": "x",  # dummy — validation only cares about origin fields here
        "username": "",
        "username_field": "",
        "password_field": "",
    }

    # form_action_origin is present as a key (even if empty string) → form-based login
    if "form_action_origin" in extra:
        entry["form_action_origin"] = extra["form_action_origin"]
    else:
        # http_realm entries don't have form_action_origin in the event at all
        entry["http_realm"] = extra.get("http_realm", "")

    return entry


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else None
    f = open(path, newline="") if path else sys.stdin

    reader = csv.DictReader(f)
    for row in reader:
        raw_extra = row.get("event_extra", "").strip()
        if not raw_extra:
            continue
        try:
            extra = parse_event_extra(raw_extra)
        except Exception as e:
            print(f"# parse error: {e} — raw: {raw_extra[:80]}", file=sys.stderr)
            continue

        entry = extra_to_login_entry(extra)
        # Emit the error_message as a comment line for reference
        if error := extra.get("error_message"):
            print(f"# error_message: {error}", file=sys.stderr)
        print(json.dumps(entry))

    if path:
        f.close()


if __name__ == "__main__":
    main()
