#!/usr/bin/env python3
"""
Merge one or more new_postconditions.json files into the seed file
bounds_checker/data/validator_postconditions.json.

Usage:
    merge_postconditions.py  new_postconditions.json [...]

Each input file must have the structure { "entries": { ... } }.
Existing entries are updated (checksum, postcondition, etc. replaced);
new entries are appended.  The seed file is updated in-place.
"""

import json
import sys
from pathlib import Path

_SEED = Path(__file__).parent.parent / 'bounds_checker' / 'data' / 'validator_postconditions.json'


def load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except Exception as e:
        print(f"error: cannot read {path}: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print(f"usage: {Path(sys.argv[0]).name} new_postconditions.json [...]", file=sys.stderr)
        sys.exit(1)

    seed_data = load_json(_SEED)
    seed_entries = seed_data.get('entries', {})

    added = []
    updated = []

    for src_path in sys.argv[1:]:
        incoming = load_json(src_path).get('entries', {})
        if not incoming:
            print(f"  {src_path}: no entries found, skipping")
            continue

        for fn_name, entry in incoming.items():
            if fn_name in seed_entries:
                seed_entries[fn_name] = entry
                updated.append(fn_name)
            else:
                seed_entries[fn_name] = entry
                added.append(fn_name)

        print(f"  {src_path}: {len(incoming)} entry/entries processed")

    seed_data['entries'] = seed_entries
    _SEED.write_text(json.dumps(seed_data, indent=2) + '\n')

    if added:
        print(f"\nAdded ({len(added)}):")
        for n in added:
            print(f"  {n}")
    if updated:
        print(f"\nUpdated ({len(updated)}):")
        for n in updated:
            print(f"  {n}")
    if not added and not updated:
        print("\nNo changes.")

    print(f"\nSeed file: {_SEED}")


if __name__ == '__main__':
    main()
