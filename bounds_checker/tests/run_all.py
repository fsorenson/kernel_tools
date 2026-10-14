#!/usr/bin/env python3
"""
Run all bounds-checker tests that do not require LLM API calls.

  python3 bounds_checker/tests/run_all.py [--stage1] [--stage17] [--verbose]

Default: run both stages.  Stage 2 (LLM) requires --llm and is not run here.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def main():
    p = argparse.ArgumentParser(description='Run bounds-checker regression tests')
    p.add_argument('--stage1',   action='store_true', help='Stage 1 scanner only')
    p.add_argument('--stage17',  action='store_true', help='Stage 1.7 SMT only')
    p.add_argument('--verbose',  action='store_true')
    args = p.parse_args()

    run_s1  = args.stage1  or not (args.stage1 or args.stage17)
    run_s17 = args.stage17 or not (args.stage1 or args.stage17)

    rc = 0

    if run_s1:
        print("=" * 60)
        print("Stage 1 scanner tests")
        print("=" * 60)
        from bounds_checker.tests import run_stage1
        rc |= run_stage1.run()

    if run_s17:
        print()
        print("=" * 60)
        print("Stage 1.7 SMT tests")
        print("=" * 60)
        from bounds_checker.tests import run_stage17
        rc |= run_stage17.run()

    return rc


if __name__ == '__main__':
    sys.exit(main())
