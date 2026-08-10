#!/usr/bin/env python3
"""Entry point — delegates to race_finder.cli."""

import sys
from race_finder.cli import main

if __name__ == '__main__':
    sys.exit(main())
