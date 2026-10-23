"""
Standalone PyInstaller & CLI/GUI entry point for win-ssd-lifeguard.
Launches the Desktop GUI when invoked with no arguments, or dispatches to CLI when arguments are supplied.
"""

import sys
from ssd_lifeguard.cli import main

if __name__ == "__main__":
    sys.exit(main())
