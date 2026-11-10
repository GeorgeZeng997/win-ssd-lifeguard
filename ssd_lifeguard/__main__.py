"""Package entry point enabling `python -m ssd_lifeguard`."""

import sys
from ssd_lifeguard.cli import main

if __name__ == "__main__":
    sys.exit(main())
