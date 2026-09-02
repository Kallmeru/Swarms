"""python -m swarms is the same as the swarms console script."""
import sys

from swarms.cli import main

if __name__ == "__main__":
    sys.exit(main())
