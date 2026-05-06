"""Allow running the package as ``python -m collector_anonymizer``."""

import sys

from collector_anonymizer.cli import main

sys.exit(main())
