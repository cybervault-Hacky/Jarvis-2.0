"""Phase 1 test package.

Makes the repository root importable no matter how the suite is started
(``python -m unittest discover -s tests`` or ``python -m pytest tests``).
"""

import logging
import pathlib
import sys

# The framework logs every lifecycle event at INFO. Tests assert on the records
# themselves (see tests/support.AuditCapture), so keep the console readable.
logging.getLogger("jarvis.device.audit").setLevel(logging.CRITICAL)

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
