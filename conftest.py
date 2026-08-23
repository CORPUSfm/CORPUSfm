"""Make the explicitly resolved application checkout importable for integration guards."""

from __future__ import annotations

import sys
from pathlib import Path

from application_checkout import APPLICATION_ROOT


if str(APPLICATION_ROOT) not in sys.path:
    sys.path.insert(0, str(APPLICATION_ROOT))

# Cross-repository behavioral controls import the application without loading its own tests/
# conftest.py. Select the same explicit in-process development seam those tests use; otherwise a
# storage or crypto call tries to resolve an installed-machine locator on the developer host.
from corpusfm.lifecycle import app_paths

app_paths.use_development_layout(lambda: Path.home() / ".corpusfm")
