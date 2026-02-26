"""
pytest configuration for create-investigation Lambda unit tests.

With --import-mode=importlib (set in pytest.ini), pytest does not add the lambda
directory to sys.path automatically. We add it here at the END so that uv-installed
macOS-native packages (already at the front of sys.path from the virtual env) are
found before the bundled Linux x86_64 .so files in this directory.
"""

import os
import sys

_this_dir = os.path.dirname(os.path.abspath(__file__))
if _this_dir not in sys.path:
    sys.path.append(_this_dir)
