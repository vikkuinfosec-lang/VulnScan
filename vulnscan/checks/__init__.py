"""Importing this package registers every check module with the scanner.

Each submodule calls scanner.register_check(...) at import time as its last
statement, so simply importing vulnscan.checks (done once, in cli.py, before
run_scan is called) wires up the whole pipeline.
"""

from vulnscan.checks import headers  # noqa: F401
from vulnscan.checks import tls  # noqa: F401
from vulnscan.checks import ports  # noqa: F401
from vulnscan.checks import misconfig  # noqa: F401
