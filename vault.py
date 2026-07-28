"""Compatibility wrapper. Prefer hermes_secret_core.VaultStore."""
from __future__ import annotations
import os, sys
from pathlib import Path
home = Path(os.environ.get("HERMES_HOME", str(Path.home()/".hermes"))).expanduser()
lib = Path(os.environ.get("HERMES_SECRET_CORE_PATH", str(home/"lib"))).expanduser()
if str(lib) not in sys.path: sys.path.insert(0, str(lib))
from hermes_secret_core.crypto import vault_wrap_v3 as wrap, vault_unwrap_v3 as unwrap
