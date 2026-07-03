"""Rule package. Importing it registers every built-in rule."""

from .base import REGISTRY, Rule, register  # noqa: F401

from . import command_injection  # noqa: F401,E402
from . import tool_poisoning     # noqa: F401,E402
from . import hooks              # noqa: F401,E402
from . import permissions        # noqa: F401,E402
from . import secrets            # noqa: F401,E402
from . import sdk_versions       # noqa: F401,E402
from . import path_traversal     # noqa: F401,E402
from . import ssrf               # noqa: F401,E402
from . import insecure_deser     # noqa: F401,E402
from . import insecure_transport # noqa: F401,E402
from . import webfetch_domain    # noqa: F401,E402


def all_rules():
    return list(REGISTRY)
