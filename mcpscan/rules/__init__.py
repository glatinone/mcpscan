"""Rule package. Importing it registers every built-in rule."""

from .base import REGISTRY, Rule, register  # noqa: F401

from . import command_injection  # noqa: F401,E402


def all_rules():
    return list(REGISTRY)
