"""Rule package. Importing it registers every built-in rule."""

from .base import REGISTRY, Rule, register  # noqa: F401


def all_rules():
    return list(REGISTRY)
