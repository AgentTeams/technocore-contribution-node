"""The read-only public HTTP surface."""

from .app import create_app

__all__ = ["create_app"]
