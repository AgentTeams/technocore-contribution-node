"""Network adapters. Technocore today; a FLOP testnet lane the day one is specified."""

from .base import NetworkAdapter, NotImplementedYet
from .flop import FlopTestnetAdapter
from .technocore import TechnocoreAdapter

__all__ = ["FlopTestnetAdapter", "NetworkAdapter", "NotImplementedYet", "TechnocoreAdapter"]
