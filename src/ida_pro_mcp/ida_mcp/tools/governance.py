#!/usr/bin/env python3
"""
CyberCane Neuro-Symbolic Governance Layer — tool entrypoint.

This thin wrapper re-exports the governance tool from cybercane.py
so that the IDA runtime's load_tools() can discover it by the tool name.
"""

try:
    from .cybercane import governance
except ImportError:
    from cybercane import governance  # type: ignore[import-not-found]

__all__ = ["governance"]
