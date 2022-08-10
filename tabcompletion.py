"""
Module to optionally enable tab completion, if `argcomplete` is installed.
"""

READY = False

try:
    import argcomplete
    READY = True
except ImportError:
    pass


def register(parser):
    if READY:
        argcomplete.autocomplete(parser)
