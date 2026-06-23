import contextlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)



@contextlib.contextmanager
def _patched_attr(obj, attr, value):
    """Swap obj.attr with value for the block; restore on exit.

    Audit §7.5: replaces the bare `server._execute_tool = _fake_execute`
    pattern that left the test's replacement installed with no teardown.
    """
    sentinel = object()
    had_attr = hasattr(obj, attr)
    original = getattr(obj, attr, sentinel)
    setattr(obj, attr, value)
    try:
        yield
    finally:
        if had_attr:
            setattr(obj, attr, original)
        else:
            try:
                delattr(obj, attr)
            except AttributeError:
                pass


@contextlib.contextmanager
def _patched_attrs(obj, **replacements):
    """Stack several _patched_attr contexts in one with block (audit §7.5)."""
    originals = {}
    for attr, value in replacements.items():
        originals[attr] = (hasattr(obj, attr), getattr(obj, attr, None))
        setattr(obj, attr, value)
    try:
        yield
    finally:
        for attr, (had_attr, original) in originals.items():
            if had_attr:
                setattr(obj, attr, original)
            else:
                try:
                    delattr(obj, attr)
                except AttributeError:
                    pass

