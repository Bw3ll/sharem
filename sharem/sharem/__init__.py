from .sharem import *
from .sharem_main import *

from importlib import import_module

_cachedSharemMain = None

def _loadSharemMain():
	"""
	Locate the real SharemMain implementation by trying a few layouts.
	Adjust the candidate list if you ever move files around.
	"""
	candidates = (
		"sharem_main",        # Sharem/sharem_main.py
		"sharem.sharem_main",  # Sharem/Sharem/sharem_main.py,
		"sharem.sharem.sharem_main",  # Sharem/Sharem/sharem_main.py


	)

	lastErr = None

	for relName in candidates:
		try:
			mod = import_module("." + relName, __name__)
		except ImportError as e:
			lastErr = e
			continue

		try:
			return getattr(mod, "SharemMain")
		except AttributeError as e:
			lastErr = e
			continue

	raise ImportError(
		f"Cannot locate SharemMain in any of {candidates}; last error was: {lastErr}"
	)

def SharemMain(*args, **kwargs):
	
	global _cachedSharemMain
	if _cachedSharemMain is None:
		_cachedSharemMain = _loadSharemMain()
	return _cachedSharemMain(*args, **kwargs)

__all__ = ["SharemMain"]