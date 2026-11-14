"""The Day 27 split look-ahead's synthetic packages now live in ctf/openers/mobile_splits_synth.py (B-229 fix round 1:
the mobile Layer-1 opener builds the Day 26 bundle from them, and ctf/ cannot import tests/). This name stays an alias
of that module, the same module object, so `import day27_mobile_splits_synth` keeps working unchanged."""
import sys

from ctf.openers import mobile_splits_synth as _synth

sys.modules[__name__] = _synth
