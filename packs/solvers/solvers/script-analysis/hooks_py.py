"""Hook file for .py specimens (Day 5, script-analysis-day-05-python-carrier-lab): SWITCHED OFF.

Loaded by name from plan_codec.hooks('py'). It holds no crib and no label pattern on purpose.
Read this before adding one.

Since the tag made after Day 5 it needs none: plan_codec's own cribs read `v=1|steps=` to
`v=9|steps=`, it reads these materials whole (adjacent literals, \\x escapes, url-safe base64),
and plan_codec.reading drops the last field of a plan it read from a piece of the material.
What follows is the history of the morning of 2026-10-05, kept as the worked example of what a
crib can cost.

What it was. The Python specimens carry a version-2 plan,

    v=2|steps=...|adapter=...|stage_count=...|syntax=...|obfuscation=...|carrier=...|windows_chain=...|campaign_id=...|<indicators>

and plan_codec's built-in cribs knew only `v=1|steps=` that morning. From about 09:02 to 09:16 Eastern on
2026-10-05 this file held EXTRA_CRIBS = [b"v=2|steps="]. With it plan_codec read 9 of the 14 base
specimens and tools/verify.py banked 21 answers at 09:03 (and the judge accepted T1059.006 for
script.attack/py).

Why it is off. shapes_py.py (written the same morning) reads the plan of every .py specimen by
itself, with its own cribs, and answers all nine fields; it closed the base and both timed modes.
generic.py asks shapes_py.py only what the plan path left open, so a plan that plan_codec reads
wins over shapes_py.py's. And plan_codec tries every PIECE of a literal alone: each chunk of
adjacent string literals, and each run of a url-safe base64 text up to its first `_`. With the
v=2 crib such a piece passes the plan grammar as a shorter plan (the `k=v|` grammar has no end
mark) whose last value is cut. Today's timed variants showed three such cut plans (time trial:
wheel and py2exe-console; mastery: one embedded-runtime); none reached the indicator asked, so
nothing was wrong. Measured offline on the 14 saved time-trial specimens, each stored again as
url-safe base64 under every single-byte key and three transforms (scratch_simple_3.py, never
committed): in 79 of 10,710 cases the lane solver answered the indicator with a cut value
(`C:/ProgramData/HuntressLab/.update-3aa9` for `...update-3aa9819b19.py`), a wrong plain answer
that costs a whole timed batch. With the crib hidden: 0 of those 79. With the crib removed,
tools/preflight.py --replay still gives the key on all three saved attempts of 2026-10-05
(base 357 of 357, time trial 357 of 357, mastery 714 of 714).

So: a crib here was not free that morning, when plan_codec had no guard against a cut plan. It
has one now, and the version cribs are built in, so this file has nothing left to add. A hook
for a later language should still be checked the same way: replay every saved variant with it
and look for a triage line that says the last field of a plan was left out.
"""

EXTRA_CRIBS = []
