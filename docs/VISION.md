# Vision

## The problem

There are hundreds of agent harnesses (Claude Code, Codex, omp, opencode, aider...) and none of them know
what a CTF is. They don't know about point values, solve counts, categories, a board that drops 40
challenges at once, teammates, live instances, flag formats, or event rules. CTF players who try agents
either babysit one chat window or "point it at the board and let it rip", and most people don't know how
to work with agents well.

The skill that wins is **controlling agentic work**: seeing many agents at once, noticing when one is
going the wrong way, and stepping in at the right moment. Teams that actively steer agents beat teams
that run them hands-off.

## What ctf-flightdeck is

A terminal harness, CTF-specific, where **the player runs the loop and the harness does the work around
them**:

- **pull** the board, **triage** challenges (category, points, solves, what the description hints at),
- run the player's **L1 solvers** (no-model scripts) first,
- **assign** challenges and **spin up agent lanes**, many in parallel,
- **verify and submit** flags end-to-end,
- show everything on one console, with **alerts** when a lane looks wrong and **one-key interventions**
  (hint, redirect, fork, kill, escalate, take over).

Every stage can be switched to auto, confirm, manual or off, because event rules differ (no platform
API, no AI, no automation against live boxes...). A **pre-flight** check turns the rules into those
settings before anything runs.

## Modes

- **pre-flight**: load the event profile and rules, check config, keys, sandbox, scope. Refuse to start
  if the setup would break a rule.
- **in-flight**: the live console during the CTF.
- **post-flight**: timeline, what went well, where stepping in would have helped, which L1 solvers were
  missing, writeup drafts.
- **build**: turn post-flight gaps into new L1 solvers, with tests that prove a raw handout reaches them.
- **practice**: replay an archived board offline to learn agent control and to test a solver pack.

## Who it is for

First users: the author (10 years of CTFs, heavy Claude Code and Codex use) and players like them who
already use coding agents. Then anyone who wants to learn: bring whatever you have (an API key, an
OpenRouter account, a subscription CLI, a folder of Python scripts) and it should just work.

## What it is not

- Not a solver pack. It ships the solver contract and a few examples; players bring their own L1.
- Not a bot that plays without a human. Autonomy is a dial the player controls.
- Not a way around event rules.
