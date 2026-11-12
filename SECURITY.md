# Security

A lane reads hostile input. A challenge's description, its handout files and its instance's
replies may be written to mislead an agent, and a lane reads all of it, runs commands on it and
can submit flags. What keeps that text from steering flightdeck is the harness, not the prompt
([docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) says how). A way around the harness is a security
problem: report it privately, never in a public issue.

## What counts

- **Challenge or platform text that steers flightdeck.** Text from a challenge, a platform (CTFd's
  challenge data and its answers) or a teammate's synced folder that changes a setting, reaches a
  system prompt, reaches the model as anything but fenced data, is read by a coding-agent CLI as
  its own configuration, or reaches your terminal as an escape sequence.
- **A lane out of its fence.** A lane or an L1 engine getting out of its Docker container onto
  your machine, or an engine writing to the pack it has read-only; a lane's http tool reaching
  anything but its challenge's instance; a Docker lane or engine on any network while its
  challenge has no instance or it has not been allowed to reach it; something a lane wrote
  running in your take-over shell before you type.
- **A key or token where it should not be**: in the run log (`events.jsonl`), a transcript, a
  report, a writeup draft, the console, or a lane (its commands' environment, its model's
  context). That is every model API key, the CTFd token and everything in your keys file.
- **A flag sent without your approval when it should have waited.** Every flag waits under
  `submit = "confirm"`, and nothing reaches the platform while an event's submit stage is
  `manual` or `off`. Under auto submit a flag still waits when the platform counts the challenge's
  tries, when the challenge's own description or handout holds it, or when it is only a match in
  what an L1 engine printed; and a flag found wrong is never submitted again.

## Not a vulnerability

- **`--host` lanes.** They are unsafe by design, and documented as such: a lane runs as you, on
  your machine, so it can read your files, your keys file and flightdeck's own environment, and
  send what it reads to its model's API. flightdeck says so before every host run, and there the
  cleanup of logs and transcripts is cleanup, not a fence. Use Docker, a disposable VM or a
  separate low-limit key. A report that a `--host` lane can read or send something of yours is
  not a vulnerability report.
- **A coding-agent CLI's own credential.** The commands `--agent claude` or `--agent codex` runs
  can read that CLI's credential, in Docker too. Give it a key you can revoke, with a low
  spending limit.
- **The network a lane was allowed.** Once a Docker lane may reach its challenge's instance, its
  container is on Docker's bridge network: open egress, not only the instance (there is no
  per-origin allowlist yet). A coding-agent lane is always on it, for its CLI's API. The http
  tool still goes only to the instance.
- **What auto submit does.** Under auto submit, a flag a lane claims goes to the platform at once,
  as you asked.
- **What the cleanup leaves on purpose.** Transcripts and writeup drafts lose what looks like a
  credential, as the README lists under "After a run"; anything else stays, lower-case names
  included (a `password` is everyday CTF content). Read a draft before you share it.
- **A bug in a challenge or a CTF platform.** Tell the event's organisers.

## How to report

Use GitHub's private vulnerability reporting:
**[report a vulnerability](https://github.com/MFisher14/ctf-flightdeck/security/advisories/new)**.
Only you and the repository's maintainers see it.

Say what you did, what happened and what should have happened, with `flightdeck --version`, your
OS, where lanes ran (Docker or `--host`) and the model API or coding-agent CLI. The best proof is
a synthetic challenge that shows it: a folder with a `challenge.json` and a handout file is enough
(the format is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)).

Never send a real key, a CTFd token, a cookie, real event data or another team's flags, even in a
private report: make up a stand-in.

## What to expect

- An answer within a week, saying whether it counts and what happens next.
- A fix in a new release, then the advisory published, crediting you unless you would rather not
  be named.
- Please keep it private until the fix is out. If players are being hit by it already, say so,
  and it goes first.

flightdeck is in alpha (0.x): only the newest release gets fixes.
