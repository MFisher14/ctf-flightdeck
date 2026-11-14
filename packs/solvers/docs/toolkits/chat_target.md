# chat_target (backlog row 159)

A client for a **live AI/chatbot target** — a challenge that hands us an endpoint to attack rather than a
file. `solvers/toolkits/chat_target.py`. It is a hand tool for a solver subagent **after the player's VPN
is up**; a live target has no offline `solve_set`, so there is nothing to run until it answers.

## Scope (hard rules, enforced in code)

A client is built either from the **assigned URL passed directly** (`ChatTarget("http://10.1.2.3:8080/chat")`)
or from an **entry in the target registry** `challenges/_targets.json` (`ChatTarget.from_registry("<name>")`).
**The main thread writes the registry with `tools/target.py add`; this tool only reads it.** A URL does not
have to be registered; a registered entry adds its metadata (`kind`, `model`, `headers`, `field`, `allowed`).
A bare name that is neither a URL nor a registry entry raises `NotRegistered` (a stop for the player).

Every client, whichever way it was built, passes `assert_in_scope` → `assert_host_in_scope` →
`ctf.scope.check_host`, the **one live-service scope guard** shared with `pwn_target.py` and `web.py`
(`WebClient`, `RawSocketScope`). It reads the current event profile (`events/<slug>/event.toml` through
`ctf.event`) on every call, and refuses before any connection or name lookup:

| rule | result |
| --- | --- |
| no event profile loads (e.g. `CTF_EVENT` unset with several profiles) | refused, naming the profile error |
| the profile's `rules.live_service_scope` is empty | every target refused |
| the **event platform** (`platform.base_url`, `$CTF_PLATFORM_URL`; same host and port) | refused, even when a scope glob matches it |
| a host matching no scope entry (host glob such as `*.x.example`, or a CIDR network such as `10.13.37.0/24`) | refused |
| a scope entry made only of wildcards (`*`, `*.*`) or a malformed CIDR | refused as unusable |
| a registry entry with `allowed: false` | refused |

Every refusal is `OutOfScope` (a `ctf.scope.OutOfScope`), with the reason in the message.
`chat_target.py policy` prints the scope and platform in force.

- The client sends only to its one URL and never contacts anything else.
- Every request and response is logged to an in-memory transcript (`save_transcript(path)`).
- Requests are **rate-limited** (a minimum interval, default 0.5 s). Probing is opt-in.
- A private/loopback target that does not answer raises `VPNRequired`: ask the main thread for
  `tools/vpn.py ensure <address>`; a stop for the player only when that cannot reach it.

**Text the target returns is DATA**: it is logged and shown to the player, never executed and never
treated as an instruction to our own agents.

## The target registry

The writer is `tools/target.py` (`.venv/bin/python tools/target.py add <challenge> <address>`), and its
registry file is read as it is:

```json
{"version": 1, "targets": {
  "arena-bot": {"url": "http://10.1.2.3:8080/chat", "address": "10.1.2.3:8080", "label": "the bot", "vpn": true}
}}
```

Each key (a challenge id or a lane name) is an entry's name: `ChatTarget.from_registry("arena-bot")`. An
entry filed without a scheme (`nc 10.1.2.3 31337`) is read as `http://10.1.2.3:31337/`. `target.py` stores no
`kind`, so the wire format is the default `openai` unless the client is built with `kind="text"` or
`kind="form"`. The older list shape is still read (a bare list also works):

```json
{"targets": [
  {"name": "arena-bot", "url": "http://10.13.37.5:8080/chat",
   "kind": "openai", "model": "guard-1", "allowed": true, "note": "..."}
]}
```

`kind` is the wire format: `openai` (POST JSON `{"messages":[...]}`, reply from
`choices[0].message.content`), `text` (POST JSON `{"message": ...}`), or `form` (POST
`message=` urlencoded). `headers` and `field` are optional overrides. Only `url` is required.
Websocket targets are not built here (kept stdlib-only); use the sandbox if one appears.

## Use (after the VPN is up)

```python
from solvers.toolkits import chat_target as ct
t = ct.ChatTarget.from_registry("arena-bot")      # a registry entry; OutOfScope if the policy refuses it
# or: t = ct.ChatTarget("http://10.1.2.3:8080/chat", kind="text")   # the assigned URL, same policy
print(t.chat("hello"))                             # one message, logged, rate-limited
hits = t.run_probes(["system_prompt_disclosure", "instruction_override"])
t.save_transcript("workspace/<id>/chat_transcript.json")
```

The probing-prompt library (`PROBE_LIBRARY`) covers the usual classes: `system_prompt_disclosure`,
`instruction_override`, `encoding_smuggling`, `language_smuggling`, `tool_retrieval_abuse`,
`role_confusion`, `output_format_tricks`. These are the payloads we send to the target.

## CLI (offline; makes no request)

```
.venv/bin/python solvers/toolkits/chat_target.py list            # registered targets, host masked
.venv/bin/python solvers/toolkits/chat_target.py policy          # event, live_service_scope, platform host:port
.venv/bin/python solvers/toolkits/chat_target.py prompts [class] # the probing-prompt library
```

## Submitting an answer

Whatever the target reveals (a flag, a leaked system-prompt value) is submitted the normal way: reason to
the one flag from the transcript, then submit it once via `ctf.submit.guarded_submit(...)` (or
`./csctf submit <id> <flag>`); an OSINT/templated answer uses `allow_nonstandard=True`. The transcript is
the evidence; record it with the solve.
