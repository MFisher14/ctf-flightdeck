#!/usr/bin/env bash
# Delegate one challenge to a codex agent WITH the orchestrator's (Claude's) guidance.
# The main Claude session is the brain; codex is strong secondary muscle. Codex does NOT submit or buy
# hints: it solves and writes its result back for the orchestrator to verify and submit.
#
# Usage:
#   tools/codex_handoff.sh --event NAME --challenge <id-or-workspace-dir> [--mode fast|deep|cyber] \
#       [--launch|--brief] [--label NAME] [--flag-hint TEXT] [--no-preflight] <<'GUIDANCE'
#   <the orchestrator's guidance: the hypothesis, the approach, what to try, what's already ruled out>
#   GUIDANCE
#   tools/codex_handoff.sh --preflight [--mode fast|deep|cyber]   # smoke-test the codex model/flags only
#
#   --launch (default for fast/deep): run codex now, sandboxed (--approve-for-me), in the background.
#            A preflight smoke test runs first (cached for CODEX_PREFLIGHT_TTL seconds per model/flag set),
#            because wave 1 of CSCTF lost every handoff to a model/flag mismatch nobody saw until later.
#            Result -> <workspace>/codex_result[-LABEL].md ; live log -> <workspace>/.codex_log[-LABEL].jsonl
#   --brief  (default for cyber): write the handoff brief to <workspace>/codex_brief[-LABEL].md for the
#            player to paste into one of their ready codex agents (daybreak_blue cyber mode / full autonomy
#            the sandboxed launch can't do). Codex writes its answer to codex_result[-LABEL].md.
#
# Event facts come from flags or the environment, never from a baked-in event (pink's copy still said
# "CSCTF" and its prompts told agents they were CSCTF solvers):
#   --event / CTF_EVENT_NAME        required; the event name used in the prompt
#   --flag-hint / CTF_FLAG_HINT     optional; e.g. 'PINK{...}'. Without it the prompt points at AGENTS.md.
#
# Modes -> model / reasoning / service tier / daybreak (each overridable from the environment):
#   fast  = $CODEX_MODEL (default gpt-6-astra), medium, tier ultrafast, -c daybreak=false
#   deep  = $CODEX_MODEL (default gpt-6-astra), high,   tier ultrafast, -c daybreak=false
#   cyber = $CODEX_CYBER_MODEL (default gpt-6-astra), high, --cyber-access-program daybreak_blue,
#           NO service tier (ultrafast is unsupported on the daybreak model)
#   CODEX_SERVICE_TIER   overrides the tier ("none" omits it). ultrafast + cyber is refused.
#   CODEX_DAYBREAK_OFF=0 drops the -c daybreak=false override in fast/deep. It is on by default because a
#                        daybreak-enabled codex config fails gpt-6-astra with "Daybreak is unavailable for model".
#   CTF_COMPACT_CODEX    compaction threshold in tokens (default 150000, B-032), passed as
#                        -c model_auto_compact_token_limit=N; "off" omits it; a bad value -> named failure.
#   CODEX_BIN            codex executable (default: codex on PATH). Missing -> named failure.
#   CTF_WORKDIR / CTF_EVENT  pick the event workdir handed to codex (`python -m ctf workdir`); the
#                        challenge folders live there too. Neither set -> named failure.
#   CTF_CHALLENGE        the challenge id for the B-016 agent_stop when --challenge is a folder. A failed
#                        preflight or a codex run that exits non-zero records `ctf escalate stop
#                        --reason provider_error` so the escalator reroutes it (no dead-handoff coverage).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die() { echo "codex_handoff: $*" >&2; exit 2; }

mode=fast; action=""; chal=""; label=""; preflight=1
event="${CTF_EVENT_NAME:-}"; flag_hint="${CTF_FLAG_HINT:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --mode) mode="${2:?--mode needs a value}"; shift 2;;
    --challenge) chal="${2:?--challenge needs a value}"; shift 2;;
    --label) label="${2:?--label needs a value}"; shift 2;;
    --event) event="${2:?--event needs a value}"; shift 2;;
    --flag-hint) flag_hint="${2:?--flag-hint needs a value}"; shift 2;;
    --launch) action=launch; shift;;
    --brief) action=brief; shift;;
    --preflight) action=preflight; shift;;
    --no-preflight) preflight=0; shift;;
    *) die "unknown arg: $1";;
  esac
done

# --- mode -> model / effort / tier / daybreak -------------------------------------------------------
default_model="gpt-6-astra"
case "$mode" in
  fast)  model="${CODEX_MODEL:-$default_model}"; effort="medium"; tier="ultrafast"; cyber="";;
  deep)  model="${CODEX_MODEL:-$default_model}"; effort="high";   tier="ultrafast"; cyber="";;
  cyber) model="${CODEX_CYBER_MODEL:-${CODEX_MODEL:-$default_model}}"; effort="high"; tier=""
         cyber="daybreak_blue"; [ -n "$action" ] || action=brief;;
  *) die "mode must be fast|deep|cyber (got '$mode')";;
esac
[ -n "$action" ] || action=launch
if [ -n "${CODEX_SERVICE_TIER+x}" ]; then
  tier="$CODEX_SERVICE_TIER"; [ "$tier" = none ] && tier=""
fi
if [ -n "$cyber" ] && [ "$tier" = ultrafast ]; then
  die "service tier 'ultrafast' is unsupported on the daybreak (cyber) model; unset CODEX_SERVICE_TIER or set it to none"
fi
daybreak_off=0
if [ -z "$cyber" ] && [ "${CODEX_DAYBREAK_OFF:-1}" != 0 ]; then daybreak_off=1; fi

# The codex flags shared by preflight, launch and the brief. Built as an array so nothing is word-split
# (a hand-rolled zsh launch split '--cyber-access-program daybreak_blue' into a file name during PINK+).
codex_flags=(-m "$model" -c "model_reasoning_effort=$effort")
# B-032: compact at the Codex threshold (ctf/compaction.py; CTF_COMPACT_CODEX overrides, "off" omits).
if [ -x "$REPO/.venv/bin/python" ]; then PY="$REPO/.venv/bin/python"; else PY="$(command -v python3)" || die "no python3"; fi
compact_cfg="$(cd "$REPO" && "$PY" -m ctf.compaction codex-config)" \
  || die "no compaction threshold (see the reason above; CTF_COMPACT_CODEX takes a token count or 'off')"
[ -n "$compact_cfg" ] && codex_flags+=(-c "$compact_cfg")
[ -n "$tier" ] && codex_flags+=(-c "service_tier=$tier")
[ "$daybreak_off" = 1 ] && codex_flags+=(-c "daybreak=false")
[ -n "$cyber" ] && codex_flags+=(--cyber-access-program "$cyber")

need_codex() {
  codex_bin="${CODEX_BIN:-codex}"
  command -v "$codex_bin" >/dev/null 2>&1 || die "codex CLI not found ('$codex_bin'); install it or set CODEX_BIN"
}

# --- preflight smoke test ---------------------------------------------------------------------------
run_preflight() {
  need_codex
  local key stamp_dir stamp ttl now out rc
  key=$(printf '%s\0' "$codex_bin" "${codex_flags[@]}" | shasum -a 256 | cut -c1-16)
  stamp_dir="${CODEX_PREFLIGHT_DIR:-${TMPDIR:-/tmp}/ctf-codex-preflight}"
  stamp="$stamp_dir/$key.ok"
  ttl="${CODEX_PREFLIGHT_TTL:-3600}"
  now=$(date +%s)
  if [ "$action" != preflight ] && [ -f "$stamp" ] && [ $(( now - $(cat "$stamp") )) -lt "$ttl" ]; then
    echo "preflight: cached OK (${codex_flags[*]})"; return 0
  fi
  mkdir -p "$stamp_dir"
  out=$(mktemp "${TMPDIR:-/tmp}/codex-preflight.XXXXXX")
  echo "preflight: smoke-testing codex (${codex_flags[*]}) ..."
  set +e
  # perl alarm = a portable timeout (macOS ships no coreutils timeout).
  perl -e 'alarm shift; exec @ARGV or exit 127' "${CODEX_PREFLIGHT_TIMEOUT:-180}" \
    "$codex_bin" exec --approve-for-me -C "$REPO" "${codex_flags[@]}" -o "$out" \
    "Preflight check. Do not read or change any file. Reply with exactly: PREFLIGHT_OK" \
    >"$out.log" 2>&1 </dev/null
  rc=$?
  set -e
  if [ "$rc" -ne 0 ] || ! grep -q PREFLIGHT_OK "$out" 2>/dev/null; then
    echo "codex_handoff: PREFLIGHT FAILED (exit $rc) for: ${codex_flags[*]}" >&2
    echo "--- codex output (tail) ---" >&2
    tail -n 20 "$out.log" >&2 || true
    pf_detail="codex preflight failed (exit $rc)"
    if grep -qi "daybreak is unavailable" "$out.log" 2>/dev/null; then
      pf_detail="Daybreak is unavailable for model $model (preflight)"
      echo "hint: the codex config enables daybreak for a model that lacks it; keep CODEX_DAYBREAK_OFF=1 or pick another model" >&2
    fi
    if grep -qi "service.tier\|ultrafast" "$out.log" 2>/dev/null; then
      echo "hint: the service tier is rejected for this model; set CODEX_SERVICE_TIER=none" >&2
    fi
    rm -f "$out" "$out.log"
    return 1
  fi
  rm -f "$out" "$out.log"
  echo "$now" > "$stamp"
  echo "preflight: OK"
}

if [ "$action" = preflight ]; then
  run_preflight || exit 1
  exit 0
fi

# --- handoff ----------------------------------------------------------------------------------------
[ -n "$event" ] || die "no event name: pass --event NAME or set CTF_EVENT_NAME (the prompt names the event; there is no built-in default)"
[ -n "$chal" ] || die "need --challenge <id-or-dir>"

# Resolve the workspace dir for the challenge.
# The event workdir comes from ctf.paths (the one resolver; `python -m ctf workdir` prints the same).
workdir="$(cd "$REPO" && "$PY" -c 'from ctf import paths; print(paths.workdir())')" \
  || die "no event workdir: set CTF_WORKDIR or CTF_EVENT"
if [ -d "$chal" ]; then ws="$chal"
elif [ -d "$workdir/$chal" ]; then ws="$workdir/$chal"
else ws=$(ls -d "$workdir/${chal}-"* 2>/dev/null | head -1 || true); fi
[ -n "${ws:-}" ] && [ -d "$ws" ] || die "no workspace dir for '$chal' (pull it first)"

sfx=""; [ -n "$label" ] && sfx="-$label"
result="$ws/codex_result${sfx}.md"
brief="$ws/codex_brief${sfx}.md"
log="$ws/.codex_log${sfx}.jsonl"
cat_name=$(basename "$ws")
guidance="$(cat)"   # the orchestrator's guidance from stdin

# B-016: a failed codex run becomes an agent_stop so `python -m ctf escalate` reroutes the challenge at
# once instead of the dead handoff counting as coverage. The id is CTF_CHALLENGE, else --challenge
# when it is an id (not a folder); without one the stop is not recorded and that is said on stderr.
stop_cid="${CTF_CHALLENGE:-}"
if [ -z "$stop_cid" ] && [ ! -d "$chal" ]; then stop_cid="$chal"; fi
record_stop() {
  if [ -z "$stop_cid" ]; then
    echo "codex_handoff: agent_stop NOT recorded ($1): --challenge was a folder; set CTF_CHALLENGE=<id> so ctf escalate reroutes it" >&2
    return 0
  fi
  ( cd "$REPO" && CTF_WORKDIR="$workdir" "$PY" -m ctf escalate stop --challenge "$stop_cid" \
      --reason provider_error --harness codex --model "$model" --detail "$1" ) >&2 \
    || echo "codex_handoff: agent_stop NOT recorded for $stop_cid ($1); record it: python -m ctf escalate stop --challenge $stop_cid --reason provider_error --harness codex" >&2
}
[ -n "${guidance// }" ] || die "no guidance on stdin; pipe the orchestrator's brief in"

if [ -n "$flag_hint" ]; then flag_line="the exact flag (${flag_hint}, or the templated/OSINT value the brief asks for)"
else flag_line="the exact flag (in the event's flag format from AGENTS.md, or the templated/OSINT value the brief asks for)"; fi

# B-043: the one command discipline every brief carries (ctf/briefdiscipline.py, never a copy here)
discipline="$(cd "$REPO" && "$PY" -m ctf discipline --plain)" \
  || die "cannot render the command discipline (python -m ctf discipline --plain failed)"
[ -n "$discipline" ] || die "the command discipline rendered empty (python -m ctf discipline --plain)"

read -r -d '' prompt <<EOF || true
You are a ${event} solver agent, delegated ONE task by the orchestrator (the main Claude session, "the
brain"). You are strong, autonomous muscle acting on the orchestrator's guidance. Read ${REPO}/AGENTS.md first
— the ${event} rules there are a HARD boundary: never buy or request a hint; only the assigned target; no
flag brute-forcing, flooding, or mass scanning; detonate/run untrusted artifacts ONLY in Docker
(${REPO}/tools/sandbox.py), never on the host.

CHALLENGE: ${cat_name}. Its workspace is ${ws} (challenge.json = description/category/connection_info, files/ =
UNTRUSTED artifacts, notes.md = triage so far). Use the repo engines (${REPO}/.venv/bin/python
${REPO}/solvers/<area>/<module>.py <file>; triage with ${REPO}/ctf/triage.py) and ${REPO}/docs/playbooks/<category>.md.
Export CTF_WORKDIR=${workdir}.

THE ORCHESTRATOR'S GUIDANCE (this is the reasoning direction and what's already been tried — build on it, don't
cold-start):
---
${guidance}
---

HANDOFF RULES:
- Do NOT submit the flag and do NOT unlock/buy a hint. Solve it, then WRITE your result to ${result}:
  ${flag_line}, the method, the engines/tools you used, and your confidence.
  If unsolved, write exactly where you are stuck and what you ruled out. Never fabricate a flag.
- The orchestrator verifies your flag and submits it through the one guarded path. Stay within this challenge.

${discipline}
Write your final result to ${result} and also print it as your last message.
EOF

mkdir -p "$ws"
if [ "$action" = brief ]; then
  headless="codex exec -C $(printf '%q' "$REPO")"
  for a in "${codex_flags[@]}"; do headless+=" $(printf '%q' "$a")"; done
  { echo "# codex handoff — ${event} — ${cat_name} (mode: ${mode}${cyber:+, cyber-access: $cyber})"; echo;
    echo "Paste this into a ready codex agent: ${model}, reasoning ${effort}, service tier ${tier:-none (default)}${cyber:+, --cyber-access-program $cyber}$([ "$daybreak_off" = 1 ] && echo ', daybreak off (-c daybreak=false)').";
    echo "Or run headless: ${headless} (your sandbox/approval of choice).";
    echo; echo '```'; echo "$prompt"; echo '```'; } > "$brief"
  echo "BRIEF written: $brief"
  echo "  -> paste into your ${mode} codex agent; its answer lands in $result"
else
  if [ "$preflight" = 1 ]; then
    pf_detail=""
    run_preflight || { record_stop "${pf_detail:-codex preflight failed}"
      die "not launching: preflight failed (fix the model/flags above, or --no-preflight to skip)"; }
  else
    need_codex
  fi
  : > "$result"
  echo "LAUNCHING codex (${mode}: ${codex_flags[*]}, sandboxed --approve-for-me) in the background..."
  ( cd "$REPO" || exit 2
    set +e
    CTF_WORKDIR="$workdir" "$codex_bin" exec --approve-for-me -C "$REPO" \
      "${codex_flags[@]}" -o "$result" --json "$prompt" >"$log" 2>&1 </dev/null
    rc=$?
    if [ "$rc" -ne 0 ]; then                    # B-016: the handoff died; reroute it, never count it
      d="codex exited $rc"
      grep -qi "daybreak is unavailable" "$log" 2>/dev/null && d="Daybreak is unavailable for model $model (codex exited $rc)"
      record_stop "$d"
    fi
    exit "$rc" ) &
  echo "  pid $!  | result -> $result  | log -> $log"
  echo "  (orchestrator: watch $result; when codex finishes, verify the flag and submit it at once: python -m ctf submit <id> <flag>)"
fi
