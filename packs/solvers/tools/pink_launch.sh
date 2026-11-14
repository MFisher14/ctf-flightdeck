#!/usr/bin/env bash
# Unattended event opener (generalized from the PINK+ launchd opener that fired at 06:55 EST on
# 2026-11-06). Meant to be run by a launchd/cron job a few minutes before an event opens: it starts ONE
# background Claude Code session with Remote Control in the repo, and that session waits for the open,
# pulls, and runs the wave. It runs only inside the event's date window, and only once per event (lock).
#
# Usage:  tools/pink_launch.sh <opener.conf>        (or set CTF_OPENER_CONF)
#
# Every event fact comes from the config file; nothing is baked in. Format: KEY=VALUE lines, '#' comments,
# no shell expansion (the file is parsed, never sourced). Keys:
#   EVENT_NAME      required  event name (notifications, Remote Control name, default session name)
#   WINDOW_START    required  first local day the opener may fire, YYYYMMDD
#   WINDOW_END      required  last local day, YYYYMMDD
#   PROMPT_FILE     required  the session's opening prompt; relative paths resolve against REPO
#   REPO            optional  repo the session runs in (default: this script's repo)
#   LOG_DIR         optional  default: $REPO/logs/opener/<event slug>   (logs/ is gitignored)
#   SESSION_NAME    optional  claude -n name (default: <event slug>-wave)
#   RC_NAME         optional  Remote Control name (default: "<EVENT_NAME> wave")
#   PERMISSION_MODE optional  claude --permission-mode (default: auto)
#   NEED_DOCKER     optional  1 (default) = start Docker and wait for it; 0 = skip
#   DOCKER_WAIT     optional  seconds to wait for Docker (default 180)
#
# Compaction (B-032): the session gets CLAUDE_CODE_AUTO_COMPACT_WINDOW and --settings '{"autoCompactWindow":N}'
# at the Claude threshold (CTF_COMPACT_CLAUDE overrides; "off" passes neither).
#
# Test/override hooks (environment): CLAUDE_BIN, DOCKER_BIN, CTF_OPENER_TODAY (YYYYMMDD),
# CTF_OPENER_NOTIFY=0 (no macOS notification), CTF_OPENER_START_DOCKER=0 (never run 'open -a Docker').
set -u

die() {  # named failure: log it, notify, exit non-zero
  echo "opener: FAILED: $*" >&2
  notify "opener FAILED: $*"
  exit 1
}
notify() {
  [ "${CTF_OPENER_NOTIFY:-1}" = 0 ] && return 0
  command -v osascript >/dev/null 2>&1 || return 0
  local msg=${1//\"/\'}
  osascript -e "display notification \"$msg\" with title \"${EVENT_NAME:-CTF} opener\"" >/dev/null 2>&1 || true
}

conf="${1:-${CTF_OPENER_CONF:-}}"
[ -n "$conf" ] || die "no config: pass <opener.conf> or set CTF_OPENER_CONF"
[ -f "$conf" ] || die "config not found: $conf"

EVENT_NAME=""; WINDOW_START=""; WINDOW_END=""; PROMPT_FILE=""; REPO=""; LOG_DIR=""
SESSION_NAME=""; RC_NAME=""; PERMISSION_MODE=""; NEED_DOCKER=""; DOCKER_WAIT=""
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%$'\r'}"
  case "$line" in ''|\#*) continue;; esac
  key="${line%%=*}"; val="${line#*=}"
  [ "$key" != "$line" ] || die "bad config line (no '='): $line"
  key="${key//[[:space:]]/}"
  val="${val#"${val%%[![:space:]]*}"}"; val="${val%"${val##*[![:space:]]}"}"
  case "$val" in \"*\") val="${val#\"}"; val="${val%\"}";; \'*\') val="${val#\'}"; val="${val%\'}";; esac
  case "$key" in
    EVENT_NAME|WINDOW_START|WINDOW_END|PROMPT_FILE|REPO|LOG_DIR|SESSION_NAME|RC_NAME|PERMISSION_MODE|NEED_DOCKER|DOCKER_WAIT)
      printf -v "$key" '%s' "$val";;
    *) die "unknown config key '$key' in $conf";;
  esac
done < "$conf"

[ -n "$EVENT_NAME" ] || die "EVENT_NAME missing in $conf"
for k in WINDOW_START WINDOW_END; do
  v="${!k}"
  [[ "$v" =~ ^[0-9]{8}$ ]] || die "$k must be YYYYMMDD in $conf (got '${v}')"
done
[ -n "$PROMPT_FILE" ] || die "PROMPT_FILE missing in $conf"

slug=$(printf '%s' "$EVENT_NAME" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '-' | sed 's/--*/-/g; s/^-//; s/-$//')
[ -n "$REPO" ] || REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -d "$REPO" ] || die "REPO is not a directory: $REPO"
case "$PROMPT_FILE" in /*) ;; *) PROMPT_FILE="$REPO/$PROMPT_FILE";; esac
LOG_DIR="${LOG_DIR:-$REPO/logs/opener/$slug}"
SESSION_NAME="${SESSION_NAME:-$slug-wave}"
RC_NAME="${RC_NAME:-$EVENT_NAME wave}"
PERMISSION_MODE="${PERMISSION_MODE:-auto}"
NEED_DOCKER="${NEED_DOCKER:-1}"
DOCKER_WAIT="${DOCKER_WAIT:-180}"
LOCK="$LOG_DIR/opener.done"

mkdir -p "$LOG_DIR" || die "cannot create LOG_DIR $LOG_DIR"
exec >>"$LOG_DIR/opener.log" 2>&1
echo "=== $(date) opener fired for $EVENT_NAME"

today="${CTF_OPENER_TODAY:-$(date +%Y%m%d)}"
if [[ "$today" < "$WINDOW_START" || "$today" > "$WINDOW_END" ]]; then
  echo "outside $EVENT_NAME window $WINDOW_START..$WINDOW_END ($today); exiting"; exit 0
fi
if [[ -e "$LOCK" ]]; then
  echo "already launched ($(cat "$LOCK")); exiting"; exit 0
fi
[ -f "$PROMPT_FILE" ] || die "PROMPT_FILE not found: $PROMPT_FILE"

# launchd starts with a bare PATH; add the usual user/tool locations.
export PATH="$HOME/.local/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
cd "$REPO" || die "cannot cd to $REPO"
claude_bin="${CLAUDE_BIN:-claude}"
command -v "$claude_bin" >/dev/null 2>&1 || die "claude CLI not found ('$claude_bin')"

PROMPT=$(cat "$PROMPT_FILE")
# Docker is the detonation sandbox: make sure it is up. If it is not, the session is told in its prompt
# (the PINK+ opener only logged it, so the session never knew).
if [ "$NEED_DOCKER" = 1 ]; then
  docker_bin="${DOCKER_BIN:-docker}"
  if ! "$docker_bin" info >/dev/null 2>&1; then
    if [ "${CTF_OPENER_START_DOCKER:-1}" = 1 ] && command -v open >/dev/null 2>&1; then
      open -a Docker 2>/dev/null
    fi
    waited=0
    while [ "$waited" -lt "$DOCKER_WAIT" ]; do
      "$docker_bin" info >/dev/null 2>&1 && break
      sleep 5; waited=$((waited + 5))
    done
  fi
  if "$docker_bin" info >/dev/null 2>&1; then
    echo "docker: up"
  else
    echo "docker: NOT up after ${DOCKER_WAIT}s; telling the session"
    PROMPT="OPENER NOTE: Docker (the detonation sandbox) was NOT running when this session started. Do not run untrusted artifacts until it is up; tell the player.

$PROMPT"
  fi
fi

# B-032: the wave session compacts at the Claude threshold (ctf/compaction.py; CTF_COMPACT_CLAUDE
# overrides, "off" leaves the default). Set twice: in the environment, and as --settings JSON in case a
# backgrounded session does not inherit this environment. A conflicting setting fails the opener.
SELF_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -x "$SELF_REPO/.venv/bin/python" ]; then PY="$SELF_REPO/.venv/bin/python"; else PY="$(command -v python3)" || die "no python3"; fi
compact_env="$(cd "$SELF_REPO" && "$PY" -m ctf.compaction claude-env)" || die "compaction threshold: see the reason above"
compact_settings="$(cd "$SELF_REPO" && "$PY" -m ctf.compaction claude-settings)" || die "compaction threshold: see the reason above"
while IFS= read -r kv; do [ -n "$kv" ] && export "${kv?}"; done <<< "$compact_env"
settings_args=()
[ -n "$compact_settings" ] && settings_args=(--settings "$compact_settings")

out=$("$claude_bin" --bg --remote-control "$RC_NAME" --permission-mode "$PERMISSION_MODE" -n "$SESSION_NAME" ${settings_args[@]+"${settings_args[@]}"} "$PROMPT" 2>&1)
rc=$?
echo "$out"
if [ "$rc" -eq 0 ] && echo "$out" | grep -q backgrounded; then
  echo "$(date) $(echo "$out" | grep backgrounded)" > "$LOCK"
  notify "$EVENT_NAME wave session launched (Remote Control: $RC_NAME)"
else
  die "claude did not background a session (exit $rc); see $LOG_DIR/opener.log"
fi
