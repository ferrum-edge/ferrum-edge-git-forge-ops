# shellcheck shell=bash
#
# Shared agent-CLI binary resolution for .agents/skills/*/scripts/dispatch-agent.sh.
#
# Every dispatch launcher must run the operator's OWN CLI install, never a copy
# bundled inside Conductor.app. Conductor's `agent-binaries/` and `bin/.internal/`
# trees lag behind the standalone releases (as of 2026-08-12: claude 2.1.220 vs
# 2.1.228, codex 0.146.0 vs 0.147.0, opencode 1.17.19 vs 1.18.16), and a
# Conductor-injected PATH can silently shadow the newer binary.
#
# Resolution order, per CLI:
#   1. the skill's explicit env override (CODEX_BIN, CLAUDE_BIN, ...)
#   2. the well-known standalone install paths for that CLI
#   3. PATH
# Any candidate whose path lives under com.conductor.app is refused at every
# step, so a stale bundle produces a hard error instead of a silent downgrade.

absolute_git_path() {
  local worktree_root=$1 selector=$2 path

  path=$(git -C "$worktree_root" rev-parse "$selector") || return 2
  case "$path" in
    /*) printf '%s\n' "$path" ;;
    *) (CDPATH='' cd -- "$worktree_root/$path" && pwd -P) ;;
  esac
}

agent_bin_is_conductor_owned() {
  case "$1" in
    *com.conductor.app*) return 0 ;;
    *) return 1 ;;
  esac
}

# require_linked_worktree <absolute-worktree-root>
# Refuse the repository's primary checkout and the controller's own checkout.
# Write-enabled workers receive a dedicated linked worktree so they cannot race
# with the operator over one index, branch, or working tree.
require_linked_worktree() {
  local worktree_root=$1
  local git_dir common_dir controller_root

  worktree_root=$(cd "$worktree_root" && pwd -P) || return 2

  git_dir=$(absolute_git_path "$worktree_root" --git-dir) || return 2
  common_dir=$(absolute_git_path "$worktree_root" --git-common-dir) || return 2
  if [[ "$git_dir" == "$common_dir" ]]; then
    printf 'Refusing the primary checkout: dispatch requires a dedicated linked git worktree: %s\n' \
      "$worktree_root" >&2
    return 2
  fi

  if controller_root=$(git -C "$PWD" rev-parse --show-toplevel 2>/dev/null); then
    controller_root=$(cd "$controller_root" && pwd -P)
    if [[ "$controller_root" == "$worktree_root" ]]; then
      printf 'Refusing the controller checkout: launch the dispatcher from a different worktree: %s\n' \
        "$worktree_root" >&2
      return 2
    fi
  fi
}

dispatch_lock_path=''
dispatch_lock_backend=''
dispatch_lock_holder=''
dispatch_lock_ready_dir=''
dispatch_lock_release_file=''
cursor_control_workspace=''
dispatch_child=''

release_worktree_dispatch_lock() {
  if [[ -n "$dispatch_child" ]] && kill -0 "$dispatch_child" 2>/dev/null; then
    kill -TERM -- "-$dispatch_child" 2>/dev/null || true
    wait "$dispatch_child" 2>/dev/null || true
  fi
  dispatch_child=''
  if [[ -n "$cursor_control_workspace" ]]; then
    case "$cursor_control_workspace" in
      "${TMPDIR:-/tmp}"/gitforgeops-cursor-control.*)
        rm -rf -- "$cursor_control_workspace"
        ;;
      *)
        printf 'Refusing to remove unexpected Cursor control workspace: %s\n' \
          "$cursor_control_workspace" >&2
        ;;
    esac
    cursor_control_workspace=''
  fi

  case "$dispatch_lock_backend" in
    lockf)
      if [[ -n "$dispatch_lock_holder" ]] && kill -0 "$dispatch_lock_holder" 2>/dev/null; then
        printf 'release\n' > "$dispatch_lock_release_file"
        wait "$dispatch_lock_holder" 2>/dev/null || true
      fi
      ;;
    flock)
      flock -u 9 2>/dev/null || true
      exec 9>&-
      ;;
  esac
  if [[ -n "$dispatch_lock_ready_dir" ]]; then
    rm -f -- "$dispatch_lock_ready_dir/ready"
    rm -f -- "$dispatch_lock_ready_dir/release"
    rmdir -- "$dispatch_lock_ready_dir" 2>/dev/null || true
  fi
  dispatch_lock_path=''
  dispatch_lock_backend=''
  dispatch_lock_holder=''
  dispatch_lock_ready_dir=''
  dispatch_lock_release_file=''
}

arm_dispatch_cleanup() {
  trap release_worktree_dispatch_lock EXIT
  trap 'forward_dispatch_signal HUP 129' HUP
  trap 'forward_dispatch_signal INT 130' INT
  trap 'forward_dispatch_signal TERM 143' TERM
}

forward_dispatch_signal() {
  local signal=$1 status=$2

  if [[ -n "$dispatch_child" ]] && kill -0 "$dispatch_child" 2>/dev/null; then
    kill -s "$signal" -- "-$dispatch_child" 2>/dev/null || true
    wait "$dispatch_child" 2>/dev/null || true
  fi
  dispatch_child=''
  exit "$status"
}

# run_dispatch_child <prompt-file> <command> [args...]
# Keep the launcher as the stable controller PID, forward cancellation to the
# CLI process group, preserve its exit status, and prevent the Linux flock
# descriptor from leaking into the worker or any daemon it starts.
run_dispatch_child() {
  local prompt_file=$1 status
  shift

  # Job control gives the worker a fresh process group and restores the default
  # SIGINT disposition that non-interactive Bash otherwise assigns to an async
  # child. The controller can then cancel the CLI and all of its descendants.
  set -m
  "$@" < "$prompt_file" 9>&- &
  dispatch_child=$!
  set +m
  if wait "$dispatch_child"; then
    status=0
  else
    status=$?
  fi
  dispatch_child=''
  return "$status"
}

prepare_cursor_control_workspace() {
  cursor_control_workspace=$(mktemp -d \
    "${TMPDIR:-/tmp}/gitforgeops-cursor-control.XXXXXX") || return 2
  chmod 0700 "$cursor_control_workspace" || return 2
  if [[ -L "$cursor_control_workspace" || ! -d "$cursor_control_workspace" ]]; then
    printf 'Cursor control workspace is not a real directory: %s\n' \
      "$cursor_control_workspace" >&2
    return 2
  fi
}

# acquire_worktree_dispatch_lock <absolute-worktree-root>
# Hold a process-scoped, worktree-specific lock until the launcher exits. This
# prevents two workers from being dispatched into the same linked worktree.
acquire_worktree_dispatch_lock() {
  local worktree_root=$1
  local git_dir owner_pid='' ready_file='' owner_file=''

  worktree_root=$(cd "$worktree_root" && pwd -P) || return 2

  git_dir=$(absolute_git_path "$worktree_root" --git-dir) || return 2
  dispatch_lock_path="$git_dir/gitforgeops-agent-dispatch.lock"

  if command -v flock >/dev/null 2>&1; then
    exec 9>> "$dispatch_lock_path"
    if ! flock -n 9; then
      IFS= read -r owner_pid < "$dispatch_lock_path" || true
      printf 'Refusing concurrent dispatch into worktree %s (lock: %s, owner pid: %s)\n' \
        "$worktree_root" "$dispatch_lock_path" "${owner_pid:-unknown}" >&2
      exec 9>&-
      dispatch_lock_path=''
      return 2
    fi
    printf '%s\n' "$$" > "$dispatch_lock_path"
    dispatch_lock_backend='flock'
  elif command -v lockf >/dev/null 2>&1; then
    dispatch_lock_ready_dir=$(mktemp -d \
      "$git_dir/gitforgeops-agent-dispatch.ready.XXXXXX") || return 2
    chmod 0700 "$dispatch_lock_ready_dir" || return 2
    ready_file="$dispatch_lock_ready_dir/ready"
    dispatch_lock_release_file="$dispatch_lock_ready_dir/release"
    owner_file="$dispatch_lock_path.owner"
    # The embedded script is intentionally single-quoted; its positional
    # parameters are expanded by the lock-holder shell, not this launcher.
    # shellcheck disable=SC2016
    lockf -k -t 0 "$dispatch_lock_path" sh -c '
      parent_pid=$1
      owner_path=$2
      ready_path=$3
      release_path=$4
      cleanup_owner() { rm -f -- "$owner_path"; }
      trap cleanup_owner EXIT
      trap "exit 129" HUP
      trap "exit 130" INT
      trap "exit 143" TERM
      printf "%s\n" "$parent_pid" > "$owner_path"
      printf "ready\n" > "$ready_path"
      while [ ! -f "$release_path" ] && kill -0 "$parent_pid" 2>/dev/null; do
        parent_state=$(ps -o stat= -p "$parent_pid" 2>/dev/null) || {
          sleep 0.1
          continue
        }
        case "$parent_state" in *Z*) break ;; esac
        sleep 0.1
      done
    ' sh "$$" "$owner_file" "$ready_file" "$dispatch_lock_release_file" \
      </dev/null >/dev/null 2>&1 &
    dispatch_lock_holder=$!
    dispatch_lock_backend='lockf'
    local ready_deadline=$((SECONDS + 30))
    while [[ ! -f "$ready_file" ]] && kill -0 "$dispatch_lock_holder" 2>/dev/null; do
      if ((SECONDS >= ready_deadline)); then
        break
      fi
      sleep 0.01
    done
    if [[ ! -f "$ready_file" ]]; then
      if [[ -f "$owner_file" ]]; then
        IFS= read -r owner_pid < "$owner_file" || true
      fi
      printf 'Refusing concurrent dispatch into worktree %s (lock: %s, owner pid: %s)\n' \
        "$worktree_root" "$dispatch_lock_path" "${owner_pid:-unknown}" >&2
      release_worktree_dispatch_lock
      return 2
    fi
  else
    printf 'Dispatch locking requires flock or lockf; neither command is available.\n' >&2
    dispatch_lock_path=''
    return 2
  fi
  arm_dispatch_cleanup
}

# Keep candidate worktrees and inherited provider variables from replacing the
# explicitly selected CLI provider. Authentication still comes from each CLI's
# normal credential store or the one provider key its launcher documents.
isolate_codex_provider() {
  unset CODEX_HOME
  unset OPENAI_API_KEY
  unset OPENAI_BASE_URL
  unset OPENAI_API_BASE
  unset OPENAI_ORG_ID
  unset OPENAI_PROJECT_ID
  unset CODEX_API_KEY
}

isolate_opencode_provider() {
  unset OPENCODE_CONFIG
  unset OPENCODE_CONFIG_DIR
  unset OPENCODE_CONFIG_CONTENT
  unset OPENCODE_API_KEY
  unset OPENCODE_AUTH_CONTENT
  export OPENCODE_DISABLE_PROJECT_CONFIG=1
}

isolate_claude_provider() {
  local variable
  while IFS= read -r variable; do
    case "$variable" in
      ANTHROPIC_*|CLAUDE_*) unset "$variable" ;;
    esac
  done < <(compgen -v)
  unset MAX_THINKING_TOKENS
}

isolate_cursor_provider() {
  local variable
  while IFS= read -r variable; do
    case "$variable" in
      CURSOR_API_KEY) ;;
      CURSOR_*) unset "$variable" ;;
    esac
  done < <(compgen -v)
}

# resolve_agent_bin <command-name> <env-var-name> [candidate-abs-path...]
# Prints the resolved absolute path on stdout; diagnostics go to stderr.
resolve_agent_bin() {
  local cmd=$1 env_var=$2
  shift 2

  local override=${!env_var:-}
  if [[ -n "$override" ]]; then
    if [[ "$override" != /* || ! -x "$override" ]]; then
      printf '%s is set but is not an executable absolute path: %s\n' \
        "$env_var" "$override" >&2
      return 127
    fi
    if agent_bin_is_conductor_owned "$override"; then
      printf '%s points at a Conductor-bundled binary: %s\n' "$env_var" "$override" >&2
      printf 'Conductor bundles lag behind; point %s at your own %s install.\n' \
        "$env_var" "$cmd" >&2
      return 127
    fi
    printf '%s\n' "$override"
    return 0
  fi

  local candidate
  for candidate in "$@"; do
    if [[ -x "$candidate" ]] && ! agent_bin_is_conductor_owned "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  if command -v "$cmd" >/dev/null 2>&1; then
    candidate=$(command -v "$cmd")
    if agent_bin_is_conductor_owned "$candidate"; then
      printf '%s on PATH resolves to a Conductor-bundled binary: %s\n' \
        "$cmd" "$candidate" >&2
      printf 'Install %s standalone or set %s to your own install.\n' "$cmd" "$env_var" >&2
      return 127
    fi
    printf '%s\n' "$candidate"
    return 0
  fi

  printf '%s CLI not found.\n' "$cmd" >&2
  printf 'Install it standalone or set %s to an absolute path.\n' "$env_var" >&2
  return 127
}
