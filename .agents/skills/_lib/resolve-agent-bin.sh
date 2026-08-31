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

  git_dir=$(git -C "$worktree_root" rev-parse --path-format=absolute --git-dir) || return 2
  common_dir=$(git -C "$worktree_root" rev-parse --path-format=absolute --git-common-dir) || return 2
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

dispatch_lock_dir=''

release_worktree_dispatch_lock() {
  if [[ -n "$dispatch_lock_dir" ]]; then
    rm -f -- "$dispatch_lock_dir/pid"
    rmdir -- "$dispatch_lock_dir" 2>/dev/null || true
    dispatch_lock_dir=''
  fi
}

# acquire_worktree_dispatch_lock <absolute-worktree-root>
# Hold a process-scoped, worktree-specific lock until the launcher exits. This
# prevents two workers from being dispatched into the same linked worktree.
acquire_worktree_dispatch_lock() {
  local worktree_root=$1
  local git_dir owner_pid='' acquired='false'

  worktree_root=$(cd "$worktree_root" && pwd -P) || return 2

  git_dir=$(git -C "$worktree_root" rev-parse --path-format=absolute --git-dir) || return 2
  dispatch_lock_dir="$git_dir/gitforgeops-agent-dispatch.lock"

  if mkdir -- "$dispatch_lock_dir" 2>/dev/null; then
    acquired='true'
  else
    if [[ -f "$dispatch_lock_dir/pid" ]]; then
      IFS= read -r owner_pid < "$dispatch_lock_dir/pid" || true
    fi
    if [[ "$owner_pid" =~ ^[0-9]+$ ]] && ! kill -0 "$owner_pid" 2>/dev/null; then
      rm -f -- "$dispatch_lock_dir/pid"
      rmdir -- "$dispatch_lock_dir" 2>/dev/null || true
      if mkdir -- "$dispatch_lock_dir" 2>/dev/null; then
        acquired='true'
      fi
    fi
  fi

  if [[ "$acquired" != 'true' ]]; then
    printf 'Refusing concurrent dispatch into worktree %s (lock: %s, owner pid: %s)\n' \
      "$worktree_root" "$dispatch_lock_dir" "${owner_pid:-unknown}" >&2
    dispatch_lock_dir=''
    return 2
  fi

  printf '%s\n' "$$" > "$dispatch_lock_dir/pid"
  trap release_worktree_dispatch_lock EXIT
}

# Keep candidate worktrees and inherited provider variables from replacing the
# explicitly selected CLI provider. Authentication still comes from each CLI's
# normal credential store or the one provider key its launcher documents.
isolate_codex_provider() {
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
  export OPENCODE_DISABLE_PROJECT_CONFIG=1
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
