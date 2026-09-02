#!/usr/bin/env bash

# Refuse to run a host-authorized agent against a different checkout. In
# particular, a pull-request worktree can change repository instructions and
# turn an approval-bypassing agent into a confused deputy with the operator's
# ambient credentials. Work on an untrusted revision requires an external OS
# sandbox; a Git worktree is not one.
require_trusted_worktree() {
  local candidate_root=$1
  local launcher_script_dir=$2
  local trusted_root

  trusted_root=$(CDPATH='' cd -- "$launcher_script_dir/../../../.." && pwd -P)
  if [[ "$candidate_root" != "$trusted_root" ]]; then
    printf 'Refusing to dispatch against an untrusted worktree: %s\n' "$candidate_root" >&2
    printf 'This launcher may run only in its own trusted checkout: %s\n' "$trusted_root" >&2
    printf '%s\n' 'Use a disposable OS sandbox with scrubbed credentials for pull-request heads.' >&2
    return 2
  fi
}
