#!/usr/bin/env bash
# install.sh -- put the Mac-side pieces of the malware scanner in place.
#
# Idempotent: safe to re-run after `git pull`. Everything it does is printed
# first and nothing happens until you confirm. Nothing here touches your global
# git config, your repos, or any project's dependencies.
#
# Installs:
#   ~/.local/bin/scan-repo      wrapper: scan.py tree + history on a repo
#   ~/.local/bin/safe-clone     clone --no-checkout -> scan -> only then checkout
#   ~/Library/LaunchAgents/com.malware-scan.daily.plist
#                               daily 12:30 sweep of ~/LocalSites + ~/LocalApps,
#                               macOS notification only when something is found
#   ~/Library/Logs/malware-scan/
#
# Uninstall:  ./install.sh --uninstall
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN_PY="$REPO_DIR/scanner/scan.py"
LOCAL_DIR="$REPO_DIR/local"

BIN_DIR="$HOME/.local/bin"
AGENT_DIR="$HOME/Library/LaunchAgents"
LOG_DIR="$HOME/Library/Logs/malware-scan"
LABEL="com.malware-scan.daily"
PLIST_DST="$AGENT_DIR/$LABEL.plist"
GEN_DIR="$LOCAL_DIR/.generated"

UNINSTALL=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --uninstall) UNINSTALL=1 ;;
    --yes|-y)    ASSUME_YES=1 ;;
    --help|-h)   awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '%s\n' "$*"; }
step() { printf '  - %s\n' "$*"; }

confirm() {
  [ "$ASSUME_YES" -eq 1 ] && return 0
  printf '\nProceed? [y/N] '
  read -r reply
  case "$reply" in [yY]|[yY][eE][sS]) return 0 ;; *) say "Aborted."; exit 1 ;; esac
}

# --------------------------------------------------------------------------
# Uninstall
# --------------------------------------------------------------------------
if [ "$UNINSTALL" -eq 1 ]; then
  say "This will remove:"
  step "launchd agent  $PLIST_DST (and unload it)"
  step "symlink        $BIN_DIR/scan-repo"
  step "symlink        $BIN_DIR/safe-clone"
  say ""
  say "It will NOT remove your logs in $LOG_DIR."
  confirm
  launchctl bootout "gui/$UID/$LABEL" 2>/dev/null \
    && say "unloaded $LABEL" || say "$LABEL was not loaded"
  rm -f "$PLIST_DST" && say "removed $PLIST_DST"
  for n in scan-repo safe-clone; do
    if [ -L "$BIN_DIR/$n" ]; then rm -f "$BIN_DIR/$n"; say "removed $BIN_DIR/$n"; fi
  done
  rm -rf "$GEN_DIR"
  say "Done."
  exit 0
fi

# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------
if [ ! -f "$SCAN_PY" ]; then
  say "install.sh: cannot find the scanner at $SCAN_PY" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  say "install.sh: python3 is required (macOS ships one at /usr/bin/python3)" >&2
  exit 2
fi
if ! python3 -m py_compile "$SCAN_PY"; then
  say "install.sh: the scanner does not compile; refusing to install." >&2
  exit 2
fi

say "malware-scan local install"
say "=========================="
say ""
say "Source repo : $REPO_DIR"
say "Scanner     : $SCAN_PY"
say ""
say "This will:"
step "create $BIN_DIR and $LOG_DIR if they do not exist"
step "write wrappers into $GEN_DIR (scan.py path baked in)"
step "symlink $BIN_DIR/scan-repo  -> $GEN_DIR/scan-repo"
step "symlink $BIN_DIR/safe-clone -> $GEN_DIR/safe-clone"
step "write $PLIST_DST and load it with launchctl (daily 12:30 sweep)"
say ""
say "It will NOT:"
step "change your global git config (it only PRINTS what to run)"
step "install a global core.hooksPath (see the note at the end -- it would"
step "  be actively misleading)"
step "touch any repository, run any package manager, or execute project code"
confirm

# --------------------------------------------------------------------------
# Install
# --------------------------------------------------------------------------
mkdir -p "$BIN_DIR" "$LOG_DIR" "$AGENT_DIR" "$GEN_DIR"
say ""
say "==> generating wrappers"
for n in scan-repo safe-clone malware-scan-daily.sh; do
  sed "s|__SCAN_PY__|$SCAN_PY|g" "$LOCAL_DIR/$n" > "$GEN_DIR/$n"
  chmod 755 "$GEN_DIR/$n"
  step "$GEN_DIR/$n"
done

say ""
say "==> linking into $BIN_DIR"
for n in scan-repo safe-clone; do
  if [ -e "$BIN_DIR/$n" ] && [ ! -L "$BIN_DIR/$n" ]; then
    say "  ! $BIN_DIR/$n exists and is not a symlink; leaving it alone." >&2
    say "    Remove it yourself, then re-run." >&2
    continue
  fi
  ln -sfn "$GEN_DIR/$n" "$BIN_DIR/$n"
  step "$BIN_DIR/$n -> $GEN_DIR/$n"
done

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) say ""
     say "  ! $BIN_DIR is not on your PATH. Add this to ~/.zshrc:"
     say "        export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac

say ""
say "==> installing the launchd agent"
sed -e "s|__DAILY_SH__|$GEN_DIR/malware-scan-daily.sh|g" \
    -e "s|__LOG_DIR__|$LOG_DIR|g" \
    "$LOCAL_DIR/$LABEL.plist" > "$PLIST_DST"
if ! plutil -lint "$PLIST_DST" >/dev/null; then
  say "  ! generated plist is malformed; removing it." >&2
  rm -f "$PLIST_DST"
  exit 2
fi
step "$PLIST_DST"
launchctl bootout "gui/$UID/$LABEL" 2>/dev/null || true   # idempotent reload
if launchctl bootstrap "gui/$UID" "$PLIST_DST" 2>/dev/null; then
  step "loaded $LABEL (runs daily at 12:30)"
else
  say "  ! launchctl bootstrap failed. Load it by hand with:"
  say "        launchctl bootstrap gui/\$UID \"$PLIST_DST\""
fi

say ""
say "==> smoke test"
if python3 "$SCAN_PY" selftest >/dev/null 2>&1; then
  step "scan.py selftest passed"
else
  say "  ! scan.py selftest FAILED -- run it by hand:"
  say "        python3 \"$SCAN_PY\" selftest"
fi

# --------------------------------------------------------------------------
# Recommendations (printed, never applied)
# --------------------------------------------------------------------------
cat <<'EOF'

==> RECOMMENDED, NOT APPLIED: object-integrity checks

Run these yourself if you want them. They make git verify every object it
receives, which blocks malformed/spoofed objects at fetch time:

    git config --global fetch.fsckObjects true
    git config --global transfer.fsckObjects true
    git config --global receive.fsckObjects true

They are deliberately NOT applied here: they can make a fetch fail on
long-standing repos with historically malformed objects, and that is your
call to make, not an installer's.

==> WHY THERE IS NO GLOBAL core.hooksPath

A global `core.hooksPath` pointing at a vetting hook looks like an obvious
extra layer. It is a trap:

  * `core.hooksPath` set in a repo's own `.git/config` OVERRIDES the global
    value. husky (v9) and simple-git-hooks both set exactly that, and so does
    anything an attacker adds.
  * So the global hook silently stops running in precisely the repos that use
    hook managers -- i.e. the modern JS repos this campaign targets -- while
    still appearing installed when you check `git config --global`.
  * A control that fails silently, and fails hardest where the risk is
    highest, is worse than no control: it buys false confidence.

The layers that actually hold are: `safe-clone` (scan before a working tree
ever exists), the daily launchd sweep, and the GitHub Actions workflow.
`scan.py tree` also reports repo-local `core.hooksPath`, fsmonitor and
sshCommand settings, plus any non-sample file in `.git/hooks/`, so a hijacked
hook path shows up as a finding instead of running unnoticed.

==> NEXT

    scan-repo                      # scan the repo you are standing in
    scan-repo --tree-only          # skip the history sweep
    safe-clone git@github.com:example-org/example-repo.git
    tail -f ~/Library/Logs/malware-scan/scan-$(date +%Y-%m-%d).log

    ./install.sh --uninstall       # undo everything above

EOF
say "Done."
