#!/usr/bin/env bash
# =============================================================================
# PRE-NUKE RESCUE — /mnt/sshd (EndeavourOS)
# Compresses directories of interest into /mnt/hdd/data/endeavourOS/
# Only includes paths that exist and are non-empty.
# =============================================================================

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
SOURCE="/mnt/sshd"
DEST="/mnt/hdd/data/endeavourOS"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ARCHIVE="$DEST/rescue_${TIMESTAMP}.tar.gz"
LOG="$DEST/rescue_${TIMESTAMP}.log"
TMPLIST=$(mktemp)

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
DIM='\033[2m'
BLD='\033[1m'
RST='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
log()  { echo -e "$1" | tee -a "$LOG"; }
info() { log "  ${CYN}→${RST}  $1"; }
ok()   { log "  ${GRN}✓${RST}  $1"; }
skip() { log "  ${DIM}–  $1 (skipped: $2)${RST}"; }
warn() { log "  ${YLW}⚠${RST}  $1"; }
die()  { log "\n  ${RED}✗  FATAL: $1${RST}\n"; exit 1; }

# Add a path to the archive list only if non-empty
queue() {
    local label="$1"
    local path="$2"

    if [ ! -e "$path" ]; then
        skip "$label" "does not exist"
        return
    fi

    if [ -d "$path" ]; then
        if [ -z "$(find "$path" -mindepth 1 -maxdepth 3 -not -path '*/lost+found*' 2>/dev/null | head -1)" ]; then
            skip "$label" "empty directory"
            return
        fi
    elif [ -f "$path" ]; then
        if [ ! -s "$path" ]; then
            skip "$label" "empty file"
            return
        fi
    fi

    # Strip leading / for tar relative paths
    echo "${path#/}" >> "$TMPLIST"
    ok "$label  ${DIM}(${path})${RST}"
}

# ── Preflight ─────────────────────────────────────────────────────────────────
[ -d "$SOURCE" ] || die "$SOURCE is not mounted or does not exist."
[ -d "$DEST" ]   || { warn "$DEST does not exist — creating it."; mkdir -p "$DEST"; }

# Detect home directories under the mounted partition
HOMES=()
while IFS= read -r d; do
    HOMES+=("$d")
done < <(find "$SOURCE/home" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
[ -d "$SOURCE/root" ] && HOMES+=("$SOURCE/root")

# ── Banner ────────────────────────────────────────────────────────────────────
clear
log ""
log "  ${BLD}PRE-NUKE RESCUE${RST}"
log "  ${DIM}source:  $SOURCE${RST}"
log "  ${DIM}dest:    $ARCHIVE${RST}"
log "  ${DIM}started: $(date)${RST}"
log ""
log "  ${BLD}Home directories found:${RST}"
for h in "${HOMES[@]}"; do log "  ${CYN}·${RST} $h"; done
log ""

# ── Queue: per-user dotfiles ──────────────────────────────────────────────────
log "  ${BLD}── Shell & History ──────────────────────────────────${RST}"
for HOME_DIR in "${HOMES[@]}"; do
    USER=$(basename "$HOME_DIR")
    log "  ${DIM}user: $USER${RST}"
    queue "$USER · .zsh_history"        "$HOME_DIR/.zsh_history"
    queue "$USER · .bash_history"       "$HOME_DIR/.bash_history"
    queue "$USER · .zshrc"              "$HOME_DIR/.zshrc"
    queue "$USER · .bashrc"             "$HOME_DIR/.bashrc"
    queue "$USER · .zprofile"           "$HOME_DIR/.zprofile"
    queue "$USER · .bash_profile"       "$HOME_DIR/.bash_profile"
    queue "$USER · .aliases"            "$HOME_DIR/.aliases"
    queue "$USER · .functions"          "$HOME_DIR/.functions"
    queue "$USER · .exports"            "$HOME_DIR/.exports"
done

log ""
log "  ${BLD}── SSH & GPG ─────────────────────────────────────────${RST}"
for HOME_DIR in "${HOMES[@]}"; do
    USER=$(basename "$HOME_DIR")
    queue "$USER · .ssh"                "$HOME_DIR/.ssh"
    queue "$USER · .gnupg"              "$HOME_DIR/.gnupg"
done

log ""
log "  ${BLD}── Application Config ───────────────────────────────${RST}"
for HOME_DIR in "${HOMES[@]}"; do
    USER=$(basename "$HOME_DIR")
    queue "$USER · .config"             "$HOME_DIR/.config"
    queue "$USER · .local/share"        "$HOME_DIR/.local/share"
    queue "$USER · .local/bin"          "$HOME_DIR/.local/bin"
    queue "$USER · .netrc"              "$HOME_DIR/.netrc"
    queue "$USER · .npmrc"              "$HOME_DIR/.npmrc"
    queue "$USER · .pypirc"             "$HOME_DIR/.pypirc"
    queue "$USER · .gitconfig"          "$HOME_DIR/.gitconfig"
    queue "$USER · .mozilla"            "$HOME_DIR/.mozilla"
    queue "$USER · chromium"            "$HOME_DIR/.config/chromium"
    queue "$USER · google-chrome"       "$HOME_DIR/.config/google-chrome"
done

log ""
log "  ${BLD}── Desktop & Downloads ──────────────────────────────${RST}"
for HOME_DIR in "${HOMES[@]}"; do
    USER=$(basename "$HOME_DIR")
    queue "$USER · Desktop"             "$HOME_DIR/Desktop"
    queue "$USER · Downloads"           "$HOME_DIR/Downloads"
done

log ""
log "  ${BLD}── System Files ─────────────────────────────────────${RST}"
queue "systemd units"                   "$SOURCE/etc/systemd/system"
queue "fstab"                           "$SOURCE/etc/fstab"
queue "hosts"                           "$SOURCE/etc/hosts"
queue "cron.d"                          "$SOURCE/etc/cron.d"
queue "cron.daily"                      "$SOURCE/etc/cron.daily"
queue "cron.weekly"                     "$SOURCE/etc/cron.weekly"
queue "crontabs (spool)"                "$SOURCE/var/spool/cron"
queue "usr/local/bin"                   "$SOURCE/usr/local/bin"
queue "srv (compose stacks)"            "$SOURCE/srv"

log ""
log "  ${BLD}── Encrypted Blobs ──────────────────────────────────${RST}"
info "Scanning for .kdbx / .age / .gpg files..."
BLOBS=$(find "$SOURCE" \( -name "*.kdbx" -o -name "*.age" -o -name "*.gpg" \) \
        -not -path "*/proc/*" -not -path "*/sys/*" 2>/dev/null || true)
if [ -n "$BLOBS" ]; then
    while IFS= read -r blob; do
        queue "encrypted blob" "$blob"
    done <<< "$BLOBS"
else
    skip "encrypted blobs" "none found"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
QUEUED=$(wc -l < "$TMPLIST" | tr -d ' ')
log ""
log "  ${BLD}── Summary ───────────────────────────────────────────${RST}"
log "  ${CYN}→${RST}  ${QUEUED} paths queued for archiving"
log ""

if [ "$QUEUED" -eq 0 ]; then
    die "Nothing to archive. Is $SOURCE mounted correctly?"
fi

# ── Archive ───────────────────────────────────────────────────────────────────
info "Creating archive — this may take a while..."
log ""

# Run tar from / so paths are relative to root
tar \
    --create \
    --gzip \
    --file="$ARCHIVE" \
    --directory=/ \
    --files-from="$TMPLIST" \
    --ignore-failed-read \
    --checkpoint=500 \
    --checkpoint-action=dot \
    2>>"$LOG"

log ""
log ""

# ── Final report ──────────────────────────────────────────────────────────────
SIZE=$(du -sh "$ARCHIVE" 2>/dev/null | cut -f1)
log "  ${GRN}${BLD}✓ Archive complete${RST}"
log "  ${DIM}file:    $ARCHIVE${RST}"
log "  ${DIM}size:    $SIZE${RST}"
log "  ${DIM}log:     $LOG${RST}"
log "  ${DIM}ended:   $(date)${RST}"
log ""
log "  ${DIM}Verify with: tar -tzf $ARCHIVE | head -40${RST}"
log ""

# Cleanup
rm -f "$TMPLIST"
