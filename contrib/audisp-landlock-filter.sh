#!/bin/sh
# Filter audisp records to extract only Landlock access denials.
#
# audisp pipes all audit records to this script's stdin.
# We match LANDLOCK_ACCESS (type 1423) and append to a per-user log.
#
# The log path should match what you pass to:
#   gleisner record --kernel-audit-log <path>

LOG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/gleisner"
LOG_FILE="$LOG_DIR/landlock-audit.log"

mkdir -p "$LOG_DIR"

while IFS= read -r line; do
    case "$line" in
        *"UNKNOWN[1423]"* | *"LANDLOCK_ACCESS"*)
            printf '%s\n' "$line" >> "$LOG_FILE"
            ;;
    esac
done
