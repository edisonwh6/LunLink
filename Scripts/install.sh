#!/bin/sh
# Copyright (c) 2026, LunLink contributors
# SPDX-License-Identifier: BSD-2-Clause
#
# Installs the LunLink application, which carries the daemon (iscsid)
# and the command-line tool (iscsictl).  Nothing is installed outside of the
# home directory of the user and no administrator privileges are needed.
#
# An installation that is in use is updated in place: targets that are
# connected are disconnected (never by force: if a volume is in use, nothing
# is changed), and connected again once the new version is in place.
#
# usage: install.sh <application> [<directory>]

set -e

APP="$1"
PREFIX="${2:-$HOME/Applications}"

if [ ! -d "$APP" ]; then
    echo "usage: $0 <application> [<directory>]" >&2
    exit 1
fi

NAME="$(basename "$APP")"
DESTINATION="$PREFIX/$NAME"
TOOL="$DESTINATION/Contents/MacOS/iscsictl"
EXECUTABLE="$DESTINATION/Contents/MacOS/${NAME%.app}"
AGENT="$HOME/Library/LaunchAgents/io.github.edisonwh6.LunLink.iscsid.plist"

CONNECTED=""
DISCONNECTED=""
RUNNING=""

# Connects the targets (one per line) that were disconnected for the update
reconnect() {
    echo "$1" | while IFS= read -r TARGET; do
        [ -n "$TARGET" ] || continue
        echo "Connecting $TARGET again"
        "$TOOL" login "$TARGET" >/dev/null ||
            echo "Could not connect $TARGET; use the application to connect it." >&2
    done
}

if [ -x "$TOOL" ]; then
    # The names of the targets that have a session
    CONNECTED="$("$TOOL" list targets 2>/dev/null | sed -n -E 's/^([^[:space:]]+) <(active|recovering).*$/\1/p')"

    # An installation must not be replaced underneath its sessions
    OLD_IFS="$IFS"
    IFS='
'
    for TARGET in $CONNECTED; do
        echo "Disconnecting $TARGET"

        if ! "$TOOL" logout "$TARGET" >/dev/null 2>&1; then
            echo "A volume of $TARGET is in use. Quit the applications that use it and try again." >&2
            echo "Nothing was installed." >&2
            IFS="$OLD_IFS"
            reconnect "$DISCONNECTED"
            exit 1
        fi
        DISCONNECTED="$DISCONNECTED$TARGET
"
    done
    IFS="$OLD_IFS"

    # The application is asked to quit (the copy at this place, not another
    # one that may be running), and is opened again afterwards
    if pgrep -f "$EXECUTABLE" >/dev/null 2>&1; then
        RUNNING=yes
        osascript -e "tell application \"$DESTINATION\" to quit" >/dev/null 2>&1 || true
    fi

    if [ ! -f "$AGENT" ]; then
        "$TOOL" daemon stop >/dev/null 2>&1 || true
    fi
fi

mkdir -p "$PREFIX"
rm -rf "$DESTINATION"
cp -R "$APP" "$DESTINATION"

# The daemon of a launch agent is started by path, which may have changed
if [ -f "$AGENT" ]; then
    "$TOOL" daemon install
fi

echo "Installed $DESTINATION"

reconnect "$DISCONNECTED"

if [ -n "$RUNNING" ]; then
    open -g "$DESTINATION"
fi

echo
echo "To use the command-line tool, add it to your PATH, for instance:"
echo "    ln -s \"$TOOL\" /usr/local/bin/iscsictl"
echo "To have targets connected automatically when you log in:"
echo "    \"$TOOL\" daemon install"
