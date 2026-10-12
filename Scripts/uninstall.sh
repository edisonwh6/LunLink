#!/bin/sh
# Copyright (c) 2026, LunLink contributors
# SPDX-License-Identifier: BSD-2-Clause
#
# Removes the LunLink application.  The configuration and the CHAP
# secrets in the keychain are left alone (see the end of this script).
#
# usage: uninstall.sh [<directory>]

PREFIX="${1:-$HOME/Applications}"
DESTINATION="$PREFIX/LunLink.app"
TOOL="$DESTINATION/Contents/MacOS/iscsictl"

if [ -x "$TOOL" ]; then
    if "$TOOL" list targets 2>/dev/null | grep -q -E "<(active|recovering)"; then
        echo "Targets are connected. Disconnect them before removing the initiator." >&2
        exit 1
    fi

    # (The copy at this place, not another one that may be running)
    if pgrep -f "$DESTINATION/Contents/MacOS/LunLink" >/dev/null 2>&1; then
        osascript -e "tell application \"$DESTINATION\" to quit" >/dev/null 2>&1 || true
    fi

    "$TOOL" daemon uninstall >/dev/null 2>&1 || true
    "$TOOL" daemon stop >/dev/null 2>&1 || true
fi

rm -rf "$DESTINATION"

echo "Removed $DESTINATION"
echo
echo "Your configuration was kept. To remove it as well:"
echo "    defaults delete io.github.edisonwh6.LunLink"
echo "    rm -rf \"$HOME/Library/Application Support/LunLink\" \"$HOME/Library/Logs/LunLink\""
echo "CHAP secrets are stored in your login keychain under the service \"LunLink\"."
