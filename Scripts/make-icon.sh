#!/bin/sh
# Copyright (c) 2026, LunLink contributors
# SPDX-License-Identifier: BSD-2-Clause
#
# Creates the icon of the application.
#
# usage: make-icon.sh <output.icns>

set -e

OUTPUT="$1"
WORK="$(dirname "$OUTPUT")/icon-work"
SCRIPTS="$(cd "$(dirname "$0")" && pwd)"

rm -rf "$WORK"
mkdir -p "$WORK/AppIcon.iconset"

swiftc -O -o "$WORK/make-icon" "$SCRIPTS/make-icon.swift"
"$WORK/make-icon" "$WORK/AppIcon.iconset"
iconutil -c icns -o "$OUTPUT" "$WORK/AppIcon.iconset"

rm -rf "$WORK"
