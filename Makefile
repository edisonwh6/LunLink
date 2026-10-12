# Copyright (c) 2026, LunLink contributors
# SPDX-License-Identifier: BSD-2-Clause
#
# Builds the user-space iSCSI initiator: the client library, the daemon
# (iscsid), the command-line tool (iscsictl) and the graphical application.
#
# Only the Xcode Command Line Tools are required (clang and swiftc); neither
# Xcode nor root privileges are needed to build, install or run.

VERSION       := 1.1.0
BUNDLE_ID     := io.github.edisonwh6.LunLink
DEPLOY_TARGET := 13.0

BUILD     := build
OBJ       := $(BUILD)/obj
APP_NAME  := LunLink
APP       := $(BUILD)/$(APP_NAME).app
PREFIX    ?= $(HOME)/Applications

LIB_DIR   := Source/User/iSCSI
D_DIR     := Source/User/iscsid
CTL_DIR   := Source/User/iscsictl
L_DIR     := Source/User/Launcher
APP_DIR   := Source/User/App

CC        := clang
SWIFTC    := swiftc

# "make app DEBUG=1" includes development aids in the application
SWIFT_DEBUG := $(if $(DEBUG),-D DEBUG,)
ARCH      := $(shell uname -m)

CPPFLAGS  := -I$(LIB_DIR) -I$(D_DIR) \
             -DCF_PREFERENCES_APP_ID='"$(BUNDLE_ID)"' \
             -DISCSI_VERSION='"$(VERSION)"'
CFLAGS    := -O2 -g -std=gnu11 -Wall -Wno-deprecated-declarations \
             -Wno-default-const-init-field-unsafe -Wno-unused-function \
             -Wno-gnu-folding-constant -mmacosx-version-min=$(DEPLOY_TARGET)
ifeq ($(ARCH),x86_64)
CFLAGS    += -msse4.2
endif

FRAMEWORKS := -framework CoreFoundation -framework Security -framework IOKit \
              -framework SystemConfiguration

LIB_SRC   := $(wildcard $(LIB_DIR)/*.c)
LIB_OBJ   := $(patsubst $(LIB_DIR)/%.c,$(OBJ)/lib/%.o,$(LIB_SRC))
D_SRC     := $(wildcard $(D_DIR)/*.c)
D_OBJ     := $(patsubst $(D_DIR)/%.c,$(OBJ)/iscsid/%.o,$(D_SRC))
APP_SRC   := $(wildcard $(APP_DIR)/*.swift)
APP_RES   := $(shell find $(APP_DIR)/Resources -type f 2>/dev/null | sed 's/ /\\ /g')
HEADERS   := $(wildcard $(LIB_DIR)/*.h) $(wildcard $(D_DIR)/*.h)

LIB       := $(BUILD)/libiSCSI.a
ISCSID    := $(BUILD)/iscsid
ISCSICTL  := $(BUILD)/iscsictl
LAUNCHER  := $(BUILD)/launcher
APP_BIN   := $(APP)/Contents/MacOS/$(APP_NAME)

.PHONY: all cli app test clean install uninstall dist

all: cli app

cli: $(ISCSID) $(ISCSICTL)

$(OBJ)/lib/%.o: $(LIB_DIR)/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(OBJ)/iscsid/%.o: $(D_DIR)/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(LIB): $(LIB_OBJ)
	@rm -f $@
	ar rcs $@ $^

# The daemon goes by the identifier of the application: macOS grants access to
# the local network per identifier, and what the user allows the application
# has to hold for the daemon, which answers for itself (it is not to depend on
# whichever process started it; see iSCSIDaemonConnectOrLaunch).
$(ISCSID): $(D_OBJ) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(D_OBJ) $(LIB) $(FRAMEWORKS)
	codesign --force --sign - --identifier $(BUNDLE_ID) $@

$(ISCSICTL): $(CTL_DIR)/iscsictl.c $(LIB) $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(CTL_DIR)/iscsictl.c $(LIB) $(FRAMEWORKS)
	codesign --force --sign - --identifier $(BUNDLE_ID).iscsictl $@

# Hands jobs to launchd on behalf of the application (see launcher.c)
$(LAUNCHER): $(L_DIR)/launcher.c
	$(CC) $(CFLAGS) -o $@ $<

# The application bundle carries the daemon and the command-line tool.  Its
# executables are stripped of debugging symbols, which would name the
# directories of whoever built them.
app: $(BUILD)/.app-stamp

$(OBJ)/app/AppSupport.o: $(APP_DIR)/AppSupport.c $(APP_DIR)/AppSupport.h $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) -I$(APP_DIR) $(CFLAGS) -c -o $@ $<

$(BUILD)/AppIcon.icns: Scripts/make-icon.swift
	Scripts/make-icon.sh $@

$(BUILD)/.app-stamp: $(APP_SRC) $(APP_DIR)/BridgingHeader.h $(APP_DIR)/Info.plist \
                     $(OBJ)/app/AppSupport.o $(APP_RES) $(BUILD)/AppIcon.icns \
                     $(LIB) $(ISCSID) $(ISCSICTL) $(LAUNCHER) $(L_DIR)/Info.plist \
                     LICENSE.md NOTICE.md
	@rm -rf "$(APP)"
	@mkdir -p "$(APP)/Contents/MacOS" "$(APP)/Contents/Resources" \
	          "$(APP)/Contents/Helpers/Launcher.app/Contents/MacOS"
	$(SWIFTC) -O $(SWIFT_DEBUG) -swift-version 5 -target $(ARCH)-apple-macos$(DEPLOY_TARGET) \
	    -module-name LunLink -parse-as-library \
	    -import-objc-header $(APP_DIR)/BridgingHeader.h -Xcc -I$(LIB_DIR) -Xcc -I$(APP_DIR) \
	    -o "$(APP_BIN)" $(APP_SRC) $(OBJ)/app/AppSupport.o $(LIB) $(FRAMEWORKS)
	sed -e 's/@VERSION@/$(VERSION)/g' -e 's/@BUNDLE_ID@/$(BUNDLE_ID)/g' \
	    $(APP_DIR)/Info.plist > "$(APP)/Contents/Info.plist"
	cp $(ISCSID) $(ISCSICTL) "$(APP)/Contents/MacOS/"
	cp $(LAUNCHER) "$(APP)/Contents/Helpers/Launcher.app/Contents/MacOS/"
	sed -e 's/@VERSION@/$(VERSION)/g' -e 's/@BUNDLE_ID@/$(BUNDLE_ID)/g' \
	    $(L_DIR)/Info.plist > "$(APP)/Contents/Helpers/Launcher.app/Contents/Info.plist"
	cp -R $(APP_DIR)/Resources/ "$(APP)/Contents/Resources/"
	cp $(BUILD)/AppIcon.icns "$(APP)/Contents/Resources/"
	cp $(D_DIR)/iscsid.8 $(CTL_DIR)/iscsictl.8 "$(APP)/Contents/Resources/"
	cp LICENSE.md NOTICE.md "$(APP)/Contents/Resources/"
	strip -S "$(APP_BIN)" "$(APP)/Contents/MacOS/iscsid" "$(APP)/Contents/MacOS/iscsictl" \
	    "$(APP)/Contents/Helpers/Launcher.app/Contents/MacOS/launcher" 2>/dev/null
	codesign --force --sign - --identifier $(BUNDLE_ID).launcher "$(APP)/Contents/Helpers/Launcher.app"
	codesign --force --sign - --identifier $(BUNDLE_ID) "$(APP)/Contents/MacOS/iscsid"
	codesign --force --sign - --identifier $(BUNDLE_ID).iscsictl "$(APP)/Contents/MacOS/iscsictl"
	codesign --force --sign - --identifier $(BUNDLE_ID) "$(APP)"
	@touch $@
	@echo "Built $(APP)"

# Exports a regular file as a disk (see Tests/fileexport.c)
$(BUILD)/fileexport: Tests/fileexport.c $(D_DIR)/iSCSIBlockExport.c $(D_DIR)/iSCSIBlockExport.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ Tests/fileexport.c $(D_DIR)/iSCSIBlockExport.c

$(BUILD)/appsupport-test: Tests/appsupport_test.c $(OBJ)/app/AppSupport.o $(LIB)
	$(CC) $(CPPFLAGS) -I$(APP_DIR) $(CFLAGS) -o $@ Tests/appsupport_test.c $(OBJ)/app/AppSupport.o $(LIB) $(FRAMEWORKS)

test: all $(BUILD)/appsupport-test
	python3 Tests/run_tests.py

# An archive of the application for handing on.  (The application is signed
# ad hoc, not notarized: on another Mac it has to be let past Gatekeeper once.)
DIST := $(BUILD)/$(APP_NAME)-$(VERSION).zip

dist: all
	@rm -f "$(DIST)"
	ditto -c -k --sequesterRsrc --keepParent "$(APP)" "$(DIST)"
	@echo "Packaged $(DIST)"
	@shasum -a 256 "$(DIST)"

install: all
	Scripts/install.sh "$(APP)" "$(PREFIX)"

uninstall:
	Scripts/uninstall.sh "$(PREFIX)"

clean:
	rm -rf $(BUILD)
