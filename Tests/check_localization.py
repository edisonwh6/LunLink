#!/usr/bin/env python3
# Copyright (c) 2026, LunLink contributors
# SPDX-License-Identifier: BSD-2-Clause

"""Checks that the user interface of the application is complete in every
language that it comes in.

The application is written in English: the keys of its strings are the
English strings themselves.  This script collects

  * the strings that the Swift sources hand to SwiftUI or String(localized:),
  * the messages of the daemon and the client library that the application
    passes on to its user, and
  * the keys of Info.plist that the system shows to the user,

and makes sure that each translation has all of them, has nothing that is no
longer in use, and uses the same placeholders as the original.

    Tests/check_localization.py     # prints what is amiss, if anything
"""

import os
import plistlib
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "Source", "User", "App")
RESOURCES = os.path.join(APP, "Resources")
DEVELOPMENT_LANGUAGE = "en"

# Views and modifiers whose first argument, if it is a string literal, is the
# key of a localized string
LOCALIZING_CALLS = ("Text", "Button", "Label", "Toggle", "Section", "Picker", "TextField", "SecureField",
                    "LabeledContent", "Window", "Menu", "help", "navigationTitle")

# Stands for an interpolated value in a key
PLACEHOLDER = "\x00"


def read_strings(path):
    """The contents of a .strings file as a dictionary."""
    result = subprocess.run(["plutil", "-convert", "xml1", "-o", "-", path], capture_output=True)

    if result.returncode != 0:
        raise ValueError(f"{path}: {result.stdout.decode().strip()}")
    return plistlib.loads(result.stdout)


def scan_literal(source, start):
    """Parses the Swift string literal that begins at source[start]; returns
    its text (with a placeholder for each interpolation) and where it ends."""
    text = []
    position = start + 1

    while source[position] != '"':
        if source[position] != "\\":
            text.append(source[position])
            position += 1
        elif source[position + 1] == "(":
            depth = 1
            position += 2

            while depth:
                if source[position] == '"':
                    position = scan_literal(source, position)[1] - 1
                elif source[position] in "()":
                    depth += 1 if source[position] == "(" else -1
                position += 1
            text.append(PLACEHOLDER)
        else:
            text.append({"n": "\n", "t": "\t"}.get(source[position + 1], source[position + 1]))
            position += 2

    return "".join(text), position + 1


def first_argument_literals(source, start):
    """The string literals of the argument that begins at source[start]
    (there are two if the argument chooses between strings)."""
    literals = []
    depth = 0
    position = start

    while position < len(source):
        character = source[position]

        if character == '"':
            text, position = scan_literal(source, position)
            literals.append(text)
            continue
        if character in "([{":
            depth += 1
        elif character in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif character == "," and depth == 0:
            break
        position += 1

    return literals, source[start:position]


def swift_keys():
    """The keys of the localized strings that the Swift sources refer to,
    each with the place where it occurs."""
    keys = {}
    pattern = re.compile(r"(?:\b|\.)(%s|String)\(" % "|".join(LOCALIZING_CALLS))

    for name in sorted(os.listdir(APP)):
        if not name.endswith(".swift"):
            continue

        source = open(os.path.join(APP, name), encoding="utf-8").read()

        for match in pattern.finditer(source):
            start = match.end()
            label = re.match(r"\s*(\w+)\s*:", source[start:])

            if match.group(1) == "String":
                if not label or label.group(1) != "localized":
                    continue
                start += label.end()
            elif label:
                continue    # Text(verbatim:), Toggle(isOn:), ...

            literals, argument = first_argument_literals(source, start)

            # An argument that is not made of literals alone (as in
            # Text(someString)) is shown as it is
            if not re.match(r'\s*"', argument) and "?" not in argument:
                continue

            for literal in literals:
                if literal:
                    line = source.count("\n", 0, match.start()) + 1
                    keys.setdefault(literal, f"{name}:{line}")
    return keys


def specifiers(string):
    return re.findall(r"%(?:\d+\$)?(?:lld|ld|d|@|f|s)", string)


def matches(key, entry):
    """Whether an entry of a strings file is the one for a key from the
    sources (whose interpolations became format specifiers)."""
    expression = "".join(r"%(?:lld|ld|d|@|f)" if part == PLACEHOLDER else re.escape(part)
                         for part in re.split(f"({PLACEHOLDER})", key))
    return re.fullmatch(expression, entry) is not None


def daemon_messages():
    """The messages of the daemon and of the client library that the
    application shows to its user."""
    messages = {}

    # Why a logical unit could not be attached (a detail may follow a colon)
    manager = open(os.path.join(ROOT, "Source", "User", "iscsid", "iSCSIDiskManager.c"), encoding="utf-8").read()

    for message in re.findall(r'\(disk->error,(?:sizeof\(disk->error\),)?"([^"]+)"', manager):
        messages[message.split(":")[0]] = "iSCSIDiskManager.c"

    # How a target responded to a login
    utilities = open(os.path.join(ROOT, "Source", "User", "iSCSI", "iSCSIUtils.c"), encoding="utf-8").read()
    function = utilities[utilities.index("CFStringRef iSCSIUtilsGetStringForLoginStatus"):]
    function = function[:function.index("\n}")]

    for message in re.findall(r'CFSTR\("([^"]+)"\)', function):
        messages[message] = "iSCSIUtils.c"

    return messages


def check():
    """Returns a list of problems (which is empty if all is well)."""
    problems = []
    languages = sorted(name[:-6] for name in os.listdir(RESOURCES) if name.endswith(".lproj"))
    translations = [language for language in languages if language != DEVELOPMENT_LANGUAGE]

    def table(language, name):
        path = os.path.join(RESOURCES, f"{language}.lproj", f"{name}.strings")

        if not os.path.exists(path):
            problems.append(f"{language}: {name}.strings is missing")
            return {}
        try:
            return read_strings(path)
        except ValueError as error:
            problems.append(str(error))
            return {}

    info = plistlib.load(open(os.path.join(APP, "Info.plist"), "rb"))

    if sorted(info.get("CFBundleLocalizations", [])) != languages:
        problems.append(f"Info.plist: CFBundleLocalizations does not list {', '.join(languages)}")

    # The user interface proper
    keys = swift_keys()

    for language in translations:
        entries = table(language, "Localizable")
        used = set()

        for key, place in sorted(keys.items(), key=lambda item: item[1]):
            found = [entry for entry in entries if matches(key, entry)]

            if not found:
                problems.append(f"{language}: no translation of \"{key.replace(PLACEHOLDER, '%@')}\" ({place})")
            used.update(found)

        for entry in sorted(set(entries) - used):
            problems.append(f"{language}: \"{entry}\" is translated, yet not used by the application")

        for entry, translation in entries.items():
            if sorted(specifiers(entry)) != sorted(specifiers(translation)):
                problems.append(f"{language}: the placeholders of \"{entry}\" and of its translation differ")
            if not translation.strip():
                problems.append(f"{language}: the translation of \"{entry}\" is empty")

    # English is what the keys say, bar the plural forms and such that the
    # table of the development language may hold
    for entry in table(DEVELOPMENT_LANGUAGE, "Localizable"):
        if not any(matches(key, entry) for key in keys):
            problems.append(f"{DEVELOPMENT_LANGUAGE}: \"{entry}\" is not used by the application")

    # Messages of the daemon
    messages = daemon_messages()

    for language in languages:
        entries = table(language, "Daemon")

        for entry in sorted(set(entries) - set(messages)):
            problems.append(f"{language}: Daemon.strings has \"{entry}\", which the daemon does not say")

        if language != DEVELOPMENT_LANGUAGE:
            for message, place in sorted(messages.items()):
                if message not in entries:
                    problems.append(f"{language}: no translation of the message \"{message}\" ({place})")

    # What the system shows on behalf of the application
    reference = table(DEVELOPMENT_LANGUAGE, "InfoPlist")

    for key, value in reference.items():
        if info.get(key) != value:
            problems.append(f"Info.plist and {DEVELOPMENT_LANGUAGE}.lproj/InfoPlist.strings disagree about {key}")

    for key in info:
        if key.endswith("UsageDescription") and key not in reference:
            problems.append(f"{DEVELOPMENT_LANGUAGE}.lproj/InfoPlist.strings lacks {key}")

    for language in translations:
        entries = table(language, "InfoPlist")

        if set(entries) != set(reference):
            difference = ", ".join(sorted(set(entries) ^ set(reference)))
            problems.append(f"{language}: InfoPlist.strings does not have the keys of the English one ({difference})")

    return problems


if __name__ == "__main__":
    found = check()

    for problem in found:
        print(problem)

    print(f"{len(swift_keys())} strings in the sources, {len(daemon_messages())} messages of the daemon: "
          + (f"{len(found)} problems" if found else "all languages are complete"))
    sys.exit(1 if found else 0)
