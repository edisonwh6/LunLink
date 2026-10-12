#!/usr/bin/env python3
# Copyright (c) 2026, LunLink contributors
# SPDX-License-Identifier: BSD-2-Clause

"""End-to-end tests of the iSCSI initiator.

The tests run the daemon and the command-line tool from the build directory
against mock targets (see mocktarget.py), in an environment of their own:
preferences, secrets and run-time files are kept apart from those of the
user.  Disks do get attached to the system for real, which is the point.

    make test                      # all tests
    Tests/run_tests.py -k recovery # tests whose names match
"""

import hashlib
import os
import plistlib
import random
import re
import signal
import subprocess
import sys
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, "build")
RUN = os.environ.get("ISCSI_TEST_RUN_DIR") or os.path.join(BUILD, "test")
ISCSID = os.path.join(BUILD, "iscsid")
ISCSICTL = os.path.join(BUILD, "iscsictl")
DOMAIN = "io.github.edisonwh6.LunLink.test"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mocktarget import Config, MockTarget  # noqa: E402

ENVIRONMENT = dict(os.environ,
                   ISCSI_RUNTIME_DIR=RUN,
                   ISCSI_SECRETS_FILE=os.path.join(RUN, "secrets.plist"),
                   ISCSI_PREFERENCES_DOMAIN=DOMAIN,
                   ISCSI_RECOVERY_TIMEOUT="8",
                   ISCSI_LAUNCH_AGENT_LABEL="io.github.edisonwh6.LunLink.iscsid.test")

MiB = 1 << 20


def ctl(*arguments, secret=None, check=False):
    """Runs iscsictl; returns its exit status and output."""
    result = subprocess.run([ISCSICTL, *arguments], env=ENVIRONMENT, capture_output=True, text=True,
                            input=(secret + "\n") if secret is not None else None, timeout=240)
    output = result.stdout + result.stderr

    if check and result.returncode != 0:
        raise AssertionError(f"iscsictl {' '.join(arguments)} failed ({result.returncode}): {output}")

    return result.returncode, output


def reset_preferences():
    """Removes the preferences of the tests (an empty domain is equivalent to
    one that does not exist, so the file may go once the domain is empty)."""
    subprocess.run(["defaults", "delete", DOMAIN], capture_output=True)

    try:
        os.unlink(os.path.expanduser(f"~/Library/Preferences/{DOMAIN}.plist"))
    except FileNotFoundError:
        pass


class Daemon:
    process = None
    log = None

    @classmethod
    def start(cls):
        os.makedirs(RUN, exist_ok=True)
        cls.log = open(os.path.join(RUN, "iscsid.log"), "ab")
        cls.process = subprocess.Popen([ISCSID, "-d"], env=ENVIRONMENT, stdout=cls.log, stderr=cls.log)

        for _ in range(100):
            if ctl("daemon", "status")[1].find("is running") >= 0:
                return
            time.sleep(0.1)

        raise AssertionError("the daemon did not start")

    @classmethod
    def stop(cls):
        if cls.process and cls.process.poll() is None:
            cls.process.send_signal(signal.SIGTERM)
            try:
                cls.process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                cls.process.kill()
        cls.process = None
        cls.close_log()

    @classmethod
    def close_log(cls):
        if cls.log:
            cls.log.close()
            cls.log = None

    @classmethod
    def kill(cls):
        cls.process.kill()
        cls.process.wait()
        cls.process = None
        cls.close_log()


def wait_until(condition, timeout=30, interval=0.2):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(interval)
    return condition()


class RawDisk:
    """Block-aligned access to a disk through its raw device."""

    def __init__(self, bsd_name, writable=True):
        self.fd = os.open(f"/dev/r{bsd_name}", os.O_RDWR if writable else os.O_RDONLY)

    def write(self, offset, data):
        position = 0
        while position < len(data):
            chunk = data[position:position + MiB]
            written = os.pwrite(self.fd, chunk, offset + position)
            if written != len(chunk):
                raise IOError("short write")
            position += written

    def read(self, offset, length):
        parts = []
        position = 0
        while position < length:
            part = os.pread(self.fd, min(MiB, length - position), offset + position)
            if not part:
                raise IOError("short read")
            parts.append(part)
            position += len(part)
        return b"".join(parts)

    def close(self):
        os.close(self.fd)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class InitiatorTestCase(unittest.TestCase):
    """Base class: each test gets targets of its own and a clean slate."""

    @classmethod
    def setUpClass(cls):
        for path in (ISCSID, ISCSICTL):
            if not os.path.exists(path):
                raise unittest.SkipTest(f"{path} has not been built (run make)")

        # A daemon that an earlier run left behind would get in the way
        ctl("daemon", "stop")
        reset_preferences()
        Daemon.start()

    @classmethod
    def tearDownClass(cls):
        Daemon.stop()

        # The command-line tool starts the daemon on its own account if a
        # test lost the one that it was given; do not leave such behind
        ctl("daemon", "stop")
        subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}/{ENVIRONMENT['ISCSI_LAUNCH_AGENT_LABEL']}.session"],
                       capture_output=True)
        reset_preferences()

    def setUp(self):
        self.targets = []

    def tearDown(self):
        for target in self.targets:
            ctl("logout", target.config.name, "-force")
            ctl("remove", "target", target.config.name)
            target.stop()

    # -- Helpers -----------------------------------------------------------

    def make_target(self, config=None, **options):
        config = config or Config()
        config.name = f"iqn.2026-01.test.mock:{self.id().split('.')[-1].replace('_', '-')}-{len(self.targets)}"
        target = MockTarget(config, **options).start()
        target.advertised = [config.name]
        self.targets.append(target)
        return target

    def add(self, target, *options):
        ctl("add", "target", f"{target.config.name},127.0.0.1:{target.port}", check=True)
        if options:
            ctl("modify", "target-config", target.config.name, *options, check=True)

    def disks(self, target):
        """The BSD names of the disks of a target, by logical unit number."""
        _, output = ctl("list", "luns")
        disks, inside, lun = {}, False, None

        for line in output.splitlines():
            if not line.startswith("\t"):
                inside = line.strip() == target.config.name
            elif inside and line.strip().startswith("LUN "):
                lun = int(line.strip().split()[1].rstrip(":"))
            elif inside and line.strip().startswith("/dev/") and lun is not None:
                disks[lun] = line.strip()[5:]
        return disks

    def login(self, target, *options):
        self.add(target, *options)
        ctl("login", target.config.name, check=True)
        disks = self.disks(target)
        self.assertEqual(len(disks), len(target.luns), "not all logical units were attached")
        return disks

    def logout(self, target):
        ctl("logout", target.config.name, check=True)

    def is_active(self, target):
        _, output = ctl("list", "targets")
        for line in output.splitlines():
            if line.startswith(target.config.name):
                return "<active" in line or "<recovering" in line
        return False

    def backing(self, target, offset, length, lun=0):
        """Reads the data of a logical unit behind the back of the initiator."""
        with open(target.luns[lun].path, "rb") as backing:
            backing.seek(offset)
            return backing.read(length)

    def exercise(self, target, bsd_name, sizes=(512, 4096, 65536, MiB, 3 * MiB + 512), lun=0):
        """Writes, reads back and verifies data in a range of sizes."""
        offset = 4096

        with RawDisk(bsd_name) as disk:
            for size in sizes:
                data = os.urandom(size)
                disk.write(offset, data)
                self.assertEqual(disk.read(offset, size), data, f"read back of {size} bytes differs")
                self.assertEqual(self.backing(target, offset, size, lun), data,
                                 f"{size} bytes did not arrive at the target intact")
                offset += size + 8192

        self.assertEqual(target.protocol_errors, [])


class BasicTests(InitiatorTestCase):
    def test_discovery(self):
        target = self.make_target()
        status, output = ctl("discover", f"127.0.0.1:{target.port}")
        self.assertEqual(status, 0, output)
        self.assertIn(target.config.name, output)
        self.assertIn(f"127.0.0.1 <port {target.port}", output)
        self.assertEqual(target.protocol_errors, [])

    def test_login_io_logout(self):
        target = self.make_target()
        disks = self.login(target)
        self.assertTrue(self.is_active(target))
        self.exercise(target, disks[0])

        # The unit attention that follows a login was dealt with
        self.assertGreaterEqual(target.unit_attentions, 1)

        self.logout(target)
        self.assertFalse(self.is_active(target))
        self.assertFalse(os.path.exists(f"/dev/{disks[0]}"))
        self.assertEqual(target.logouts, 1)

    def test_initiator_name_is_presented(self):
        target = self.make_target()
        self.login(target)
        _, output = ctl("list", "initiator-config")
        self.assertIn(output.splitlines()[0].strip(), target.initiator_names)
        self.logout(target)

    def test_login_twice_is_refused(self):
        target = self.make_target()
        self.login(target)
        status, output = ctl("login", target.config.name)
        self.assertNotEqual(status, 0)
        self.assertIn("active session", output)

    def test_login_to_unreachable_portal(self):
        target = self.make_target()
        target.set_reachable(False)
        self.add(target)
        status, _ = ctl("login", target.config.name)
        self.assertNotEqual(status, 0)
        self.assertFalse(self.is_active(target))

    def test_second_portal_is_used_if_first_is_down(self):
        target = self.make_target()
        ctl("add", "target", f"{target.config.name},127.0.0.2:9", check=True)
        ctl("add", "target", f"{target.config.name},127.0.0.1:{target.port}", check=True)
        ctl("login", target.config.name, check=True)
        self.assertTrue(self.is_active(target))

    def test_multiple_logical_units(self):
        target = self.make_target(lun_sizes=[16 * MiB, 24 * MiB, 32 * MiB])
        disks = self.login(target)
        self.assertEqual(sorted(disks), [0, 1, 2])

        for lun, bsd_name in disks.items():
            self.exercise(target, bsd_name, sizes=(4096, MiB), lun=lun)

    def test_read_only(self):
        target = self.make_target()
        disks = self.login(target, "-read-only", "enable")

        with self.assertRaises(OSError):
            with RawDisk(disks[0]) as disk:
                disk.write(0, os.urandom(4096))

        self.assertEqual(target.bytes_written, 0)

        with RawDisk(disks[0], writable=False) as disk:
            self.assertEqual(disk.read(0, 4096), bytes(4096))

    def test_disk_ejected_by_other_means(self):
        target = self.make_target()
        disks = self.login(target)

        result = subprocess.run(["diskutil", "eject", disks[0]], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(wait_until(lambda: not os.path.exists(f"/dev/{disks[0]}"), timeout=10))

        # The daemon notices, and no longer lays claim to the name of the disk
        _, output = ctl("list", "luns")
        self.assertIn("not attached", output)
        self.assertNotIn(f"/dev/{disks[0]}", output)

        # Logging out and in again brings the disk back
        self.logout(target)
        ctl("login", target.config.name, check=True)
        self.assertEqual(len(self.disks(target)), 1)

    def test_unaligned_io(self):
        target = self.make_target()
        disks = self.login(target)

        # Seed the unit, then go through the file that backs the disk, which
        # (unlike the disk) can be read and written at any offset
        with RawDisk(disks[0]) as disk:
            seed = os.urandom(MiB)
            disk.write(0, seed)

        image = os.path.join(RUN, "Disks", [name for name in os.listdir(os.path.join(RUN, "Disks"))
                                            if target.config.name.split(":")[-1] in name][0])
        expected = bytearray(seed)

        with open(image, "r+b", buffering=0) as handle:
            for offset, size in ((1, 10), (511, 2), (1000, 3000), (70001, 123457)):
                data = os.urandom(size)
                os.pwrite(handle.fileno(), data, offset)
                expected[offset:offset + size] = data

            os.fsync(handle.fileno())
            self.assertEqual(os.pread(handle.fileno(), 200001, 333), bytes(expected[333:200334]))

        self.assertEqual(self.backing(target, 0, MiB), bytes(expected))
        self.assertEqual(target.protocol_errors, [])


class NegotiationTests(InitiatorTestCase):
    """Data is exchanged correctly whatever the target settles on."""

    def run_with(self, sizes=(512, 65536, MiB + 4096), options=(), **settings):
        target = self.make_target(Config(**settings))
        disks = self.login(target, *options)
        self.exercise(target, disks[0], sizes=sizes)
        self.logout(target)
        return target

    def test_r2t_only(self):
        target = self.run_with(initial_r2t=True, immediate_data=False)
        self.assertGreater(target.r2ts, 0)

    def test_immediate_data_and_r2t(self):
        self.run_with(initial_r2t=True, immediate_data=True)

    def test_unsolicited_data(self):
        target = self.run_with(initial_r2t=False, immediate_data=False)
        self.assertGreater(target.data_outs, 0)

    def test_immediate_and_unsolicited_data(self):
        self.run_with(initial_r2t=False, immediate_data=True)

    def test_small_bursts_and_segments(self):
        target = self.run_with(initial_r2t=False, immediate_data=True,
                               first_burst=4096, max_burst=8192, max_recv=1024,
                               sizes=(512, 4096, 65536, 300 * 1024))
        self.assertGreater(target.r2ts, 30)

    def test_first_burst_larger_than_segment(self):
        self.run_with(initial_r2t=False, immediate_data=True, first_burst=65536, max_burst=65536, max_recv=8192)

    def test_separate_status(self):
        self.run_with(phase_collapse=False)

    def test_digests(self):
        target = self.run_with(options=("-HeaderDigest", "CRC32C", "-DataDigest", "CRC32C"),
                               sizes=(512, 65536, 300 * 1024))
        _, output = ctl("list", "target-config", target.config.name)
        self.assertEqual(target.protocol_errors, [])

    def test_digests_declined_by_target(self):
        self.run_with(options=("-HeaderDigest", "CRC32C", "-DataDigest", "CRC32C"),
                      header_digest=False, data_digest=False, sizes=(4096, 65536))

    def test_write_cache_is_flushed(self):
        """What was written is flushed from the cache of the unit, a moment
        after the writes rather than after each of them."""
        target = self.run_with(fua=False)
        self.assertEqual(target.fua_writes, 0)
        self.assertGreater(target.flushes, 0)
        self.assertLess(target.flushes, target.writes)

    def test_sync_writes_bypass_the_cache(self):
        """On request every write is on stable storage when it returns."""
        target = self.run_with(options=("-sync-writes", "enable"))
        self.assertGreater(target.fua_writes, 0)
        self.assertEqual(target.fua_writes, target.writes)

    def test_sync_writes_without_fua(self):
        """... which takes a flush per write if the unit cannot bypass its cache."""
        target = self.run_with(fua=False, options=("-sync-writes", "enable"))
        self.assertEqual(target.fua_writes, 0)
        self.assertGreater(target.flushes, 0)
        self.assertLessEqual(target.flushes, target.writes)

    def test_queued_writes_keep_their_order(self):
        """Writes are acknowledged before they reach the target.  Those that
        overlap have to arrive in the order in which they were made, a read
        has to see what was written before it, and all of it has to be at
        the target once the target is logged out of."""
        target = self.make_target()
        disks = self.login(target)
        base, region = 2 * MiB, 4 * MiB
        model = bytearray(region)
        generator = random.Random(5)

        with RawDisk(disks[0]) as disk:
            disk.write(base, bytes(model))

            for step in range(400):
                size = generator.choice((512, 4096, 65536, 200 * 1024))
                offset = generator.randrange(0, (region - size) // 512) * 512

                if step % 4 == 3:
                    self.assertEqual(disk.read(base + offset, size), bytes(model[offset:offset + size]),
                                     f"step {step}: a read did not see what was written before it")
                else:
                    data = os.urandom(size)
                    disk.write(base + offset, data)
                    model[offset:offset + size] = data

            self.assertEqual(disk.read(base, region), bytes(model))

        self.logout(target)
        self.assertEqual(self.backing(target, base, region), bytes(model))
        self.assertGreater(target.flushes, 0)
        self.assertEqual(target.protocol_errors, [])

    def test_no_write_cache(self):
        """A unit without a write cache needs neither."""
        target = self.run_with(write_cache=False)
        self.assertEqual(target.fua_writes, 0)
        self.assertEqual(target.flushes, 0)

    def test_transfer_limit_of_unit(self):
        target = self.make_target()
        target.max_transfer_blocks = 64
        disks = self.login(target)
        self.exercise(target, disks[0], sizes=(512, MiB))
        self.assertGreater(target.commands, 32)


class AuthenticationTests(InitiatorTestCase):
    def test_chap(self):
        target = self.make_target(Config(chap=("alice", "correct horse battery")))
        self.add(target, "-initiator-authentication", "CHAP", "-initiator-CHAP-name", "alice")
        ctl("modify", "target-config", target.config.name, "-initiator-CHAP-secret",
            secret="correct horse battery", check=True)
        ctl("login", target.config.name, check=True)
        self.assertTrue(self.is_active(target))

    def test_chap_with_wrong_secret(self):
        target = self.make_target(Config(chap=("alice", "correct horse battery")))
        self.add(target, "-initiator-authentication", "CHAP", "-initiator-CHAP-name", "alice")
        ctl("modify", "target-config", target.config.name, "-initiator-CHAP-secret", secret="wrong", check=True)
        status, output = ctl("login", target.config.name)
        self.assertNotEqual(status, 0)
        self.assertIn("Authentication failure", output)
        self.assertFalse(self.is_active(target))

    def test_chap_required_but_not_configured(self):
        target = self.make_target(Config(chap=("alice", "secret-secret-1")))
        self.add(target)
        status, _ = ctl("login", target.config.name)
        self.assertNotEqual(status, 0)
        self.assertFalse(self.is_active(target))

    def test_chap_credentials_of_initiator(self):
        """Targets without credentials of their own use those of the initiator."""
        target = self.make_target(Config(chap=("bob", "initiator-wide-secret")))
        ctl("modify", "initiator-config", "-authentication", "CHAP", "-CHAP-name", "bob", check=True)
        ctl("modify", "initiator-config", "-CHAP-secret", secret="initiator-wide-secret", check=True)

        try:
            self.add(target)
            ctl("login", target.config.name, check=True)
            self.assertTrue(self.is_active(target))
        finally:
            ctl("modify", "initiator-config", "-authentication", "None", check=True)

    def test_secret_follows_initiator_name(self):
        target = self.make_target(Config(chap=("erin", "secret-that-moves")))
        original = ctl("list", "initiator-config")[1].splitlines()[0].strip()

        ctl("modify", "initiator-config", "-authentication", "CHAP", "-CHAP-name", "erin", check=True)
        ctl("modify", "initiator-config", "-CHAP-secret", secret="secret-that-moves", check=True)

        try:
            # Setting the name it already has must not lose the secret either
            ctl("modify", "initiator-config", "-node-name", original, check=True)
            ctl("modify", "initiator-config", "-node-name", "iqn.2026-01.test.mock:renamed-initiator", check=True)
            self.assertIn("CHAP secret: <specified>", ctl("list", "initiator-config")[1])

            self.add(target)
            ctl("login", target.config.name, check=True)
            self.assertIn("iqn.2026-01.test.mock:renamed-initiator", target.initiator_names)
        finally:
            ctl("logout", target.config.name, "-force")
            ctl("modify", "initiator-config", "-authentication", "None", "-node-name", original, check=True)

    def test_mutual_chap(self):
        target = self.make_target(Config(chap=("alice", "initiator-secret-1"),
                                         mutual_chap=("target", "target-secret-22")))
        self.add(target, "-initiator-authentication", "CHAP", "-initiator-CHAP-name", "alice",
                 "-authentication", "CHAP", "-CHAP-name", "target")
        ctl("modify", "target-config", target.config.name, "-initiator-CHAP-secret",
            secret="initiator-secret-1", check=True)
        ctl("modify", "target-config", target.config.name, "-CHAP-secret", secret="target-secret-22", check=True)
        ctl("login", target.config.name, check=True)
        self.assertTrue(self.is_active(target))

    def test_mutual_chap_with_impostor(self):
        """A target that does not know its own secret is turned down."""
        target = self.make_target(Config(chap=("alice", "initiator-secret-1"),
                                         mutual_chap=("target", "not-the-real-secret")))
        self.add(target, "-initiator-authentication", "CHAP", "-initiator-CHAP-name", "alice",
                 "-authentication", "CHAP", "-CHAP-name", "target")
        ctl("modify", "target-config", target.config.name, "-initiator-CHAP-secret",
            secret="initiator-secret-1", check=True)
        ctl("modify", "target-config", target.config.name, "-CHAP-secret", secret="target-secret-22", check=True)
        status, _ = ctl("login", target.config.name)
        self.assertNotEqual(status, 0)
        self.assertFalse(self.is_active(target))


class ApplicationTests(InitiatorTestCase):
    def test_application_support(self):
        """The functions behind the graphical application do what its user asks."""
        helper = os.path.join(BUILD, "appsupport-test")

        if not os.path.exists(helper):
            self.skipTest(f"{helper} has not been built (run make test)")

        target = self.make_target(Config(chap=("carol", "application-secret")))
        result = subprocess.run([helper, target.config.name, f"127.0.0.1:{target.port}", "carol", "application-secret"],
                                env=ENVIRONMENT, capture_output=True, text=True, timeout=240)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(target.protocol_errors, [])


class RecoveryTests(InitiatorTestCase):
    def write_in_background(self, bsd_name, total=24 * MiB):
        """Writes a pattern slowly enough for a failure to hit it mid-way."""
        data = os.urandom(total)
        outcome = {}

        def work():
            try:
                with RawDisk(bsd_name) as disk:
                    for offset in range(0, total, MiB // 4):
                        disk.write(offset, data[offset:offset + MiB // 4])
                        time.sleep(0.02)
                outcome["error"] = None
            except Exception as error:  # noqa: BLE001
                outcome["error"] = error

        thread = threading.Thread(target=work)
        thread.start()
        return data, thread, outcome

    def test_dropped_connection(self):
        target = self.make_target()
        disks = self.login(target)
        data, thread, outcome = self.write_in_background(disks[0])

        time.sleep(0.5)
        target.drop_connections()
        thread.join(timeout=120)

        self.assertFalse(thread.is_alive(), "the writer is stuck")
        self.assertIsNone(outcome["error"])
        self.assertEqual(self.backing(target, 0, len(data)), data)
        self.assertGreaterEqual(target.logins, 2)
        self.assertTrue(self.is_active(target))
        self.assertEqual(target.protocol_errors, [])

    def test_outage(self):
        target = self.make_target()
        disks = self.login(target)
        data, thread, outcome = self.write_in_background(disks[0])

        time.sleep(0.5)
        target.set_reachable(False)
        time.sleep(4)
        _, output = ctl("list", "targets")
        self.assertIn("<recovering", output)
        target.set_reachable(True)
        thread.join(timeout=120)

        self.assertFalse(thread.is_alive(), "the writer is stuck")
        self.assertIsNone(outcome["error"])
        self.assertEqual(self.backing(target, 0, len(data)), data)

        with RawDisk(disks[0]) as disk:
            self.assertEqual(disk.read(0, len(data)), data)

        self.assertEqual(target.protocol_errors, [])

    def test_outage_beyond_recovery_timeout(self):
        target = self.make_target()
        disks = self.login(target, "-persistent", "disable")

        target.set_reachable(False)

        # The session is given up on and its disk is detached
        self.assertTrue(wait_until(lambda: not self.is_active(target), timeout=40))
        self.assertTrue(wait_until(lambda: not os.path.exists(f"/dev/{disks[0]}"), timeout=20))

        # Nothing stands in the way of logging in again later
        target.set_reachable(True)
        ctl("login", target.config.name, check=True)
        self.assertTrue(self.is_active(target))

    def test_persistent_target_is_logged_in_again(self):
        target = self.make_target()
        self.login(target, "-persistent", "enable")

        target.set_reachable(False)
        self.assertTrue(wait_until(lambda: not self.is_active(target), timeout=40))

        target.set_reachable(True)
        self.assertTrue(wait_until(lambda: self.is_active(target), timeout=40))
        self.assertTrue(wait_until(lambda: len(self.disks(target)) == 1, timeout=20))


class FileSystemTests(InitiatorTestCase):
    def volume(self, bsd_name):
        """The mount point of the first mounted volume of a disk."""
        output = subprocess.run(["diskutil", "list", "-plist"], capture_output=True).stdout
        entries = plistlib.loads(output).get("AllDisksAndPartitions", [])

        # The volumes of an APFS container are listed with the container,
        # which refers to the partitions that it resides on
        containers = {}
        for entry in entries:
            for store in entry.get("APFSPhysicalStores", []):
                containers[store.get("DeviceIdentifier")] = entry.get("APFSVolumes", [])

        for entry in entries:
            if entry.get("DeviceIdentifier") != bsd_name:
                continue
            for partition in entry.get("Partitions", []):
                candidates = [partition] + containers.get(partition.get("DeviceIdentifier"), [])
                for candidate in candidates:
                    if candidate.get("MountPoint"):
                        return candidate["MountPoint"]
        return None

    def partitions(self, bsd_name):
        """The partitions of a disk as diskutil describes them."""
        output = subprocess.run(["diskutil", "list", "-plist", bsd_name], capture_output=True).stdout
        entries = plistlib.loads(output).get("AllDisksAndPartitions", [])
        return entries[0].get("Partitions", []) if entries else []

    def test_efi_partition_is_left_alone(self):
        """Only volumes that are meant for the user are mounted: a disk of
        some size is given a partition for EFI when it is formatted, which
        the system keeps out of sight."""
        target = self.make_target(lun_sizes=[8192 * MiB])
        disks = self.login(target)

        result = subprocess.run(["diskutil", "eraseDisk", "APFS", "iSCSITest", "GPT", f"/dev/{disks[0]}"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([p.get("Content") for p in self.partitions(disks[0])], ["EFI", "Apple_APFS"])

        self.logout(target)
        ctl("login", target.config.name, check=True)
        disks = self.disks(target)

        # The disk is the one with the partitions, not the APFS container
        # that the system derives from it (which looks like a disk as well)
        self.assertEqual([p.get("Content") for p in self.partitions(disks[0])], ["EFI", "Apple_APFS"])

        self.assertTrue(wait_until(lambda: self.volume(disks[0]) is not None, timeout=30))
        time.sleep(3)   # whatever else was going to be mounted is mounted by now

        self.assertEqual(os.path.basename(self.volume(disks[0])), "iSCSITest")
        self.assertIsNone(self.partitions(disks[0])[0].get("MountPoint"))
        self.assertEqual(target.protocol_errors, [])

    def test_hfs_volume_survives_logout_and_login(self):
        self.check_volume("JHFS+")

    def test_volume_with_sync_writes(self):
        self.check_volume("JHFS+", sync_writes=True)

    def test_apfs_volume_survives_logout_and_login(self):
        self.check_volume("APFS", size=256 * MiB)

    def test_exfat_volume_survives_logout_and_login(self):
        self.check_volume("ExFAT")

    def check_volume(self, file_system, size=96 * MiB, sync_writes=False):
        target = self.make_target(lun_sizes=[size])
        disks = self.login(target, "-sync-writes", "enable") if sync_writes else self.login(target)

        result = subprocess.run(["diskutil", "eraseDisk", file_system, "iSCSITest", "GPT", f"/dev/{disks[0]}"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        mount_point = self.volume(disks[0])
        self.assertIsNotNone(mount_point)

        payload = os.urandom(20 * MiB)
        path = os.path.join(mount_point, "payload.bin")

        with open(path, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

            # A volume that is in use keeps the target from being logged out
            status, output = ctl("logout", target.config.name)
            self.assertEqual(status, 16, output)
            self.assertTrue(self.is_active(target))

        self.logout(target)
        self.assertFalse(os.path.exists(mount_point))

        if sync_writes:
            # What the file system wrote was made to bypass the write cache
            self.assertGreater(target.fua_writes, 0)
            self.assertEqual(target.fua_writes, target.writes)
        else:
            # ... or was flushed from it before the target was let go
            self.assertEqual(target.fua_writes, 0)
            self.assertGreater(target.flushes, 0)

        # The volume is mounted again when the target is logged in to
        ctl("login", target.config.name, check=True)
        disks = self.disks(target)
        self.assertTrue(wait_until(lambda: self.volume(disks[0]) is not None, timeout=30))

        with open(os.path.join(self.volume(disks[0]), "payload.bin"), "rb") as handle:
            self.assertEqual(hashlib.sha256(handle.read()).digest(), hashlib.sha256(payload).digest())

        self.assertEqual(target.protocol_errors, [])


class DaemonTests(InitiatorTestCase):
    def test_configuration_commands(self):
        target = self.make_target()
        name = target.config.name
        self.add(target, "-auto-login", "enable", "-HeaderDigest", "CRC32C")

        _, output = ctl("list", "target-config", name)
        self.assertIn("Auto-login: enabled", output)
        self.assertIn("HeaderDigest: CRC32C", output)
        self.assertIn("DataDigest: None", output)

        ctl("modify", "target-config", name, "-auto-login", "disable", "-HeaderDigest", "None", check=True)
        _, output = ctl("list", "target-config", name)
        self.assertIn("Auto-login: disabled", output)

        self.assertNotEqual(ctl("modify", "target-config", name, "-MaxConnections", "4")[0], 0)
        self.assertNotEqual(ctl("add", "target", f"{name},127.0.0.1:{target.port}")[0], 0)
        self.assertNotEqual(ctl("add", "target", "not-an-iqn,127.0.0.1")[0], 0)

        ctl("remove", "target", name, check=True)
        self.assertNotIn(name, ctl("list", "targets")[1])

    def test_discovery_portal(self):
        target = self.make_target()
        portal = f"127.0.0.1:{target.port}"

        ctl("add", "discovery-portal", portal, check=True)
        ctl("modify", "discovery-config", "-SendTargets", "enable", "-interval", "60", check=True)

        try:
            self.assertTrue(wait_until(lambda: target.config.name in ctl("list", "targets")[1], timeout=20))
            self.assertIn("dynamic", ctl("list", "targets")[1])

            ctl("login", target.config.name, check=True)
            self.assertTrue(self.is_active(target))
            self.logout(target)
        finally:
            ctl("modify", "discovery-config", "-SendTargets", "disable")
            ctl("remove", "discovery-portal", portal)

        self.assertNotIn(target.config.name, ctl("list", "targets")[1])

    def test_auto_login(self):
        target = self.make_target()
        self.add(target, "-auto-login", "enable")

        Daemon.stop()
        Daemon.start()

        self.assertTrue(wait_until(lambda: self.is_active(target), timeout=30))
        self.assertTrue(wait_until(lambda: len(self.disks(target)) == 1, timeout=20))

    def test_sessions_end_with_daemon(self):
        target = self.make_target()
        disks = self.login(target)

        Daemon.stop()
        self.assertFalse(os.path.exists(f"/dev/{disks[0]}"))
        self.assertEqual(target.logouts, 1)
        Daemon.start()

    def test_bundled_tools_leave_the_daemon_to_launchd(self):
        """Started from within the application bundle, the daemon is a job of
        launchd instead of a child of whoever needed it (which the system
        would hold against the application; see Launcher/launcher.c)."""
        bundled = os.path.join(BUILD, "LunLink.app", "Contents", "MacOS", "iscsictl")

        if not os.path.exists(bundled):
            self.skipTest("the application has not been built (run make)")

        def tool(*arguments):
            result = subprocess.run([bundled, *arguments], env=ENVIRONMENT, capture_output=True, text=True, timeout=120)
            return result.returncode, result.stdout + result.stderr

        job = f"gui/{os.getuid()}/{ENVIRONMENT['ISCSI_LAUNCH_AGENT_LABEL']}.session"
        target = self.make_target()
        Daemon.stop()

        try:
            status, output = tool("daemon", "start")
            self.assertEqual(status, 0, output)

            pid = int(re.search(r"pid (\d+)", tool("daemon", "status")[1]).group(1))
            parent = subprocess.run(["ps", "-o", "ppid=", "-p", str(pid)], capture_output=True, text=True).stdout
            self.assertEqual(int(parent), 1)
            self.assertEqual(subprocess.run(["launchctl", "print", job], capture_output=True).returncode, 0)

            disks = self.login(target)
            self.exercise(target, disks[0], sizes=(4096, MiB))
            self.logout(target)

            # Once the daemon is stopped launchd is rid of the job
            status, output = tool("daemon", "stop")
            self.assertEqual(status, 0, output)
            self.assertIn("is not running", tool("daemon", "status")[1])
            self.assertNotEqual(subprocess.run(["launchctl", "print", job], capture_output=True).returncode, 0)
        finally:
            ctl("logout", target.config.name, "-force")
            tool("daemon", "stop")
            subprocess.run(["launchctl", "bootout", job], capture_output=True)
            Daemon.start()

    def test_launch_agent(self):
        """The daemon can be handed over to launchd, which starts it on demand."""
        target = self.make_target()
        plist = os.path.expanduser("~/Library/LaunchAgents/io.github.edisonwh6.LunLink.iscsid.test.plist")

        status, output = ctl("daemon", "install")

        try:
            self.assertEqual(status, 0, output)
            self.assertTrue(os.path.exists(plist))

            # The daemon that the tests started made way for the one of launchd
            self.assertEqual(Daemon.process.wait(timeout=30), 0)
            self.assertIn("starts at login", ctl("daemon", "status")[1])
            self.assertIn("is running", ctl("daemon", "status")[1])

            disks = self.login(target)
            self.exercise(target, disks[0], sizes=(4096, MiB))
            self.logout(target)

            # Once stopped, the daemon is started again when it is needed
            ctl("daemon", "stop", check=True)
            self.assertIn("is running", ctl("daemon", "status")[1])
        finally:
            ctl("logout", target.config.name, "-force")
            status, output = ctl("daemon", "uninstall")
            Daemon.process = None
            Daemon.close_log()

            if os.path.exists(plist):
                os.unlink(plist)

            Daemon.start()

        self.assertEqual(status, 0, output)
        self.assertIn("does not start at login", ctl("daemon", "status")[1])

    def test_cleanup_after_crash(self):
        target = self.make_target()
        disks = self.login(target)

        Daemon.kill()
        self.assertTrue(os.path.exists(f"/dev/{disks[0]}"))

        # The next instance detaches what the last one left behind
        Daemon.start()
        self.assertTrue(wait_until(lambda: not os.path.exists(f"/dev/{disks[0]}"), timeout=30))

        ctl("login", target.config.name, check=True)
        self.exercise(target, self.disks(target)[0], sizes=(4096, MiB))


class LocalizationTests(unittest.TestCase):
    def test_languages_are_complete(self):
        """Every string of the application exists in every language."""
        import check_localization

        self.assertEqual(check_localization.check(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
