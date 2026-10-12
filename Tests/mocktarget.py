#!/usr/bin/env python3
# Copyright (c) 2026, LunLink contributors
# SPDX-License-Identifier: BSD-2-Clause

"""A small iSCSI target for testing the initiator.

The target implements just enough of iSCSI (RFC 7143) and of SCSI to pass
for a disk array: login with optional CHAP (one-way and mutual), SendTargets
discovery, and logical units that are backed by files.  Its negotiation
parameters can be set so as to exercise the various ways in which data is
exchanged (immediate data, unsolicited data, R2T, small data segments,
digests), and it checks that the initiator plays by the rules: violations
are recorded in `protocol_errors`.

It can be run on its own:

    mocktarget.py --port 3260 --lun-size 64

or be driven from Python, which is what the test suite does (see MockTarget).
"""

import argparse
import asyncio
import hashlib
import os
import struct
import tempfile
import threading

RESERVED_TAG = 0xFFFFFFFF

OP_NOP_OUT, OP_SCSI_CMD, OP_LOGIN_REQ, OP_TEXT_REQ, OP_DATA_OUT, OP_LOGOUT_REQ = 0x00, 0x01, 0x03, 0x04, 0x05, 0x06
OP_NOP_IN, OP_SCSI_RSP, OP_LOGIN_RSP, OP_TEXT_RSP, OP_DATA_IN, OP_LOGOUT_RSP = 0x20, 0x21, 0x23, 0x24, 0x25, 0x26
OP_R2T, OP_ASYNC = 0x31, 0x32


def _crc32c_table():
    table = []
    for index in range(256):
        value = index
        for _ in range(8):
            value = (value >> 1) ^ 0x82F63B78 if value & 1 else value >> 1
        table.append(value)
    return table


_CRC_TABLE = _crc32c_table()


def crc32c(data, crc=0):
    crc ^= 0xFFFFFFFF
    table = _CRC_TABLE
    for byte in data:
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def parse_text(data):
    """Parses the key=value pairs of a login or text PDU."""
    pairs = {}
    for item in bytes(data).split(b"\0"):
        if b"=" in item:
            key, value = item.split(b"=", 1)
            pairs[key.decode()] = value.decode()
    return pairs


def build_text(pairs):
    return b"".join(f"{key}={value}".encode() + b"\0" for key, value in pairs)


class ProtocolError(Exception):
    pass


class LogicalUnit:
    """A logical unit backed by a (sparse) file."""

    def __init__(self, size, block_size=512, path=None, read_only=False):
        self.block_size = block_size
        self.block_count = size // block_size
        self.read_only = read_only
        self.owns_file = path is None

        if path is None:
            handle, path = tempfile.mkstemp(prefix="mocktarget-lun-")
            os.close(handle)

        self.path = path
        self.file = open(path, "r+b" if os.path.exists(path) else "w+b")
        self.file.truncate(self.block_count * block_size)

        # A unit attention condition is pending after power on
        self.unit_attention = True

    def read(self, block, count):
        self.file.seek(block * self.block_size)
        return self.file.read(count * self.block_size)

    def write(self, block, data):
        self.file.seek(block * self.block_size)
        self.file.write(data)
        self.file.flush()

    def close(self):
        self.file.close()
        if self.owns_file:
            os.unlink(self.path)


class Config:
    """The behavior of a target."""

    def __init__(self, **options):
        self.name = "iqn.2026-01.test.mock:target0"
        self.alias = "Mock Target"

        # CHAP: (name, secret) of the initiator, and those by which the
        # target identifies itself if the initiator asks (mutual CHAP)
        self.chap = None
        self.mutual_chap = None

        # Whether discovery sessions have to authenticate as well
        self.discovery_auth = False

        # Operational parameters that the target insists on
        self.initial_r2t = True
        self.immediate_data = True
        self.first_burst = 65536
        self.max_burst = 262144
        self.max_recv = 262144
        self.header_digest = True
        self.data_digest = True

        # Whether status is sent along with the last Data-In PDU
        self.phase_collapse = True

        # Whether the logical units have a write cache, and whether they can
        # be told to bypass it for a write (force unit access)
        self.write_cache = True
        self.fua = True

        # Number of commands that may be outstanding
        self.window = 32

        self.__dict__.update(options)


class Connection:
    def __init__(self, target, reader, writer):
        self.target = target
        self.config = target.config
        self.reader = reader
        self.writer = writer

        self.header_digest = False
        self.data_digest = False
        self.stat_sn = 1
        self.exp_cmd_sn = 0
        self.full_feature = False
        self.discovery = False
        self.next_ttt = 1

        # Negotiated values
        self.initiator_max_recv = 8192
        self.initial_r2t = True
        self.immediate_data = True
        self.first_burst = 65536
        self.max_burst = 262144

        # Writes that are waiting for data: ITT -> state
        self.writes = {}

    # -- PDU transport ---------------------------------------------------

    async def read_pdu(self):
        bhs = await self.reader.readexactly(48)
        ahs_length = bhs[4] * 4
        data_length = int.from_bytes(bhs[5:8], "big")
        ahs = await self.reader.readexactly(ahs_length) if ahs_length else b""

        if self.header_digest:
            digest = int.from_bytes(await self.reader.readexactly(4), "little")
            if digest != crc32c(bhs + ahs):
                raise ProtocolError("header digest mismatch")

        data = b""
        if data_length:
            padded = (data_length + 3) & ~3
            data = await self.reader.readexactly(padded)

            if self.data_digest:
                digest = int.from_bytes(await self.reader.readexactly(4), "little")
                if digest != crc32c(data):
                    raise ProtocolError("data digest mismatch")

            data = data[:data_length]

        return bhs, data

    def send_pdu(self, bhs, data=b""):
        bhs = bytearray(bhs)
        bhs[4] = 0
        bhs[5:8] = len(data).to_bytes(3, "big")
        out = bytes(bhs)

        if self.header_digest:
            out += crc32c(bhs).to_bytes(4, "little")

        if data:
            padded = data + b"\0" * (-len(data) % 4)
            out += padded

            if self.data_digest:
                out += crc32c(padded).to_bytes(4, "little")

        self.writer.write(out)

    def sequence_numbers(self, bhs, advance_stat_sn=True):
        struct.pack_into(">III", bhs, 24, self.stat_sn, self.exp_cmd_sn,
                         (self.exp_cmd_sn + self.config.window - 1) & 0xFFFFFFFF)
        if advance_stat_sn:
            self.stat_sn = (self.stat_sn + 1) & 0xFFFFFFFF

    def note_command(self, bhs):
        """Tracks the command sequence number of a request."""
        if bhs[0] & 0x40:
            return
        cmd_sn = struct.unpack_from(">I", bhs, 24)[0]
        if self.full_feature and cmd_sn != self.exp_cmd_sn:
            raise ProtocolError(f"CmdSN {cmd_sn} out of order (expected {self.exp_cmd_sn})")
        self.exp_cmd_sn = (cmd_sn + 1) & 0xFFFFFFFF

    # -- Login -----------------------------------------------------------

    def login_response(self, request, stage_flags, pairs=(), status=(0, 0), tsih=0):
        bhs = bytearray(48)
        bhs[0] = OP_LOGIN_RSP
        bhs[1] = stage_flags
        bhs[2] = bhs[3] = 0
        bhs[8:14] = request[8:14]
        struct.pack_into(">H", bhs, 14, tsih)
        bhs[16:20] = request[16:20]
        self.sequence_numbers(bhs)
        bhs[36], bhs[37] = status
        self.send_pdu(bhs, build_text(pairs))

    async def login(self):
        """Carries out the login phase; returns False if the login failed."""
        config = self.config
        authenticated = False
        chap_challenge = chap_id = None
        first = True
        tsih = 0

        while True:
            bhs, data = await self.read_pdu()

            if bhs[0] & 0x3F != OP_LOGIN_REQ:
                raise ProtocolError("expected a login request")

            pairs = parse_text(data)
            transit = bool(bhs[1] & 0x80)
            current = (bhs[1] >> 2) & 3
            requested = bhs[1] & 3
            response = []

            if first:
                first = False
                self.exp_cmd_sn = struct.unpack_from(">I", bhs, 24)[0]
                self.discovery = pairs.get("SessionType", "Normal") == "Discovery"
                self.target.initiator_names.append(pairs.get("InitiatorName"))

                if not pairs.get("InitiatorName"):
                    self.login_response(bhs, 0, status=(2, 7))
                    return False

                if not self.discovery:
                    if pairs.get("TargetName") != config.name:
                        self.login_response(bhs, 0, status=(2, 3))
                        return False
                    response.append(("TargetAlias", config.alias))
                    response.append(("TargetPortalGroupTag", "1"))

            needs_auth = config.chap is not None and (not self.discovery or config.discovery_auth)

            if current == 0:
                # Security negotiation
                if "AuthMethod" in pairs:
                    offered = pairs["AuthMethod"].split(",")
                    wanted = "CHAP" if needs_auth else "None"

                    if wanted not in offered:
                        if needs_auth or "CHAP" not in offered:
                            self.login_response(bhs, 0, status=(2, 1))
                            return False
                        wanted = "CHAP"

                    response.append(("AuthMethod", wanted))

                    if wanted == "None":
                        authenticated = True

                if "CHAP_A" in pairs:
                    if "5" not in pairs["CHAP_A"].split(","):
                        self.login_response(bhs, 0, status=(2, 1))
                        return False

                    chap_id = os.urandom(1)[0]
                    chap_challenge = os.urandom(16)
                    response += [("CHAP_A", "5"), ("CHAP_I", str(chap_id)),
                                 ("CHAP_C", "0x" + chap_challenge.hex())]

                if "CHAP_R" in pairs:
                    name, secret = config.chap if config.chap else ("", "")
                    expected = hashlib.md5(bytes([chap_id]) + secret.encode() + chap_challenge).hexdigest()
                    received = pairs["CHAP_R"][2:].lower() if pairs["CHAP_R"][:2] in ("0x", "0X") else ""

                    if chap_challenge is None or pairs.get("CHAP_N") != name or received != expected:
                        self.login_response(bhs, 0, status=(2, 1))
                        return False

                    authenticated = True

                    # The initiator wants the target to authenticate itself
                    if "CHAP_C" in pairs:
                        if not config.mutual_chap:
                            self.login_response(bhs, 0, status=(2, 1))
                            return False

                        name, secret = config.mutual_chap
                        challenge = bytes.fromhex(pairs["CHAP_C"][2:])
                        answer = hashlib.md5(bytes([int(pairs["CHAP_I"])]) + secret.encode() + challenge).hexdigest()
                        response += [("CHAP_N", name), ("CHAP_R", "0x" + answer)]

                if transit and not authenticated:
                    if needs_auth:
                        self.login_response(bhs, 0, status=(2, 1))
                        return False
                    authenticated = True

            elif current == 1:
                # Operational negotiation
                if not authenticated and needs_auth:
                    self.login_response(bhs, 0, status=(2, 1))
                    return False

                response += self.negotiate(pairs)
            else:
                raise ProtocolError("invalid login stage")

            if transit:
                flags = 0x80 | (current << 2) | requested

                if requested == 3:
                    tsih = self.target.next_tsih()
                    self.login_response(bhs, flags, response, tsih=tsih)
                    await self.writer.drain()

                    # Digests take effect once the login is concluded
                    self.header_digest, self.data_digest = self.pending_digests
                    self.full_feature = True
                    return True

                self.login_response(bhs, flags, response)
            else:
                self.login_response(bhs, current << 2, response)

            await self.writer.drain()

    pending_digests = (False, False)

    def negotiate(self, pairs):
        config = self.config
        response = []
        header, data = self.pending_digests

        def yes(flag):
            return "Yes" if flag else "No"

        for key, value in pairs.items():
            if key == "HeaderDigest":
                header = config.header_digest and value.split(",")[0] == "CRC32C"
                response.append((key, "CRC32C" if header else "None"))
            elif key == "DataDigest":
                data = config.data_digest and value.split(",")[0] == "CRC32C"
                response.append((key, "CRC32C" if data else "None"))
            elif key == "MaxRecvDataSegmentLength":
                self.initiator_max_recv = int(value)
                response.append((key, str(config.max_recv)))
            elif self.discovery:
                if key in ("DefaultTime2Wait", "DefaultTime2Retain", "ErrorRecoveryLevel"):
                    response.append((key, {"DefaultTime2Wait": "2", "DefaultTime2Retain": "0",
                                           "ErrorRecoveryLevel": "0"}[key]))
            elif key == "InitialR2T":
                self.initial_r2t = config.initial_r2t or value == "Yes"
                response.append((key, yes(self.initial_r2t)))
            elif key == "ImmediateData":
                self.immediate_data = config.immediate_data and value == "Yes"
                response.append((key, yes(self.immediate_data)))
            elif key == "MaxBurstLength":
                self.max_burst = min(config.max_burst, int(value))
                response.append((key, str(self.max_burst)))
            elif key == "FirstBurstLength":
                self.first_burst = min(config.first_burst, int(value))
                response.append((key, str(self.first_burst)))
            elif key == "MaxConnections":
                response.append((key, "1"))
            elif key == "MaxOutstandingR2T":
                response.append((key, "1"))
            elif key in ("DataPDUInOrder", "DataSequenceInOrder"):
                response.append((key, "Yes"))
            elif key == "DefaultTime2Wait":
                response.append((key, "2"))
            elif key == "DefaultTime2Retain":
                response.append((key, "0"))
            elif key == "ErrorRecoveryLevel":
                response.append((key, "0"))

        self.pending_digests = (header, data)
        self.first_burst = min(self.first_burst, self.max_burst)
        return response

    # -- Full feature phase ----------------------------------------------

    async def serve(self):
        while True:
            bhs, data = await self.read_pdu()
            opcode = bhs[0] & 0x3F

            if opcode == OP_SCSI_CMD:
                self.note_command(bhs)
                self.scsi_command(bhs, data)
            elif opcode == OP_DATA_OUT:
                self.data_out(bhs, data)
            elif opcode == OP_NOP_OUT:
                self.nop_out(bhs)
            elif opcode == OP_TEXT_REQ:
                self.text_request(bhs, data)
            elif opcode == OP_LOGOUT_REQ:
                self.note_command(bhs)
                response = bytearray(48)
                response[0] = OP_LOGOUT_RSP
                response[1] = 0x80
                response[16:20] = bhs[16:20]
                self.sequence_numbers(response)
                self.send_pdu(response)
                await self.writer.drain()
                self.target.logouts += 1
                return
            else:
                raise ProtocolError(f"unexpected opcode {opcode:#x}")

            await self.writer.drain()

    def nop_out(self, bhs):
        itt = struct.unpack_from(">I", bhs, 16)[0]
        if itt == RESERVED_TAG:
            return
        response = bytearray(48)
        response[0] = OP_NOP_IN
        response[1] = 0x80
        response[16:20] = bhs[16:20]
        struct.pack_into(">I", response, 20, RESERVED_TAG)
        self.sequence_numbers(response)
        self.send_pdu(response)
        self.target.pings += 1

    def text_request(self, bhs, data):
        pairs = parse_text(data)
        response_pairs = []

        if pairs.get("SendTargets") == "All":
            host, port = self.writer.get_extra_info("sockname")[:2]
            for config in self.target.advertised:
                response_pairs.append(("TargetName", config))
                response_pairs.append(("TargetAddress", f"{host}:{port},1"))

        response = bytearray(48)
        response[0] = OP_TEXT_RSP
        response[1] = 0x80
        response[16:20] = bhs[16:20]
        struct.pack_into(">I", response, 20, RESERVED_TAG)
        self.sequence_numbers(response)
        self.send_pdu(response, build_text(response_pairs))

    def scsi_response(self, itt, status=0, sense=None, residual=0):
        response = bytearray(48)
        response[0] = OP_SCSI_RSP
        response[1] = 0x80 | (0x02 if residual else 0)
        response[3] = status
        struct.pack_into(">I", response, 16, itt)
        self.sequence_numbers(response)
        struct.pack_into(">I", response, 44, residual)

        data = b""
        if sense:
            key, asc, ascq = sense
            fixed = bytearray(18)
            fixed[0], fixed[2], fixed[7], fixed[12], fixed[13] = 0x70, key, 10, asc, ascq
            data = struct.pack(">H", len(fixed)) + fixed

        self.send_pdu(response, data)

    def data_in(self, itt, lun_bytes, payload, expected):
        """Sends data to the initiator, followed by the status."""
        payload = payload[:expected]
        residual = expected - len(payload)
        segment = min(self.initiator_max_recv, self.config.max_recv)
        offset = 0
        data_sn = 0
        collapse = self.config.phase_collapse

        while True:
            chunk = payload[offset:offset + segment]
            last = offset + len(chunk) >= len(payload)

            bhs = bytearray(48)
            bhs[0] = OP_DATA_IN
            bhs[1] = 0x80 if last else 0
            bhs[8:16] = lun_bytes
            struct.pack_into(">II", bhs, 16, itt, RESERVED_TAG)

            if last and collapse:
                bhs[1] |= 0x01 | (0x02 if residual else 0)
                self.sequence_numbers(bhs)
                struct.pack_into(">I", bhs, 44, residual)
            else:
                self.sequence_numbers(bhs, advance_stat_sn=False)
                struct.pack_into(">I", bhs, 24, 0)

            struct.pack_into(">II", bhs, 36, data_sn, offset)
            self.send_pdu(bhs, chunk)

            offset += len(chunk)
            data_sn += 1

            if last:
                break

        if not collapse:
            self.scsi_response(itt, residual=residual)

    def scsi_command(self, bhs, data):
        target = self.target
        itt = struct.unpack_from(">I", bhs, 16)[0]
        expected = struct.unpack_from(">I", bhs, 20)[0]
        lun_bytes = bytes(bhs[8:16])
        lun_number = lun_bytes[1] if lun_bytes[0] == 0 else ((lun_bytes[0] & 0x3F) << 8) | lun_bytes[1]
        cdb = bytes(bhs[32:48])
        opcode = cdb[0]
        is_write = bool(bhs[1] & 0x20)
        final = bool(bhs[1] & 0x80)

        target.commands += 1

        if self.discovery:
            raise ProtocolError("SCSI command in a discovery session")

        # REPORT LUNS and INQUIRY work for any logical unit number
        if opcode == 0xA0:
            entries = b"".join(struct.pack(">BB6x", 0, number) for number in range(len(target.luns)))
            self.data_in(itt, lun_bytes, struct.pack(">I4x", len(entries)) + entries, expected)
            return

        unit = target.luns[lun_number] if lun_number < len(target.luns) else None

        if opcode == 0x12:
            self.inquiry(itt, lun_bytes, cdb, unit, expected)
            return

        if unit is None:
            self.scsi_response(itt, 2, (5, 0x25, 0x00), residual=expected)
            return

        if unit.unit_attention:
            unit.unit_attention = False
            target.unit_attentions += 1
            if is_write:
                self.discard_write(itt, expected, data, final)
            self.scsi_response(itt, 2, (6, 0x29, 0x00), residual=expected)
            return

        if opcode == 0x00:
            self.scsi_response(itt)
        elif opcode == 0x25:
            last = min(unit.block_count - 1, 0xFFFFFFFF)
            self.data_in(itt, lun_bytes, struct.pack(">II", last, unit.block_size), expected)
        elif opcode == 0x9E and cdb[1] & 0x1F == 0x10:
            payload = struct.pack(">QI", unit.block_count - 1, unit.block_size) + bytes(20)
            self.data_in(itt, lun_bytes, payload, expected)
        elif opcode == 0x1A:
            # Mode parameter header followed by the caching page
            page = bytes([0x08, 0x12, 0x04 if self.config.write_cache else 0]) + bytes(17)
            header = bytes([3 + len(page), 0, (0x80 if unit.read_only else 0) | (0x10 if self.config.fua else 0), 0])
            self.data_in(itt, lun_bytes, header + page, expected)
        elif opcode in (0x28, 0x88):
            block, count = self.decode_rw(cdb)
            if block + count > unit.block_count:
                self.scsi_response(itt, 2, (5, 0x21, 0x00), residual=expected)
            else:
                target.bytes_read += count * unit.block_size
                self.data_in(itt, lun_bytes, unit.read(block, count), expected)
        elif opcode in (0x2A, 0x8A):
            block, count = self.decode_rw(cdb)
            length = count * unit.block_size

            if unit.read_only:
                self.discard_write(itt, expected, data, final)
                self.scsi_response(itt, 2, (7, 0x27, 0x00), residual=expected)
            elif block + count > unit.block_count or length != expected:
                self.discard_write(itt, expected, data, final)
                self.scsi_response(itt, 2, (5, 0x21, 0x00), residual=expected)
            else:
                target.writes += 1
                if cdb[1] & 0x08:
                    target.fua_writes += 1
                self.begin_write(itt, lun_bytes, unit, block, expected, data, final)
        elif opcode in (0x35, 0x91):
            target.flushes += 1
            self.scsi_response(itt)
        else:
            self.scsi_response(itt, 2, (5, 0x20, 0x00), residual=expected)

    @staticmethod
    def decode_rw(cdb):
        if cdb[0] in (0x28, 0x2A):
            return struct.unpack_from(">I", cdb, 2)[0], struct.unpack_from(">H", cdb, 7)[0]
        return struct.unpack_from(">Q", cdb, 2)[0], struct.unpack_from(">I", cdb, 10)[0]

    def inquiry(self, itt, lun_bytes, cdb, unit, expected):
        if unit is None:
            # Peripheral qualifier 3: no device at this logical unit number
            self.data_in(itt, lun_bytes, bytes([0x7F]) + bytes(35), expected)
        elif not cdb[1] & 0x01:
            payload = bytearray(36)
            payload[0], payload[2], payload[3], payload[4] = 0x00, 0x05, 0x02, 31
            payload[8:16] = b"MOCK    "
            payload[16:32] = b"Test Disk       "
            payload[32:36] = b"1.0 "
            self.data_in(itt, lun_bytes, bytes(payload), expected)
        elif cdb[2] == 0x80:
            serial = f"MOCK{self.target.luns.index(unit):04d}".encode()
            self.data_in(itt, lun_bytes, bytes([0, 0x80, 0, len(serial)]) + serial, expected)
        elif cdb[2] == 0xB0:
            payload = bytearray(64)
            payload[1], payload[3] = 0xB0, 60
            struct.pack_into(">I", payload, 8, self.target.max_transfer_blocks)
            self.data_in(itt, lun_bytes, bytes(payload), expected)
        else:
            self.scsi_response(itt, 2, (5, 0x24, 0x00), residual=expected)

    # -- Writes ----------------------------------------------------------

    def check_unsolicited(self, immediate, final):
        """Checks the data that accompanies a write command."""
        if immediate and not self.immediate_data:
            raise ProtocolError("immediate data though ImmediateData=No")
        if immediate > self.config.max_recv:
            raise ProtocolError("immediate data exceeds MaxRecvDataSegmentLength")
        if immediate > self.first_burst:
            raise ProtocolError("immediate data exceeds FirstBurstLength")
        if not final and self.initial_r2t:
            raise ProtocolError("unsolicited Data-Out though InitialR2T=Yes")

    def begin_write(self, itt, lun_bytes, unit, block, expected, data, final):
        self.check_unsolicited(len(data), final)

        state = {
            "lun": lun_bytes, "unit": unit, "block": block, "expected": expected,
            "buffer": bytearray(expected), "received": len(data),
            # While unsolicited data is underway no transfer tag is in use
            "ttt": RESERVED_TAG, "burst_end": None if final else min(self.first_burst, expected),
            "discard": False, "r2t_sn": 0, "data_sn": 0,
        }
        state["buffer"][:len(data)] = data
        self.writes[itt] = state

        if final:
            self.continue_write(itt, state)

    def discard_write(self, itt, expected, data, final):
        """Swallows the unsolicited data of a write that was refused."""
        if not final:
            self.writes[itt] = {"discard": True, "ttt": RESERVED_TAG}

    def continue_write(self, itt, state):
        """Asks for the next burst of a write, or completes the write."""
        if state["received"] >= state["expected"]:
            del self.writes[itt]
            state["unit"].write(state["block"], bytes(state["buffer"]))
            self.target.bytes_written += state["expected"]
            self.scsi_response(itt)
            return

        length = min(self.max_burst, state["expected"] - state["received"])
        state["ttt"] = self.next_ttt
        state["burst_end"] = state["received"] + length
        state["data_sn"] = 0
        self.next_ttt += 1

        bhs = bytearray(48)
        bhs[0] = OP_R2T
        bhs[1] = 0x80
        bhs[8:16] = state["lun"]
        struct.pack_into(">II", bhs, 16, itt, state["ttt"])
        self.sequence_numbers(bhs, advance_stat_sn=False)
        struct.pack_into(">III", bhs, 36, state["r2t_sn"], state["received"], length)
        state["r2t_sn"] += 1
        self.send_pdu(bhs)
        self.target.r2ts += 1

    def data_out(self, bhs, data):
        itt, ttt = struct.unpack_from(">II", bhs, 16)
        data_sn, offset = struct.unpack_from(">II", bhs, 36)
        final = bool(bhs[1] & 0x80)
        state = self.writes.get(itt)

        if state is None:
            raise ProtocolError("Data-Out for an unknown task")

        if state["discard"]:
            if final:
                del self.writes[itt]
            return

        if ttt != state["ttt"]:
            raise ProtocolError("Data-Out with the wrong target transfer tag")
        if len(data) > self.config.max_recv:
            raise ProtocolError("Data-Out exceeds MaxRecvDataSegmentLength")
        if offset != state["received"]:
            raise ProtocolError(f"Data-Out at offset {offset}, expected {state['received']}")
        if data_sn != state["data_sn"]:
            raise ProtocolError("Data-Out with the wrong DataSN")
        if offset + len(data) > state["burst_end"]:
            raise ProtocolError("Data-Out exceeds the burst that was allowed")

        state["buffer"][offset:offset + len(data)] = data
        state["received"] += len(data)
        state["data_sn"] += 1
        self.target.data_outs += 1

        if final:
            if ttt != RESERVED_TAG and state["received"] != state["burst_end"]:
                raise ProtocolError("burst ended short of what was asked for")
            self.continue_write(itt, state)


class MockTarget:
    """An iSCSI target that runs on a thread of its own.

        target = MockTarget(Config(chap=("user", "secret")), lun_sizes=[64 << 20])
        target.start()
        ... target.port ...
        target.stop()
    """

    def __init__(self, config=None, lun_sizes=(64 << 20,), block_size=512, host="127.0.0.1", port=0,
                 read_only=False):
        self.config = config or Config()
        self.host = host
        self.port = port
        self.luns = [LogicalUnit(size, block_size, read_only=read_only) for size in lun_sizes]
        self.advertised = [self.config.name]
        self.max_transfer_blocks = 0

        self.protocol_errors = []
        self.initiator_names = []
        self.logins = self.logouts = self.failed_logins = 0
        self.commands = self.r2ts = self.data_outs = self.pings = self.flushes = self.fua_writes = 0
        self.unit_attentions = self.bytes_read = self.bytes_written = self.writes = 0

        self._tsih = 0
        self._loop = None
        self._thread = None
        self._server = None
        self._ready = threading.Event()
        self._connections = set()
        self._refuse = False

    def next_tsih(self):
        self._tsih += 1
        return self._tsih

    # -- Control (callable from any thread) ------------------------------

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait()
        return self

    def stop(self):
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join()
        for unit in self.luns:
            unit.close()

    def drop_connections(self):
        """Severs all connections, as a network failure would."""
        self._loop.call_soon_threadsafe(self._drop)

    def set_reachable(self, reachable):
        """Makes the target refuse (or accept again) new connections."""
        self._refuse = not reachable
        if not reachable:
            self.drop_connections()

    def connection_count(self):
        return len(self._connections)

    # -- Implementation ---------------------------------------------------

    def _drop(self):
        for connection in list(self._connections):
            connection.writer.transport.abort()

    def _run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._server = self._loop.run_until_complete(asyncio.start_server(self._handle, self.host, self.port))
        self.port = self._server.sockets[0].getsockname()[1]
        self._ready.set()

        try:
            self._loop.run_forever()
        finally:
            self._drop()
            self._server.close()
            self._loop.run_until_complete(asyncio.sleep(0.05))
            self._loop.close()

    async def _handle(self, reader, writer):
        if self._refuse:
            writer.transport.abort()
            return

        connection = Connection(self, reader, writer)
        self._connections.add(connection)

        try:
            if await connection.login():
                self.logins += 1
                await connection.serve()
            else:
                self.failed_logins += 1
                await writer.drain()
        except ProtocolError as error:
            self.protocol_errors.append(str(error))
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            self._connections.discard(connection)
            try:
                writer.close()
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(description="A small iSCSI target for testing initiators.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3260)
    parser.add_argument("--name", default=Config().name)
    parser.add_argument("--lun-size", type=int, default=64, help="size of each logical unit, in MiB")
    parser.add_argument("--luns", type=int, default=1, help="number of logical units")
    parser.add_argument("--chap", metavar="NAME:SECRET", help="require CHAP authentication")
    arguments = parser.parse_args()

    config = Config(name=arguments.name)

    if arguments.chap:
        config.chap = tuple(arguments.chap.split(":", 1))

    target = MockTarget(config, [arguments.lun_size << 20] * arguments.luns, host=arguments.host, port=arguments.port)
    target.start()
    print(f"{config.name} is listening on {target.host}:{target.port}")

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        target.stop()


if __name__ == "__main__":
    main()
