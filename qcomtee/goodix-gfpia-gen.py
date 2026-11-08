#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate, but never send, known Goodix gfpia request/payload pairs."""

import argparse
import datetime
import hashlib
import os
import struct
import sys
from pathlib import Path


REQUEST_SIZE = 0x80
PAYLOAD_SIZES = {
    "1000": 0x280,
    "1001": 0x168,
    "1005": 0x74,
    "1014": 0x270,
    "1060": 0x6C,
}

# The HAL sends ordinary commands as class 1 and factory-test commands,
# including untrusted enrolment, as class 3.
CLASS_NORMAL = 1
CLASS_TEST = 3

PIANO_ACTIVE_GROUP_PATH = b"/data/vendor_de/0/fpdata"

PIANO_MODEL_LOGICAL_SIZE = 0x124FF4
PIANO_MODEL_CHUNK_SIZE = 0x7CF9C
PIANO_MODEL_PAYLOAD_SIZE = 0x7D014
PIANO_MODEL_DATA_OFFSET = 0x6C
PIANO_MODEL_CHUNK_OFFSET = 0x7D008
PIANO_MODEL_TOTAL_OFFSET = 0x7D00C
PIANO_MODEL_COMMAND_OFFSET = 0x7D010
PIANO_MODEL_COMMAND = 1111
PIANO_TRANSPORT_COMMAND = 1113
PIANO_CAP_S_SIZE = 0x4B540
PIANO_CAP_S_SHA256 = (
    "01829194c8a1e00b7bf1cc0440043bc5ee45057791f1f1ab410f8119bc10ae4e"
)
PIANO_MISTOUCH_SIZE = 0x48C88
PIANO_MISTOUCH_SHA256 = (
    "422741920cb2a0e508241e9d1b7c824f7304f15e638b1576423c6fb99f99ec71"
)


class GeneratorError(Exception):
    pass


def ranged_integer(name, minimum, maximum):
    def parse(value):
        try:
            number = int(value, 0)
        except ValueError as error:
            raise argparse.ArgumentTypeError(
                f"{name} must be an integer"
            ) from error
        if number < minimum or number > maximum:
            raise argparse.ArgumentTypeError(
                f"{name} must be in the range {minimum:#x}..{maximum:#x}"
            )
        return number

    return parse


u8 = ranged_integer("value", 0, 0xFF)
u32 = ranged_integer("value", 0, 0xFFFFFFFF)
time_ms = ranged_integer("time-ms", 0, 86_399_999)
log_level = ranged_integer("log-level", 0, 4)


def milliseconds_since_local_midnight():
    now = datetime.datetime.now()
    return (
        ((now.hour * 60 + now.minute) * 60 + now.second) * 1000
        + now.microsecond // 1000
    )


def build_request(
    command, token, payload_size, request_time, log_level,
    command_class=CLASS_NORMAL,
):
    request = bytearray(REQUEST_SIZE)

    # Bytes 0..7 remain zero for QSEEComCompat to patch with the memory object.
    struct.pack_into("<I", request, 0x08, token)
    struct.pack_into("<I", request, 0x0C, command_class)
    struct.pack_into("<Q", request, 0x10, request_time)
    struct.pack_into("<I", request, 0x18, log_level)
    struct.pack_into("<I", request, 0x20, command)
    struct.pack_into("<I", request, 0x24, payload_size)
    return bytes(request)


def read_otp(path):
    if path is None:
        return b""

    try:
        data = path.read_bytes()
    except OSError as error:
        raise GeneratorError(f"cannot read OTP file {path}: {error}") from error
    if len(data) > 0xC0:
        raise GeneratorError(
            f"OTP file is {len(data):#x} bytes; maximum is 0xc0"
        )
    return data


def build_payload(args):
    payload = bytearray(PAYLOAD_SIZES[args.command])

    # ta_elapsed at 0x48 is an output and must enter the TA as zero.
    struct.pack_into("<I", payload, 0x44, args.sequence)

    if args.command == "1000":
        struct.pack_into("<I", payload, 0x278, args.probe_level)
    elif args.command == "1001":
        otp = read_otp(args.otp)
        payload[0x6C] = 0 if args.fw_info_from_device else args.fw_info
        payload[0x98 : 0x98 + len(otp)] = otp
        struct.pack_into("<I", payload, 0x158, len(otp))
    elif args.command == "1005":
        # Orientation and navigation polarity at 0x6c/0x6e are TA outputs.
        struct.pack_into("<I", payload, 0x70, args.dump_enabled)
    elif args.command == "1060":
        # Untrusted enrolment sends the common prefix and nothing else.
        pass
    else:
        raise GeneratorError(f"unsupported command {args.command}")

    return bytes(payload)


def read_exact_model(path, expected_size, expected_digest, description):
    try:
        data = path.read_bytes()
    except OSError as error:
        raise GeneratorError(f"cannot read {description} {path}: {error}") from error

    digest = hashlib.sha256(data).hexdigest()
    if len(data) != expected_size or digest != expected_digest:
        raise GeneratorError(
            f"{description} must be the reviewed Piano image "
            f"({expected_size:#x} bytes, sha256 {expected_digest}); "
            f"got {len(data):#x} bytes, sha256 {digest}"
        )
    return data


def build_piano_logical_models(cap_s, mistouch):
    asp = bytearray(PIANO_MODEL_LOGICAL_SIZE)
    asp[0x70 : 0x70 + len(cap_s)] = cap_s
    struct.pack_into("<I", asp, 0x1248B8, len(cap_s))

    palm = bytearray(PIANO_MODEL_LOGICAL_SIZE)
    struct.pack_into("<I", palm, 0x6C, 1)
    palm[0x70 : 0x70 + len(mistouch)] = mistouch
    struct.pack_into("<I", palm, 0x124FF0, len(mistouch) // 4)
    return bytes(asp), bytes(palm)


def build_piano_model_payload(logical_model, chunk_index, sequence):
    payload = bytearray(PIANO_MODEL_PAYLOAD_SIZE)
    start = chunk_index * PIANO_MODEL_CHUNK_SIZE
    chunk = logical_model[start : start + PIANO_MODEL_CHUNK_SIZE]

    struct.pack_into("<I", payload, 0x44, sequence)
    payload[
        PIANO_MODEL_DATA_OFFSET : PIANO_MODEL_DATA_OFFSET + len(chunk)
    ] = chunk
    payload[PIANO_MODEL_CHUNK_OFFSET] = chunk_index
    struct.pack_into(
        "<I", payload, PIANO_MODEL_TOTAL_OFFSET, PIANO_MODEL_LOGICAL_SIZE
    )
    struct.pack_into(
        "<I", payload, PIANO_MODEL_COMMAND_OFFSET, PIANO_MODEL_COMMAND
    )
    return bytes(payload)


def write_new_file(path, data):
    created = False
    fd = None
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(fd, "wb") as output:
            fd = None
            output.write(data)
    except FileExistsError as error:
        raise GeneratorError(f"refusing to overwrite {path}") from error
    except OSError as error:
        if fd is not None:
            os.close(fd)
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise GeneratorError(f"cannot write {path}: {error}") from error


def write_pair(request_path, request, payload_path, payload):
    if os.path.abspath(request_path) == os.path.abspath(payload_path):
        raise GeneratorError("request and payload output paths must differ")
    if request_path.exists():
        raise GeneratorError(f"refusing to overwrite {request_path}")
    if payload_path.exists():
        raise GeneratorError(f"refusing to overwrite {payload_path}")

    request_created = False
    try:
        write_new_file(request_path, request)
        request_created = True
        write_new_file(payload_path, payload)
    except Exception:
        if request_created:
            try:
                request_path.unlink()
            except OSError:
                pass
        raise


def write_piano_sequence(output_dir, files):
    created = []
    try:
        output_dir.mkdir(mode=0o700)
    except FileExistsError as error:
        raise GeneratorError(
            f"refusing to use existing directory {output_dir}"
        ) from error
    except OSError as error:
        raise GeneratorError(
            f"cannot create output directory {output_dir}: {error}"
        ) from error

    try:
        for name, data in files:
            path = output_dir / name
            write_new_file(path, data)
            created.append(path)

        checksums = "".join(
            f"{hashlib.sha256(data).hexdigest()}  {name}\n"
            for name, data in files
        ).encode("ascii")
        checksum_path = output_dir / "SHA256SUMS"
        write_new_file(checksum_path, checksums)
        created.append(checksum_path)
    except Exception:
        for path in reversed(created):
            try:
                path.unlink()
            except OSError:
                pass
        try:
            output_dir.rmdir()
        except OSError:
            pass
        raise


def build_piano_sequence(
    args, request_time, set_active_group, enroll_probe=False
):
    cap_s = read_exact_model(
        args.cap_s_model,
        PIANO_CAP_S_SIZE,
        PIANO_CAP_S_SHA256,
        "CAP_S_2 model",
    )
    mistouch = read_exact_model(
        args.mistouch_model,
        PIANO_MISTOUCH_SIZE,
        PIANO_MISTOUCH_SHA256,
        "Piano mistouch model",
    )
    asp, palm = build_piano_logical_models(cap_s, mistouch)

    files = []

    def append_pair(
        stem, command, token, payload, command_class=CLASS_NORMAL
    ):
        request = build_request(
            command,
            token,
            len(payload),
            request_time,
            args.log_level,
            command_class,
        )
        files.extend(
            (
                (f"request-{stem}.bin", request),
                (f"payload-{stem}.bin", payload),
            )
        )

    payload_1000 = bytearray(PAYLOAD_SIZES["1000"])
    struct.pack_into("<I", payload_1000, 0x278, 4)
    append_pair("1000", 1000, 1, bytes(payload_1000))

    payload_1001 = bytearray(PAYLOAD_SIZES["1001"])
    struct.pack_into("<I", payload_1001, 0x44, 1)
    append_pair("1001", 1001, 2, bytes(payload_1001))

    token = 3
    sequence = 2
    for model_name, logical_model in (("asp", asp), ("palm", palm)):
        for chunk_index in range(3):
            payload = build_piano_model_payload(
                logical_model, chunk_index, sequence
            )
            append_pair(
                f"1113-{model_name}-{chunk_index}",
                PIANO_TRANSPORT_COMMAND,
                token,
                payload,
            )
            token += 1
            sequence += 1

    payload_1005 = bytearray(PAYLOAD_SIZES["1005"])
    struct.pack_into("<I", payload_1005, 0x44, sequence)
    append_pair("1005", 1005, token, bytes(payload_1005))

    if set_active_group:
        payload_1014 = bytearray(PAYLOAD_SIZES["1014"])
        struct.pack_into("<I", payload_1014, 0x44, sequence + 1)
        struct.pack_into("<I", payload_1014, 0x6C, 0)
        payload_1014[0x70 : 0x70 + len(PIANO_ACTIVE_GROUP_PATH)] = (
            PIANO_ACTIVE_GROUP_PATH
        )
        append_pair("1014", 1014, token + 1, bytes(payload_1014))

    if enroll_probe:
        # GF_CMD_TEST_UNTRUSTED_ENROLL carries nothing but the common prefix:
        # gf_hal_test_invoke_command_ex() callocs 0x6c bytes and sends them
        # untouched.
        payload_1060 = bytearray(PAYLOAD_SIZES["1060"])
        struct.pack_into("<I", payload_1060, 0x44, sequence + 2)
        append_pair(
            "1060", 1060, token + 2, bytes(payload_1060), CLASS_TEST
        )
    return files


def add_common_arguments(parser):
    parser.add_argument("--sequence", required=True, type=u32)
    parser.add_argument("--token", required=True, type=u32)
    parser.add_argument(
        "--time-ms",
        type=time_ms,
        default=None,
        help="local milliseconds since midnight (default: current local time)",
    )
    parser.add_argument("--log-level", type=log_level, default=0)
    parser.add_argument("--request-out", required=True, type=Path)
    parser.add_argument("--payload-out", required=True, type=Path)


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "generate offline Goodix gfpia request and payload files; "
            "this program has no device or TEE transport support"
        )
    )
    common = argparse.ArgumentParser(add_help=False)
    add_common_arguments(common)
    commands = parser.add_subparsers(dest="command", required=True)

    command_1000 = commands.add_parser(
        "1000", parents=[common], help="generate a sensor probe request"
    )
    command_1000.add_argument(
        "--probe-level", required=True, type=int, choices=(1, 2, 3, 4)
    )

    command_1001 = commands.add_parser(
        "1001", parents=[common], help="generate a sensor information request"
    )
    fw_info = command_1001.add_mutually_exclusive_group(required=True)
    fw_info.add_argument("--fw-info", type=u8)
    fw_info.add_argument(
        "--fw-info-from-device",
        action="store_true",
        help="leave a zero placeholder for the sequence client to fill",
    )
    command_1001.add_argument(
        "--otp", type=Path, help="optional cached OTP bytes (at most 0xc0 bytes)"
    )

    command_1005 = commands.add_parser(
        "1005", parents=[common], help="generate a final initialization request"
    )
    command_1005.add_argument(
        "--dump-enabled", required=True, type=int, choices=(0, 1)
    )

    commands.add_parser(
        "1060",
        parents=[common],
        help="generate an untrusted enrolment request (factory-test class 3)",
    )

    piano_init = commands.add_parser(
        "piano-init",
        help="generate the fixed Piano 1000/1001/model/1005 input directory",
    )
    piano_init.add_argument("--cap-s-model", required=True, type=Path)
    piano_init.add_argument("--mistouch-model", required=True, type=Path)
    piano_init.add_argument("--time-ms", type=time_ms, default=None)
    piano_init.add_argument("--log-level", type=log_level, default=0)
    piano_init.add_argument("--output-dir", required=True, type=Path)

    piano_active_group = commands.add_parser(
        "piano-active-group",
        help="generate Piano initialization followed by the fixed main-user group",
    )
    piano_active_group.add_argument("--cap-s-model", required=True, type=Path)
    piano_active_group.add_argument(
        "--mistouch-model", required=True, type=Path
    )
    piano_active_group.add_argument("--time-ms", type=time_ms, default=None)
    piano_active_group.add_argument("--log-level", type=log_level, default=0)
    piano_active_group.add_argument("--output-dir", required=True, type=Path)

    piano_enroll_probe = commands.add_parser(
        "piano-enroll-probe",
        help="generate the active-group sequence plus one untrusted enrolment",
    )
    piano_enroll_probe.add_argument("--cap-s-model", required=True, type=Path)
    piano_enroll_probe.add_argument(
        "--mistouch-model", required=True, type=Path
    )
    piano_enroll_probe.add_argument("--time-ms", type=time_ms, default=None)
    piano_enroll_probe.add_argument("--log-level", type=log_level, default=0)
    piano_enroll_probe.add_argument("--output-dir", required=True, type=Path)
    return parser


def describe(path, data):
    digest = hashlib.sha256(data).hexdigest()
    print(f"{path}: {len(data):#x} bytes, sha256 {digest}")


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        request_time = (
            milliseconds_since_local_midnight()
            if args.time_ms is None
            else args.time_ms
        )
        if args.command in (
            "piano-init", "piano-active-group", "piano-enroll-probe"
        ):
            files = build_piano_sequence(
                args,
                request_time,
                args.command != "piano-init",
                args.command == "piano-enroll-probe",
            )
            write_piano_sequence(args.output_dir, files)
            for name, data in files:
                describe(args.output_dir / name, data)
            describe(
                args.output_dir / "SHA256SUMS",
                (args.output_dir / "SHA256SUMS").read_bytes(),
            )
            return 0
        payload = build_payload(args)
        request = build_request(
            int(args.command),
            args.token,
            len(payload),
            request_time,
            args.log_level,
            CLASS_TEST if args.command == "1060" else CLASS_NORMAL,
        )
        write_pair(args.request_out, request, args.payload_out, payload)
    except GeneratorError as error:
        parser.error(str(error))

    describe(args.request_out, request)
    describe(args.payload_out, payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
