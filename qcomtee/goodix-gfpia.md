# Xiaomi Piano Goodix `gfpia` bring-up notes

This document records the userspace ABI and initialization order recovered
from the Xiaomi Piano stock fingerprint stack. It is intentionally limited to
what static analysis or captured buffers establish. In particular, a TA
return value of zero does not prove that the sensor is usable.

The addresses below are ELF virtual addresses from stock `libgf_hal.so`
(Build ID `3e77582c7e2d0f615af1607f6753b2a4`) or stock `mi_fp.ko`; they are not
runtime addresses and do not include ASLR.

## Safety boundary

`gfpia` uses `QSEECom_send_modified_cmd`, not the plain send operation. The
request's first eight bytes are a QTEE memory-object patch location and must
be zero in the input file. The first fd-info entry identifies the payload
DMA-BUF with offset zero; the other three entries are unused. Never put a
physical address in the request or fd-info array.

The companion `goodix-gfpia-gen.py` program only creates files. It contains no
SSH, ioctl, TEE, QSEECom, or other transport code. It supports the recovered
small commands `1000`, `1001`, and `1005`, plus fixed `piano-init` and
`piano-active-group` directories containing the reviewed Piano model
sequence. It does not expose arbitrary command-1113, group-id, pathname, or
HMAC inputs. It verifies the two selected embedded model hashes and refuses
to overwrite an existing file or directory.

The payload sequence and request token are independent counters. Captures can
make them look adjacent, but there is no established `token = sequence + 1`
rule. Stock `libgf_ca.so` increments its process-global token immediately
before each modified request, while the HAL writes its separate session-local
sequence into payload offset `0x44`. The generator therefore requires both
values explicitly. The reviewed zero-model cold-start path happens to use
token/sequence pairs `1/0`, `2/1`, and `3/2`.
The fixed Piano path uses `1/0`, `2/1`, six model pairs `3/2` through
`8/7`, and final command 1005 at `9/8`. Its fixed active-group extension uses
command 1014 at `10/9`.

## Modified-request envelope

The request is a zero-initialized, 0x80-byte little-endian structure:

| Offset | Size | Meaning |
| ---: | ---: | --- |
| `0x00` | 8 | QTEE memory-object patch field; zero in the file |
| `0x08` | 4 | Request token |
| `0x0c` | 4 | Command class; `1` for these commands |
| `0x10` | 8 | Local milliseconds since midnight |
| `0x18` | 4 | TA log level |
| `0x20` | 4 | Command ID |
| `0x24` | 4 | Exact payload length |

The response is 0x40 bytes. In the stock combined sbuffer it follows the
request, so TA status is at sbuffer offset `0x80` and the transport/auxiliary
error is at `0x84`. In the standalone response file written by
`qcomtee-qseecom`, those fields are at offsets `0x00` and `0x04`. Check the
transport/auxiliary error for zero before interpreting TA status.

Legacy fd-info consists of four entries of this form:

```c
struct gf_fd_info {
	int32_t fd;
	uint32_t offset;
};
```

Only entry zero carries the payload DMA-BUF, at offset zero. The object-based
mainline client expresses the same association as its first QTEE memory
object; it does not synthesize legacy physical addresses.

## Shared payload prefix

All three recovered initialization commands start with this 0x6c-byte prefix:

```c
struct gf_common {
	uint8_t opaque_00[0x44];
	uint32_t sequence;       /* 0x44: maintained by the HAL */
	uint32_t ta_elapsed;     /* 0x48: output; zero on input */
	uint8_t opaque_4c[0x20];
};
```

Unidentified and output-only bytes must start at zero.

### Command 1000: sensor probe

Class is 1 and payload size is 0x280.

| Offset | Size | Direction | Meaning |
| ---: | ---: | --- | --- |
| `0x70` | `0x208` | output | Sensor configuration |
| `0x278` | 4 | input | Probe level |

Normal cold boot probes levels `4, 3, 2, 1`, stopping at the first success.
For the P81/GF3656ZS1 path, a successful configuration starts with byte
`0x31`. Do not turn that observed byte into a general success condition; both
response error fields still take precedence.

### Command 1001: sensor information

Class is 1 and payload size is 0x168.

| Offset | Size | Direction | Meaning |
| ---: | ---: | --- | --- |
| `0x6c` | 1 | input | Byte returned by `GET_FW_INFO` |
| `0x70` | 4 | output | Sensor parameter 0 |
| `0x74` | 4 | output | Sensor parameter 1 |
| `0x78` | 4 | output | Sensor parameter 2 |
| `0x7c` | 4 | output | Sensor parameter 3 |
| `0x80` | 4 | output | Navigation parameter 0 |
| `0x84` | 4 | output | Navigation parameter 1 |
| `0x88` | 16 | output | Chip information |
| `0x98` | `0xc0` | input/output | Optional cached OTP bytes |
| `0x158` | 4 | input/output | OTP length, at most `0xc0` |
| `0x15c` | 4 | output | Optional chip-type override |
| `0x160` | 4 | output | Optional chip-series override |
| `0x164` | 1 | output | Configuration flag |
| `0x165` | 1 | output | Match version; current TA returns `2` |

Use `--fw-info-from-device` when generating input for the fixed sequence
client. It leaves `0x6c` zero for validation; after command 1000 succeeds, the
client issues the second `GET_FW_INFO` on the inherited fingerprint fd and
overwrites only its shared-memory working copy. The current mainline Piano
shim returns zero, matching the stock driver's constant result.

The inspected `gfpia` does not write `0x15c` or `0x160`; they remain zero.
The HAL only overrides command 1000's configuration when those values are
nonzero. This is why the offline generator leaves them zero and offers no
override option.

### Command 1005: finish initialization

Class is 1 and payload size is 0x74.

| Offset | Size | Direction | Meaning |
| ---: | ---: | --- | --- |
| `0x6c` | 2 | output | Orientation in degrees: `0`, `90`, `180`, or `270` |
| `0x6e` | 2 | output | Navigation polarity |
| `0x70` | 4 | input | Dump enable flag |

`gf_hal_init_finished` at `0x20da4` allocates this payload with `calloc`,
writes only the dump flag at `0x70` before invoking command 1005, and reads the
two halfwords at `0x6c/0x6e` only after a successful return. Consequently
orientation and navigation polarity must enter the TA as zero; they are not
caller-selected settings.

## Normal cold-start sequence

`gf_hal_open` is at `0x1c9d4`. Its sequence is:

1. Open the device and issue `REQUEST_RESOURCE`.
2. Open the TA session.
3. Issue `ENABLE_POWER` for the NUL-terminated string `vreg3v3`.
4. Issue `GET_FW_INFO`. The first ioctl return code is ignored. If its output
   byte is zero, issue `RESET`.
5. Try command 1000 at levels `4, 3, 2, 1`. Each attempt is clock-on, invoke,
   then clock-off. After failed levels 4, 3, and 2, reset and sleep 5 ms. A
   failed level 1 goes directly to power-off cleanup.
6. On success, copy the 0x208-byte configuration and enter Milan
   initialization at `0x3ffe4`.
7. Issue `GET_FW_INFO` again; this ioctl error is fatal. Invoke command 1001.
8. Issue `INIT`, `ENABLE_IRQ`, and `CHIP_INFO`.
9. Load zero, one, or two configured models. Each enabled model uses three
   command 1113 chunks, and each chunk has its own clock-on/invoke/clock-off
   wrapper.
10. Invoke command 1005 through the same clock wrapper.

`qcomtee-qseecom send-gfpia-1000-1001-1005` implements only the zero-model
form of this sequence. It requires token/sequence 3/2 for command 1005, keeps
the same controller object across all three commands, forces HLOS
initialization before 1005, and keeps IRQ enabled until 1005 has returned. It
does not infer that models are absent from missing files and never sends
command 1113.

The captured Piano configuration selects both models: chip `0x31`,
`u32 config[0x17c] = 1` enables the palm model, `config[0x19d] = 1`
enables ASP, and `config[0x1a2] = 0` selects CAP_S_2 rather than CAP_T_2.
`send-gfpia-piano-init` requires those exact returned values before it drives
the six reviewed command-1113 chunks and final command 1005. It keeps the same
controller and IRQ across the entire sequence. Unlike stock, it treats a
nonzero model-chunk result as fatal and does not continue to a later chunk or
to command 1005.

The command wrapper is `hal_milan_invoke_command` at `0x41260`. It attempts
clock-off after every invocation, including a failing one. Clock ioctl errors
are only logged and do not replace the TA return value. Thus static analysis
proves an off ioctl was attempted, not that the physical or secure clock is
off. Stock `mi_fp.ko` implements both SPI clock ioctls as logging no-ops; the
actual secure SPI clock state remains a TrustZone concern.

## Command 1014: set active group

The fixed main-user request is class 1 with a 0x270-byte payload:

| Offset | Size | Direction | Meaning |
| ---: | ---: | --- | --- |
| `0x00` | `0x6c` | input/output | Common prefix; sequence is `u32@0x44` |
| `0x6c` | 4 | input | Group id, fixed to 0 |
| `0x70` | `0x200` | input | NUL-terminated active-group pathname |

`piano-active-group` accepts only `/data/vendor_de/0/fpdata`, whose 24 bytes
occupy `[0x70,0x88)`; offset 0x88 and the rest of the pathname field are zero.
It appends command 1014 immediately after the nine-step model initialization
on the same controller. `send-gfpia-piano-active-group` stops there and does
not install an HMAC key. The separate `send-gfpia-piano-hmac` extension
continues with the fixed exchange described below.

Command 1014 is not a side-effect-free gid setter. The TA may read, migrate,
create, or synchronize `auth_token*`, `gf_module_info*`, `finger_*`, and
backup files under the selected directory. Several missing-file and
load/synchronize errors are logged and then swallowed by the stock TA, so a
zero command response must be checked together with filesystem-supplicant
logs and resulting state. The client still treats any nonzero transport,
auxiliary, or TA status as fatal and stops at the first failure.

## Keymaster HMAC installation: command 109

`send-gfpia-piano-hmac` has one fixed order: the nine initialization requests,
class-1 command 1014 at token/sequence 10/9, Keymaster command `0x205` with
selector `2`, release of the `keymaster64` controller, and finally GFPiA
class-2 command 109 at token 11. The GFPiA controller is kept across the whole
sequence, and the IRQ remains enabled from HLOS initialization through command
109. Each step must succeed before the next is issued.

`KEYMASTER_SOURCE` must be the `keymaster64` ELF reconstructed on the device
from its current slot's `keymaster` partition. Keep that reconstructed image
on the device and do not use the other slot's image. The Keymaster request is
two little-endian `uint32_t` values:

```c
struct keymaster_hmac_request {
	uint32_t command;       /* 0x205 */
	uint32_t selector;      /* 2 */
};
```

The Keymaster response is exactly 0x100 bytes. It starts with signed status at
offset 0, encapsulated-message offset at 4, and encapsulated-message length at
8. Status must be zero, the message must be nonempty and start after the
12-byte header, and its range must fit inside the response. The complete
0x100-byte response, including its header, becomes command 109's shared-memory
payload without modification. In particular, offset 0x44 belongs to the
encapsulated inter-app message and must not be overwritten with a GFPiA
sequence number.

Command 109 uses the normal 0x80-byte modified-request envelope, but class is
2, token is 11, command is 109, and payload size is 0x100. The raw Keymaster
response and command-109 HMAC buffers are never printed or written to disk;
only non-secret status fields are reported. All sensitive request-output,
response, and shared-memory buffers are explicitly cleared after use and on
error paths.

The offline HMAC self-test does not open `/dev/tee` or access the sensor:

```sh
qcomtee-qseecom self-test-hmac
```

It checks the exact Keymaster and GFPiA request fields, rejects nonzero status,
truncated or out-of-range encapsulated messages, modified command-109 fields,
and invalid payload addresses, and verifies sensitive-buffer clearing.

## Hardware ioctl ABI

| Operation | ioctl | HAL helper/address | Stock behavior |
| --- | ---: | --- | --- |
| `INIT` | `0x80016700` | call at `0x26178` | Initialize device state |
| `RESET` | `0x00006702` | `gf_hal_reset_chip` `0x2626c` | Reset low then high |
| `ENABLE_IRQ` | `0x00006703` | call at `0x261d0` | Enable interrupt |
| `ENABLE_SPI_CLK` | `0x40046705` | `gf_hal_control_spi_clock` `0x264f0` | Log-only no-op |
| `DISABLE_SPI_CLK` | `0x00006706` | `gf_hal_control_spi_clock` `0x264f0` | Log-only no-op |
| `ENABLE_POWER` | `0x40016707` | `gf_hal_enable_power` `0x26960` | Enable named regulator |
| `DISABLE_POWER` | `0x40016708` | helper at `0x26a3c` | Disable named regulator |
| `GET_FW_INFO` | `0x8001670b` | helper at `0x26334` | Return one byte |
| `CHIP_INFO` | `0x4008670d` | call at `0x26ebc` | Eight-byte argument |
| `REQUEST_RESOURCE` | `0x00006725` | call at `0x2588c` | Acquire resources |

Despite `_IOW(..., char)`, the power ioctl argument is a pointer to the full
`"vreg3v3\0"` name, not a pointer to one isolated character.

The stock reset defaults to 10 ms low plus 10 ms high because the inspected
Piano fingerprint node has no `xiaomi,rst_low_time` or
`xiaomi,rst_high_time` property. Power enable and disable each add a 1 ms
busy-wait in the driver. These are minimum requested delays; scheduling can
make them longer, and a runtime overlay that supplies reset properties would
need separate verification.

## Model command 1113

Recovered model files are:

| File | Size | SHA-256 |
| --- | ---: | --- |
| `piano-goodix-cap-s-2.bin` | `0x4b540` | `01829194c8a1e00b7bf1cc0440043bc5ee45057791f1f1ab410f8119bc10ae4e` |
| `piano-goodix-cap-t-2.bin` | `0x4b540` | `b43b6c3890943436d5c863ab3915a538fd2e2f008deb22915c3bc003c42525ee` |
| `piano-goodix-mistouch.bin` | `0x48c88` | `422741920cb2a0e508241e9d1b7c824f7304f15e638b1576423c6fb99f99ec71` |

The selected blobs are embedded directly in stock `libgf_hal.so`. CAP_S_2 is
at ELF file/virtual offset `0x39c3e0`; CAP_T_2 is at `0x3e7924`; and Piano's
`DLWeightLightDubaiU4_12_10_14MisTouch` is at `0x094da0`. The table sizes
and hashes above match byte-for-byte extraction from those offsets.

Each model starts as a zeroed `0x124ff4`-byte logical buffer:

| Model | Nonzero logical-model fields |
| --- | --- |
| ASP CAP_S_2 | model bytes at `[0x70,0x4b5b0)`; `u32[0x1248b8] = 0x4b540` |
| Piano palm | `u32[0x6c] = 1`; model bytes at `[0x70,0x48cf8)`; `u32[0x124ff0] = 0x12322` |

Outer command 1113 (`GF_CMD_TRANSPORT_DATA`) uses a `0x7d014`-byte
payload:

| Offset | Size | Meaning |
| ---: | ---: | --- |
| `0x00` | `0x6c` | Common prefix; sequence is `u32@0x44` |
| `0x6c` | `0x7cf9c` | One logical-model slice |
| `0x7d008` | 1 | Chunk index, 0 through 2 |
| `0x7d009` | 3 | Zero padding |
| `0x7d00c` | 4 | Logical total, `0x124ff4` |
| `0x7d010` | 4 | Inner command, `1111` (`GF_CMD_INIT_MODEL`) |

The three slices are `0x7cf9c`, `0x7cf9c`, and `0x2b0bc` bytes; the
unused tail of the third slice is zero. Stock also writes its logging timestamp
into common bytes `[0x4c,0x66)`. The reviewed offline inputs leave that
opaque logging field zero, as with the already accepted initialization
requests; they set only the independently validated sequence field.

An ordinary nonzero return stops the remaining chunks for that model, but
`hal_milan_init_model` does not propagate that failure: it may try the second
model and then continue to command 1005. This nonfatal stock behavior must not
be mistaken for proof that a model loaded successfully. The bring-up client
instead synchronizes the returned request, response, and payload, validates
the result, and stops immediately.

The earlier zero-model experiment reached command 1005 but returned status
`0x461` with auxiliary status zero. Neither the stock HAL nor this TA names
`0x461`: their error table jumps from `0x45f` to the `0x462`
`INVALID_ERROR` sentinel, so `gf_strerror(0x461)` also reports
`INVALID_ERROR`. Missing model state is a supported hypothesis because the
captured feature flags require both models, but `0x461` itself is not proof
of that interpretation.

The reconstructed TA used for this analysis is 11681880 bytes with SHA-256
`74ea1fe6bb7d9eeeeb71ae161b69b1f53ea2c68799076198ce768dc95df921a1`.

## Command names and wire identifiers

`libgf_hal.so` carries a name table at virtual address `0x432f98`: 16-byte
entries of `{const char *name; uint64_t value}`, running from
`GF_CMD_DETECT_SENSOR` for at least 120 entries. **The wire command is the
table value minus one.**

Five commands recovered independently by earlier static analysis agree with
that offset: table 1001/1002/1006/1015/1114 are `GF_CMD_DETECT_SENSOR`,
`GF_CMD_INIT`, `GF_CMD_INIT_FINISHED`, `GF_CMD_SET_ACTIVE_GROUP` and
`GF_CMD_TRANSPORT_DATA`, matching wire commands 1000, 1001, 1005, 1014 and
1113 above. A sixth check comes from the code: `hal_test_pause_enroll` sends
the literal `0x445` while the table gives
`GF_CMD_TEST_UNTRUSTED_PAUSE_ENROLL` the value `0x446`.

Wire identifiers on the enrolment and matching paths:

```
1006 PRE_ENROLL     1007 ENROLL        1008 POST_ENROLL   1009 CANCEL
1010 AUTHENTICATE   1011 GET_AUTH_ID   1012 SAVE          1013 REMOVE
1015 ENUMERATE      1016 IRQ           1092 PAUSE_ENROLL

1060 TEST_UNTRUSTED_ENROLL
1061 TEST_UNTRUSTED_AUTHENTICATE
1062 TEST_DELETE_UNTRUSTED_ENROLLED_FINGER
1093 TEST_UNTRUSTED_PAUSE_ENROLL
```

## Command class

Request offset `0x0c` is the command class. The HAL sends its ordinary
commands as class `1` and every factory-test command as class `3`. The three
initialization commands documented above are class 1; the untrusted enrolment
and authentication commands are class 3.

`gf_hal_test_invoke_command(command, payload, size)` and
`gf_hal_test_invoke_command_ex(command)` both hardcode the class:

```asm
2a804: mov w0, #1 ; mov w1, #0x6c ; bl calloc   ; payload = 0x6c, zeroed
2a81c: mov w0, #3                               ; class 3
2a824: mov w1, w19                              ; command
2a82c: mov w3, #0x6c                            ; payload size
2a834: blr x8                                   ; invoke
```

Payload shapes taken from the call sites:

| Wire | Class | Payload | Builder |
| ---: | ---: | ---: | --- |
| 1006 PRE_ENROLL | 1 | `0x78` | `gf_hal_common_pre_enroll` |
| 1007 ENROLL | 1 | `0xbc` | `gf_hal_common_enroll` |
| 1010 AUTHENTICATE | 1 | `0x80` | `gf_hal_common_authenticate` |
| 1011 GET_AUTH_ID | 1 | `0x78` | `gf_hal_common_get_auth_id` |
| 1012 SAVE | 1 | `0x78` | `gf_hal_save` |
| 1013 REMOVE | 1 | `0xcc` | `gf_hal_common_remove` |
| 1015 ENUMERATE | 1 | `0xc0` | `gf_hal_common_enumerate` |
| 1060 UNTRUSTED_ENROLL | 3 | `0x6c` | `hal_test_enroll` |
| 1061 UNTRUSTED_AUTHENTICATE | 3 | `0x80` | `hal_test_authenticate` |
| 1093 UNTRUSTED_PAUSE_ENROLL | 3 | `0x70` | `hal_test_pause_enroll` |

### Command 1060: untrusted enrolment

Class is 3 and payload size is `0x6c`. `hal_test_enroll` is nothing but
`gf_hal_test_invoke_command_ex(0x424)`, so the command carries no fields of
its own: the payload is the shared prefix, zeroed apart from the sequence the
HAL maintains at `0x44`. Unlike command 1007 it takes no `hw_auth_token`, so
it needs neither gatekeeper nor a shared HMAC.

Observed output on Piano, after the full initialization and active-group
sequence returned status zero:

| Offset | Value | Note |
| ---: | --- | --- |
| `0x08` | `0x23` | output |
| `0x10`..`0x34` | nine words of `0x42` | output |
| `0x44` | unchanged | sequence, echoed |
| `0x48` | `0x3e80` | `ta_elapsed` |

A zero status means the TA accepted and opened an untrusted enrolment. It does
not mean a finger was enrolled: enrolment is driven by sensor interrupts, and
the capture loop that feeds them back to the TA is not yet recovered. The
command that the interrupt path sends is still unidentified, because
`gf_hal_irq` only calls the device vtable slot at `[device + 112]` and the
Milan implementation is a static function.

### Command 1093: untrusted pause and resume enrolment

Class is 3 and payload size is `0x70`. One byte at `0x6c` selects the
direction: `hal_test_pause_enroll` writes `1`, `hal_test_resume_enroll` leaves
it zero.

### Command 1061: untrusted authentication

Class is 3 and payload size is `0x80`. `hal_test_authenticate` writes only two
fields into the zeroed payload: a `uint32_t` at `0x6c` and a `uint64_t` at
`0x70`.

### Command 1016: interrupt

Class is 1 and payload size is `0xd134`. This is the command the whole
enrolment and matching path runs on: the TA does not report progress through
the command that started the operation, it reports it here, once per sensor
interrupt.

`hal_milan_irq` allocates the payload with `calloc` and writes exactly four
fields before sending it. Everything else, including the sequence at `0x44`
that every other command carries, stays zero:

```asm
41a50: mov w0, #1 ; mov w1, #0xd134 ; bl calloc
41a94: str w8, [x21]        ; x21 = payload + 0x2c5, w8 = 0x2000000
41ab4: stur xzr, [x21, #4]  ; eight zero bytes at 0x2c9
41ab8: str w8, [x19, #168]  ; 0xa8 = 0x200
41abc: str w20, [x19, #152] ; 0x98 = 1
41a78: strb w0, [x26, #576] ; 0xd130 = gf_is_dump_enabled()
41aa8: mov w0, #0x3f8       ; command 1016
41ac0: bl gf_hal_invoke_command
```

| Offset | Size | Direction | Meaning |
| ---: | ---: | --- | --- |
| `0x6c` | 4 | output | Interrupt bitmask; see below |
| `0x70` | 4 | output | Which operation the image was fed to |
| `0x88` | 2 | output | Read on enrolment success |
| `0x94` | 4 | output | `GF_ERROR_*`, in the same 1006..1119 numbering as the commands |
| `0x98` | 4 | input/output | `1` on entry; `4` or `5` means send the command again for the same interrupt |
| `0xa8` | 4 | input | `0x200` |
| `0x2c5` | 4 | input | `0x2000000`, followed by eight zero bytes at `0x2c9` |
| `0xd130` | 1 | input | Dump enable flag |

`irq_image_enroll_or_authenticate` dispatches on the `0x94` result through a
jump table covering `0x3ee`..`0x45f`. A zero result then selects on `0x70`:
`0` runs `gf_hal_common_enroll_success`, `1` and `2` share a path, and `4` has
its own. Those are `OPERATION_ENROLL`, `OPERATION_AUTHENTICATE_IMAGE`,
`OPERATION_AUTHENTICATE_FF` and `OPERATION_AUTHENTICATE_FIDO`; the untrusted
path reports `OPERATION_TEST_UNTRUSTED_ENROLL` instead, which that dispatcher
does not handle. It goes to `hal_notify_test_finger_event`, which only encodes
what it was given as TLV for a factory-test app and never asks the TA again.
Everything an untrusted enrolment reports therefore has to be read out of the
interrupt payload itself.

Observed on Piano across 31 rounds of one untrusted enrolment, reading the
payload as little-endian words:

| Offset | Meaning |
| ---: | --- |
| `0x08` | Operation, mirrored from `0x70` |
| `0x0c` | `GF_ERROR_*` for this round; zero when the round succeeded |
| `0x48` | `ta_elapsed`: about 3-5 ms for a finger-down round, 8-9 ms for finger-up, and 60-87 ms to capture and judge an image |
| `0x85` | `0xff` when the image was taken, `0` when it was refused |
| `0x88` | Signed, and one lower on every image taken: `-1`, `-2`, ... `-9` |

The only fields that ever changed were `0x0c`, `0x48`, `0x6c`, `0x85`, `0x88`
and `0x98`. The whole 53 KB beyond `0x2f4` was byte-identical in every round,
so the sensor image never leaves the secure world - which is what a
match-on-chip design should do, and it means the HLOS has no image to look at.

A refused image sets `0x0c` to `GF_ERROR_ALGO_FAKE` (1121), leaves `0x85` at
zero and puts `26` in `0x88`. That is the anti-spoofing model refusing the
press - the same ASP model the initialization sequence loads through command
1113. On Piano nine presses out of thirteen were taken.

Nine accepted images produced no completion of any kind: no result, no state
change, and nothing new in the TA's storage. An untrusted enrolment does not
appear to finish by itself.

### Where the TA keeps its state

The TA reaches its persistent files through the listener the filesystem
supplicant answers, and it names them exactly as Android does. After one
initialization and one untrusted enrolment, `data/vendor_de/0/fpdata` under the
supplicant's state root held:

```
gf_calibration.so  gf_fdt_base.so  gf_module_info_0.so  gf_otp_info.so
```

plus `persist/data/fingerprint_version`. That path is the one command 1014
selects as the active group, and it is the same path the stock stack uses on
the userdata partition. Templates enrolled under Android therefore live where
this TA would look for them.

Declare the command's own `0xd134` in the request, not the length of the
mapping the payload lives in. A request that declares more than the command
has is refused before the TA looks at the payload, and the refusal appears as
`0xffffffff` in the auxiliary field with the payload untouched.

### The interrupt bitmask

`gf_strirq` names each bit of the word at `0x6c`:

| Bit | Name | Bit | Name |
| ---: | --- | ---: | --- |
| 1 | `FINGER_DOWN` | 17 | `FARGO_ERR_NOT_RESOLVED` |
| 2 | `FINGER_UP` | 18 | `RESET_FIRST` |
| 3 | `MENUKEY_DOWN` | 19 | `RESET_FAILED` |
| 4 | `MENUKEY_UP` | 20 | `ESD_ERR` |
| 5 | `BACKKEY_DOWN` | 21 | `NAV_LEFT` |
| 6 | `BACKKEY_UP` | 22 | `NAV_RIGHT` |
| 7 | `IMAGE` | 23 | `NAV_UP` |
| 8 | `RESET` | 24 | `NAV_DOWN` |
| 9 | `TMR_IRQ_MNT` | 25 | `PRESS_LIGHT` |
| 10 | `ONE_FRAME_DONE` | 26 | `PRESS_HEAVY` |
| 11 | `ESD_IRQ` | 27 | `UPDATE_BASE` |
| 12 | `ADC_FIFO_FULL` | 28 | `TEMPERATURE_CHANGE` |
| 13 | `ADC_FIFO_HALF` | 31 | `ERR_CHECKSUM` |
| 14 | `FDT_REVERSE` | | |
| 15 | `NAV` | | |
| 16 | `FARGO_ERR` | | |

## Recovering the HAL's private symbols

`libgf_hal.so` is stripped, but it carries a `.gnu_debugdata` section: an
LZMA-compressed ELF holding a symbol table for the static functions.

```
aarch64-linux-gnu-objcopy --dump-section .gnu_debugdata=dbg.xz libgf_hal.so
xz -dc dbg.xz > dbg.elf
nm dbg.elf
```

That yields 112 names the dynamic symbol table does not have, including the
whole `hal_milan_*` family and `irq_image_enroll_or_authenticate`. Without it
the Milan device operations are only reachable by following the vtable slot
`gf_hal_irq` calls at `[device + 112]`.

### Command 1015: enumerate

Class is 1 and payload size is `0xc0`. `gf_hal_common_enumerate` sends nothing
but zeroes and reads two parallel arrays back out of the same buffer:

```asm
22354: add  x9, x20, #0x98       ; finger identifiers
22370: ldr  w10, [x8], #4        ; identifier; zero means an empty slot
22378: ldur w9, [x9, #-40]       ; the group, 0x28 lower
```

| Offset | Size | Direction | Meaning |
| ---: | ---: | --- | --- |
| `0x70` + 4*i | 4 | output | Group of slot i |
| `0x98` + 4*i | 4 | output | Finger of slot i; zero when the slot is empty |

Ten slots fill the payload exactly. This is the cheapest way to see what the TA
holds, it changes nothing, and it is the only direct evidence that an
enrolment was stored. On Piano, against a state root the TA had only ever
written its own calibration into, it returns status zero and no fingers.

### Command 1012: save

Class is 1 and payload size is `0x78`. `gf_hal_save` writes two words and
nothing else:

| Offset | Size | Direction | Meaning |
| ---: | ---: | --- | --- |
| `0x6c` | 4 | input | Group |
| `0x70` | 4 | input | Finger |

Neither is the caller's to choose. `gf_hal_common_enroll_success` takes both
straight out of the interrupt payload the TA has just filled in:

```asm
245f4: ldp w0, w1, [x19, #128]   ; irq payload 0x80 and 0x84
245f8: bl  gf_hal_save
```

So the TA names the finger it has been building, at `0x80` and `0x84` of the
GF_CMD_IRQ payload, and the HAL passes those two values back. A refused image
leaves `0x84` zero. The stock path calls `gf_hal_common_remove_without_callback`
with the same pair first, so that saving over an existing finger replaces it.

## Reloading the application

Releasing the controller does not unload the application: QTEE keeps it
resident and the next `loadFromRegion` reports `ALREADY_LOADED`.
`IAppController::unload` is op 1 and takes no arguments either way; sending it
before dropping the controller leaves QTEE as it was found.

That is worth doing, but it does not make a second run work in the same boot.
After an unload and a fresh load of `gfpia`, the first command fails with QTEE
error `0xffffff96`. Each run still needs a reboot.

## Enrolment and matching

This is the sequence that works, verified end to end on Piano: a finger
enrolled from mainline, stored, found again after a reboot, matched, and an
unenrolled finger correctly refused.

```
1000 -> 1001 -> 1113 x6 -> 1005 -> 1014      initialization and active group
1015                                          what the TA already holds
1006 -> challenge
1007 with a 69-byte token over that challenge
     ... GF_CMD_IRQ per interrupt until 0x88 reaches zero ...
1008
1012 with the group and finger the TA named
1015                                          the finger is now listed
```

Matching is the same up to 1014, then `1015`, `1010`, and one interrupt.

### Neither enrolment nor matching needs a gatekeeper

`gf_hal_common_pre_enroll` calls `send_hmac_key()` and carries on whether it
worked (`cbnz w0`). `gf_hal_common_authenticate` refuses to send at all unless
it worked (`cbz w0`), which looks like a hard requirement.

It is not. That is the HAL declining to send; the TA does not check. Command
1010 sent directly returns status zero and matches normally, and command 1007
accepts a `hw_auth_token` whose 32-byte HMAC is all zeroes. A system with no
gatekeeper and no Keymaster shared key can enrol and match.

### Command 1006: pre-enrol

Class is 1 and payload size is `0x78`. The TA returns a 64-bit challenge at
`0x70`. `gf_hal_common_pre_enroll` also clears the HAL's own enrolment count
before sending; skipping this command leaves the TA's enrolment state wherever
it was.

### Command 1007: enrol

Class is 1 and payload size is `0xbc`.

| Offset | Size | Direction | Meaning |
| ---: | ---: | --- | --- |
| `0x6c` | 4 | input | Group |
| `0x74` | 1 | input | Dump enable flag |
| `0x76` | 69 | input | `hw_auth_token` |

The token is Android's: a version byte, then the challenge, user id and
authenticator id as little-endian 64-bit values, then a big-endian
authenticator type and timestamp, then a 32-byte HMAC. Zero is accepted for
everything but the challenge.

### Command 1008: post-enrol

Class is 1 and payload size is `0x6c`, all zeroes.
`gf_hal_common_post_enroll` is nothing but `gf_hal_invoke_command_ex(1008)`,
which is the class 1 twin of the class 3 helper: `calloc(0x6c)` and send.

### Command 1010: authenticate

Class is 1 and payload size is `0x80`.

| Offset | Size | Direction | Meaning |
| ---: | ---: | --- | --- |
| `0x6c` | 4 | input | Group |
| `0x70` | 8 | input | Operation identifier |
| `0x78` | 4 | input | `0xffffffff` |

### What an enrolment and a match look like on the wire

Both report through `GF_CMD_IRQ`, in the fields at the end of the common area:

| Offset | Meaning |
| ---: | --- |
| `0x70` | Operation: 0 enrolling, 1 or 2 matching |
| `0x80` | Group |
| `0x84` | Finger: assigned while enrolling, matched while matching, zero for neither |
| `0x88` | Images still wanted; an enrolment starts at 25 and finishes at zero |
| `0x0c` | This round's `GF_ERROR_*` |

Enrolment feedback on Piano: `0x3f3` `ACQUIRED_PARTIAL` and `0x415`
`DUPLICATE_AREA` both leave `0x88` untouched and mean the press did not count;
`0x461` `ALGO_FAKE` is the anti-spoofing model refusing it. Reaching 25 usable
images takes something like 35 presses, most of the losses being duplicates.

A match returns status zero with the enrolled identifier in `0x84`. An
unenrolled finger returns `0x428` `MATCH_FAIL_AND_RETRY` with `0x84` zero.

### The template does not fit a round number

The first write of `finger_0_0.so` arrives as exactly 515824 bytes, which is
the 504 KB shared buffer minus the 272-byte write header. A supplicant that
caps writes at a tidier 500 KB refuses the one write that matters and the TA
reports `GF_ERROR_WRITE_SECURE_OBJECT_FAILED`. Size the cap from the buffer,
not from a round figure. The finished template is 732343 bytes across several
writes.

## Exceptional recovery paths

After the wrapper has attempted clock-off:

- Return `0x419` (`GF_ERROR_TA_DEAD`) destroys the timer, resets the sensor,
  and enters `gf_hal_reinit` at `0x1f138`. It does not replay the failed
  command. A nonzero first byte in the payload causes another reset.
- Return `0x45e` (`GF_ERROR_OVER_CURRENT`) causes the first two local recovery
  attempts to power-cycle with a requested 200 ms off interval. Later repeats
  power off; the tenth accumulated event removes/closes the device.

`gf_hal_reinit` is not the normal cold-start loop. It turns the clock on once,
reopens the TA, keeps that logical clock state across 1000, 1001, model, and
1005 commands, and attempts one clock-off at exit. Its command 1000 loop has
up to five attempts; the first four failures reset and sleep 5 ms. The payload
is cleared on each attempt and no probe level is written, so its level is
zero. Reinit does not issue a power ioctl and assumes power is already on.

## Offline generation

Generate deterministic command files by supplying `--time-ms 0`, for example:

```sh
qcomtee/goodix-gfpia-gen.py 1000 \
  --sequence 0x10 --token 0x20 --time-ms 0 --probe-level 4 \
  --request-out request-1000.bin --payload-out payload-1000.bin

qcomtee/goodix-gfpia-gen.py 1001 \
  --sequence 0x11 --token 0x21 --time-ms 0 --fw-info-from-device \
  --request-out request-1001.bin --payload-out payload-1001.bin

qcomtee/goodix-gfpia-gen.py 1005 \
  --sequence 0x12 --token 0x22 --time-ms 0 \
  --dump-enabled 0 \
  --request-out request-1005.bin --payload-out payload-1005.bin
```

Generate the complete Piano sequence only from the reviewed embedded model
extractions:

    qcomtee/goodix-gfpia-gen.py piano-init \
      --cap-s-model /tmp/piano-goodix-cap-s-2.bin \
      --mistouch-model /tmp/piano-goodix-mistouch.bin \
      --time-ms 0 --output-dir piano-init-input

    (cd piano-init-input && sha256sum -c SHA256SUMS)
    mkdir piano-init-output
    xiaomi-fp-run --pass-fp-fd qcomtee-qseecom \
      send-gfpia-piano-init gfpia /boot/image \
      piano-init-input piano-init-output

Generate the same initialization followed by the fixed main-user active
group:

    qcomtee/goodix-gfpia-gen.py piano-active-group \
      --cap-s-model /tmp/piano-goodix-cap-s-2.bin \
      --mistouch-model /tmp/piano-goodix-mistouch.bin \
      --time-ms 0 --output-dir piano-active-group-input

    (cd piano-active-group-input && sha256sum -c SHA256SUMS)
    mkdir piano-active-group-output
    xiaomi-fp-run --pass-fp-fd qcomtee-qseecom \
      send-gfpia-piano-active-group gfpia /boot/image \
      piano-active-group-input piano-active-group-output

Use the same reviewed active-group inputs for the HMAC extension, but create a
new output directory. The final argument is the device-side reconstructed ELF
from the device's current-slot `keymaster` partition:

    mkdir piano-hmac-output
    xiaomi-fp-run --pass-fp-fd qcomtee-qseecom \
      send-gfpia-piano-hmac gfpia /boot/image \
      piano-active-group-input piano-hmac-output \
      /root/keymaster64-current-slot-reconstructed.elf

For --time-ms 0 and the model hashes above, the generated SHA256SUMS file is
1572 bytes with SHA-256
74d9344c32c7321dd89e907a07179bbd884a61d923a6e4013bb92a477309c308.
The generator creates the input directory itself and rejects an existing
path. The client requires a separate, existing output directory and opens all
27 fixed output names with O_EXCL before command 1000.

For `piano-active-group` with the same deterministic inputs, `SHA256SUMS` is
1738 bytes with SHA-256
`fed56bd8a7df4f21b52aaea7f32f82b921e57ef13d0c2109e4f0d3c7ccdde185`.
The extra fixed vectors are:

| File | Size | SHA-256 |
| --- | ---: | --- |
| `request-1014.bin` | `0x80` | `768447bfccc473abfcc9e800886679514e5cb12d5f71a54a5cad12072f1073d6` |
| `payload-1014.bin` | `0x270` | `47a6566169409b72d0a793aeec3a651335fa01d025335276fad8f95f9761a754` |

Those exact commands produce these reference vectors:

| File | Size | SHA-256 |
| --- | ---: | --- |
| `request-1000.bin` | `0x80` | `9e1346e6815dec073ed9fedfac5673f2693d980259b9a3bc98e38e56e729adae` |
| `payload-1000.bin` | `0x280` | `d90228b4a2a8ba8a106e5c492621065200ea53ea00d42deb6f58f3dada3368d8` |
| `request-1001.bin` | `0x80` | `a04a666241f8a0656aaa643592bee32ee0275a5fd7885f183598ec49406ec677` |
| `payload-1001.bin` | `0x168` | `874a7de7582d15dca4e4a8fd19c51f9590a5b61394dd98d59ef7b7aed46435aa` |
| `request-1005.bin` | `0x80` | `85efc0bb7d14f2dbf610d7170aa21e41e900d23c513ae051a68ae0da39c41e65` |
| `payload-1005.bin` | `0x74` | `3beec4ae00015e2f7705a7e62b4b7f9ebfecfc22dca00d6bb1e5c99fa486d823` |

Omitting `--time-ms` uses the host's current local milliseconds since
midnight. Generation alone is not authorization to send a request. Before any
device-side experiment, independently verify request offsets, payload length,
both counters, the sensor's power/reset state, and the previous response's
transport error.
