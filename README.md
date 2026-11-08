# xiaomi-piano-libfprint-gfpia

Linux fingerprint support for the Xiaomi Pad 8 Pro (`xiaomi,piano`, SM8750)
side sensor: a Goodix reader driven by the `gfpia` trusted application in
QTEE. Images and templates never reach Linux; matching happens in the secure
world, and Linux only starts operations and reads what the application made of
each finger. To libfprint this is a match-on-chip driver with device storage.

This stack enrolled fingers, verified them and logged in through
`pam_fprintd` on mainline Linux.

## Layout

| Directory | Package | What it is |
| --- | --- | --- |
| `libfprint/` | `libfprint-xiaomi-piano` | The libfprint driver (`xiaomi-piano.c`), the gfpia protocol (`gfpia.c`), the QTEE transport (`gfpia-tee.c`) and a standalone tester (`gfpia-test.c`). The package is the distribution's libfprint with this driver compiled in. |
| `qcomtee/` | `xiaomi-piano-fp-supplicant`, `qcomtee-piano-tools` | `qcomtee-fs-supplicant`, which serves the TA's storage listeners (10 and 0x7000), and the protocol tools `qcomtee-qseecom`, `xiaomi-fp-run` and `goodix-gfpia-gen.py`. `goodix-gfpia.md` documents the protocol and where every number in it came from. |
| `kernel/xiaomi-fp-uio/` | `xiaomi-fp-uio-dkms` | The out-of-tree UIO driver for the sensor's supply, reset line and wake interrupt, plus the `goodix,gf3656zs1` binding. |
| `integration/` | `xiaomi-piano-fp` | The fprintd service drop-in (`FP_XIAOMI_PIANO=1`, `DeviceAllow` for `/dev/tee0` and `char-uio`, `ReadWritePaths`). |
| `firmware/` | `xiaomi-piano-fp-firmware` | The packaging script for the TA image and its initialisation data. The blobs themselves are not in this repository. |

## Runtime requirements

- `/dev/tee0` from the mainline `qcomtee` driver.
- `/dev/uioN` from `xiaomi-fp-uio`. It is found by the name in
  `/sys/class/uio/uioN/name`, not by a fixed minor.
- `xiaomi-fingerprint-supplicant.service` running before fprintd opens the
  sensor.
- `/usr/lib/firmware/qcom/sm8750/xiaomi/piano-fp/`, holding `gfpia.mdt`,
  `gfpia.b00`..`gfpia.b08` and the `request-NNNN.bin` / `payload-NNNN.bin`
  pairs for 1000, 1001, the six 1113 model chunks, 1005 and 1014.

## Firmware

The TA image and the initialisation payloads are Goodix/Xiaomi proprietary
data. Take them from the device's own Android installation and place the 30
files in `firmware/piano-fp/`, which is ignored by git. `firmware/PKGBUILD`
checks the count and installs them. The payloads carry Goodix's sensor
configuration and both algorithm models; `qcomtee/goodix-gfpia-gen.py` shows
how they are laid out and verifies the embedded model hashes.

`firmware/README.md` lists all 30 files with their sizes and SHA-256, where
the TA image is on the device, which `libgf_hal.so` offsets hold the two
models, and the commands that regenerate every request and payload.

## Installing

Run makepkg as a normal user and install in dependency order:

    (cd kernel/xiaomi-fp-uio && makepkg -f)
    (cd qcomtee && makepkg -f)
    (cd firmware && makepkg -f)
    (cd libfprint && makepkg -f)
    (cd integration && makepkg -f)
    sudo pacman -U kernel/xiaomi-fp-uio/*.pkg.tar.zst qcomtee/*.pkg.tar.zst \
                   firmware/*.pkg.tar.zst libfprint/*.pkg.tar.zst
    sudo pacman -U integration/*.pkg.tar.zst
    sudo systemctl enable --now xiaomi-fingerprint-supplicant.service

Then enrol with `fprintd-enroll` or the desktop's user settings.

`libfprint-xiaomi-piano` conflicts with `libfprint`. pacman asks to remove the
old package, and `--noconfirm` answers no, so answer it by hand. A previous
hand installation of the firmware needs
`--overwrite '/usr/lib/firmware/qcom/sm8750/xiaomi/piano-fp/*'` once.

DKMS needs the running kernel's build tree. When the kernel is cross-built
elsewhere, build the module there instead:

    make -C kernel/xiaomi-fp-uio KDIR=<kernel O= dir> ARCH=arm64 LLVM=1

## Behaviour worth knowing

- Never unload the TA. A reload after an unload is accepted, but the first
  command to the new copy is refused until reboot. The driver drops only its
  own references and leaves the TA resident.
- A stale `gf_fdt_base.so` detect baseline stops finger detection without any
  error. The driver deletes it before initialising.
- `libfprint/README`, `qcomtee/README` and `kernel/README` cover each part in
  detail.

## License

Everything in this repository is licensed under the GNU General Public
License, version 2 or (at your option) any later version
(`GPL-2.0-or-later`); see `LICENSE`. The device tree binding is
`(GPL-2.0-or-later OR BSD-2-Clause)`.

The `libfprint-xiaomi-piano` package combines this driver with upstream
libfprint (`LGPL-2.1-or-later`), so the resulting `libfprint-2.so` is
distributed under GPL-2.0-or-later terms. The firmware files are proprietary
and are not covered by this license.
