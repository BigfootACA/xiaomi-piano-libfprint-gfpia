#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Build libfprint with the Xiaomi Pad 8 Pro fingerprint driver and install it.
#
# Run this again after every libfprint package update: the distribution's
# libfprint does not know this driver exists and will overwrite it.

set -euo pipefail

version=${LIBFPRINT_VERSION:-1.94.100}
work=${WORK_DIR:-/root/build}
source_dir="$work/libfprint-v$version"
driver_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

die() { echo "error: $*" >&2; exit 1; }

for tool in meson ninja pkg-config curl tar; do
	command -v "$tool" >/dev/null || die "$tool is not installed"
done
[ -f /usr/bin/glib-mkenums ] || die "glib-mkenums is missing; install glib2-devel"

mkdir -p "$work"
if [ ! -d "$source_dir" ]; then
	echo "fetching libfprint $version"
	curl -sL -o "$work/libfprint.tar.gz" \
		"https://gitlab.freedesktop.org/libfprint/libfprint/-/archive/v$version/libfprint-v$version.tar.gz"
	tar xzf "$work/libfprint.tar.gz" -C "$work"
fi

echo "grafting the driver in"
mkdir -p "$source_dir/libfprint/drivers/xiaomi-piano"
cp "$driver_dir"/gfpia.c "$driver_dir"/gfpia.h \
   "$driver_dir"/gfpia-tee.c "$driver_dir"/gfpia-tee.h \
   "$driver_dir"/xiaomi-piano.c \
   "$source_dir/libfprint/drivers/xiaomi-piano/"

python3 - "$source_dir" <<'PYTHON'
import sys

source = sys.argv[1]
path = source + "/libfprint/meson.build"
text = open(path).read()

entry = """    'xiaomi_piano' : files(
        'drivers/xiaomi-piano/xiaomi-piano.c',
        'drivers/xiaomi-piano/gfpia.c',
        'drivers/xiaomi-piano/gfpia-tee.c',
    ),
"""
if "xiaomi_piano" not in text:
    anchor = "    'elanmoc' : files('drivers/elanmoc/elanmoc.c'),\n"
    if anchor not in text:
        raise SystemExit("cannot find where to add the driver in meson.build")
    open(path, "w").write(text.replace(anchor, anchor + entry, 1))
    print("meson.build updated")
else:
    print("meson.build already knows the driver")

# libfprint 1.94.100 iterates a dict with one variable, which meson 1.12
# refuses. Only reached when introspection is off, which it is here.
path = source + "/tests/meson.build"
text = open(path).read()
old = "    foreach driver_test: drivers_tests\n"
if old in text:
    open(path, "w").write(text.replace(old, "    foreach driver_test, _ : drivers_tests\n", 1))
    print("tests/meson.build made meson 1.12 safe")
PYTHON

cd "$source_dir"
rm -rf build
meson setup build --prefix=/usr --libdir=lib \
	-Dintrospection=false -Ddoc=false -Dgtk-examples=false \
	-Dinstalled-tests=false -Ddrivers=xiaomi_piano
ninja -C build
ninja -C build install

echo
echo "installed. restart fprintd to pick it up:"
echo "  systemctl restart fprintd.service"
