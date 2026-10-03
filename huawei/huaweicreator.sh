#!/usr/bin/env bash
set -xe

BOARDNAME=$1

if [ -z "$BOARDNAME" ];
then
	echo "Usage: huaweicreator.sh <BOARDNAME>"
	exit 1
fi

UBOOT_BIN="u-boot.bin"
UBOOT_HUAWEI="uboot-${BOARDNAME}.bin"
UIMAGE_OUT="uImage"
UBOOT_LOADADDR=0x84000000
UBOOT_ENTRYADDR=0x84000040

# uImage is padded to 512k
UIMAGE_SIZE=524288

rm -f "$UBOOT_HUAWEI" "$UIMAGE_OUT"

cat "$UBOOT_BIN" >> "$UBOOT_HUAWEI"

mkimage -A arm -C none -T kernel -a "$UBOOT_LOADADDR" -e "$UBOOT_ENTRYADDR" -d "$UBOOT_BIN" "$UIMAGE_OUT"

# Fail if the uImage does not fit, dd would silently cut it off
size=$(stat -c%s "$UIMAGE_OUT")
if [ "$size" -gt "$UIMAGE_SIZE" ]; then
	echo "Error: $UIMAGE_OUT is $size bytes, limit is $UIMAGE_SIZE bytes" >&2
	rm -f "$UIMAGE_OUT" "$UBOOT_HUAWEI"
	exit 1
fi

# Pad uImage file to 512kB zeros (otherwise u-boot will halt at something something hashtable)
dd if=/dev/zero of="$UIMAGE_OUT" bs=1 count=0 seek=$UIMAGE_SIZE

echo "Done."
