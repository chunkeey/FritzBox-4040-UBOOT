#!/bin/sh -xe

# A helpful
#
#
#
#

UBOOT_BIN="u-boot.bin"
UBOOT_FRITZ4040="uboot-fritz4040.bin"
FRITZ_DTS="fritz/fritz4040.dts"
FRITZ_DTB="fritz4040.dtb"
UBOOT_LOADADDR=0x841FFFF8

rm -f "$UBOOT_FRITZ4040"

# Can you guys *PLEASE* switch to FIT?!

#
# Usually, the kernel has to start at 0x80208000. But AVM needed to have a
# pointer to the DTB somewhere, so they added 4 + 4 + 4 Bytes = 12 Bytes
# header (see insert-fritz-dtb-pointer) in front of the image. Since the
# "Image" is supposed to be "hack-free" and EVA isn't really that good for
# testing (INITRAMFS!). Yadayadayada...
# So here's a u-boot image for the FritzBox 4040 based on ASUS
# U-Boot for the RT-AC58u.

# The first 4 bytes are ARM-Code for a relative jump to +0x8 from this OPcode.
# The second 4 bytes are the offset of the DTB-TABLE in the memory.
# Since the (extracted) u-boot is loaded to 0xC4200000 and we align the
# DTB-Table to be at the 1MiB marker, we put the dtb table at:
# 0xC41FFFF8 + 0x00100000 + 4 * DTB_SIZE + 0x200 (PAD) = 0xC43301f8
#
# Note: the zImage has a few NOPs at the beginning. so we can replace those
# with our code here to make this work.
#
#
# Note2: The address space switches between 0x84...... in EVA to 0xc4......

printf "\x00\x00\x00\xea\xf8\x01\x33\xc4" > $UBOOT_FRITZ4040

# Append u-boot

cat "$UBOOT_BIN" >> "$UBOOT_FRITZ4040"

# Pad file to 1M
dd if="$UBOOT_FRITZ4040" of="$UBOOT_FRITZ4040.new" bs=1M count=1 conv=sync
mv "$UBOOT_FRITZ4040.new" "$UBOOT_FRITZ4040"

# Compile DTS
dtc "$FRITZ_DTS" -o "$FRITZ_DTB" --space 49152

# Append the compiled DTBs
cat "$FRITZ_DTB" "$FRITZ_DTB" "$FRITZ_DTB" "$FRITZ_DTB" >> $UBOOT_FRITZ4040
rm -f "$FRITZ_DTB"

# Add 512 bytes of pad area
printf "%0.s\0" {1..512} >> $UBOOT_FRITZ4040

# This table links to the individual DTBs for every HWSubRevision.
# A table entry consists of two 32-bit words.
#       - The first word is the HWSubrevision.
#       - The next word is a pointer to the DTB.
# The table is terminated with an sentinel entry (NULL) at the end.
#
# Note: Because the DTB is attached to this table, we point it to the end
# of this table.
# 0xC4330200 + 0x04 = 0xC4320204
# 0xC41FFFF8 + 0x100000 + 0 * DTB_SIZE = 0xC42FFFF8
# 0xC41FFFF8 + 0x100000 + 1 * DTB_SIZE = 0xC430BFF8
# ...
# 0xC41FFFF8 + 0x100000 + 3 * DTB_SIZE = 0xC4908000
# (And the last entry is left empty)
( cat "$UBOOT_FRITZ4040";                              	\
          printf "\xfc\x01\x33\xc4";                    \
          printf "\x01\x00\x00\x00\xF8\xFF\x2F\xc4";    \
          printf "\x02\x00\x00\x00\xF8\xFF\x2F\xc4";    \
          printf "\x05\x00\x00\x00\xF8\xBF\x30\xc4";    \
          printf "\x06\x00\x00\x00\xF8\x7F\x31\xc4";    \
          printf "\x07\x00\x00\x00\xF8\x3F\x32\xc4";    \
          printf "\x06\x01\x00\x00\x00\x00\x00\x00" ) > $UBOOT_FRITZ4040.new

mv "$UBOOT_FRITZ4040.new" "$UBOOT_FRITZ4040"


# Add 64k bytes of pad area
printf "%0.s\0" {1..65536} >> $UBOOT_FRITZ4040

# Pack it with lzma
fritz/lzma e "$UBOOT_FRITZ4040" -lc1 -lp2 -pb2 "$UBOOT_FRITZ4040.new"

# Make it a EVA image
fritz/lzma2eva $UBOOT_LOADADDR $UBOOT_LOADADDR "$UBOOT_FRITZ4040.new" "$UBOOT_FRITZ4040"

# The bootloader seems to add a TI checksum signature (8 Bytes) as part of the
# "check mtd1" command in the FTP prompt. To make this easier we add spacer here.
(cat "$UBOOT_FRITZ4040"; printf "\xff\xff\xff\xff\xff\xff\xff\xff" ) > $UBOOT_FRITZ4040.new

# The next bit. The hshqs partition should be aligned to 0x100
let size=$(stat -c%s "$UBOOT_FRITZ4040")
let "pad = 256 - ( $size % 256) % 256"
( printf "%0.s\377" {1..256} | dd conv=sync bs=$pad count=1 ) > $UBOOT_FRITZ4040.pad

cat "$UBOOT_FRITZ4040" "$UBOOT_FRITZ4040.pad" > $UBOOT_FRITZ4040.new

mv "$UBOOT_FRITZ4040.new" "$UBOOT_FRITZ4040"

rm -f "$UBOOT_FRITZ4040.pad"

# Apparently, EVA checks for the SquashFS filesystem MAGIC too. Likely for the rootfs
# entry.
(cat "$UBOOT_FRITZ4040"; echo "hsqs"; printf "%0.s\0" {1..124} ) > $UBOOT_FRITZ4040.new

# Make it so that this fits into 512k (Note: we have to add 8 Bytes for the final checksum
# so 524280 is 512k - 8.
dd if="$UBOOT_FRITZ4040.new" of="$UBOOT_FRITZ4040" conv=sync bs=524280 count=1
rm "$UBOOT_FRITZ4040.new"

fritz/tichksum -a "$UBOOT_FRITZ4040"

echo "Done."
