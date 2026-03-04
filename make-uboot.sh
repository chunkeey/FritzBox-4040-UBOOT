#!/bin/bash

BOARDNAME=$1

die() {
	echo Error: $1
	exit 1
}

no_toolchain() {
	cat << EOF

No working toolchain was found for the given directoy.
      >>> You have to make one.<<<
LEDE/OpenWRT toolchains work fine for this.

Return once you finished.
EOF

	exit 1
}

[ -z "$BOARDNAME" ] && die "Usage: make-uboot <BOARDNAME>"

[ -e "$OPENWRT_OR_LEDE_TOOLCHAIN_FOR_ARM7" ] || no_toolchain

export PATH="$PATH:$OPENWRT_OR_LEDE_TOOLCHAIN_FOR_ARM7"

arm-openwrt-linux-gcc -v || no_toolchain
arm-openwrt-linux-ld -v || no_toolchain

make clean || die "Can't clean old cruft"

USE_PRIVATE_LIBGCC=yes make $BOARDNAME || die "Failed to set build target"

USE_PRIVATE_LIBGCC=yes make || die "Failure during u-boot build"

[ -e u-boot.bin ] || die "Build succeeded. But u-boot.bin wasn't created"

if [[ $BOARDNAME == *"huawei"* ]]; then
    huawei/huaweicreator.sh $BOARDNAME || die "Failure during Huawei creation"
else
    fritz/fritzcreator.sh $BOARDNAME || die "Failure during Fritzing"
fi

[ -e uboot-${BOARDNAME}.bin ] || die "No idea, but the uboot-${BOARDNAME}.bin wasn't created."
