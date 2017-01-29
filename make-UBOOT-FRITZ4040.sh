#!/bin/sh

OPENWRT_OR_LEDE_TOOLCHAIN_FOR_ARM7_WITHOUT_VFP=/mnt/build/src2/f4040-uboot/staging_dir/toolchain-arm_cortex-a7_gcc-5.4.0_musl-1.1.16_eabi/bin/

die() {
	echo Error: $1
	exit 1
}

no_toolchain() {
	cat << EOF

No working toolchain was found for the given directoy.
      >>> You have to make one.<<<
LEDE/OpenWRT toolchains work fine for thah. But they
need to be compiled without NEON(v2) or VFP as these
won't work with u-boot.

Here's a patch for the armvirt target that can
be used. Just apply it and build a image. The
toolchain will automatically be created for you:
---
diff --git a/target/linux/armvirt/Makefile b/target/linux/armvirt/Makefile
index 3fedcad0a0..fcea7b5e9a 100644
--- a/target/linux/armvirt/Makefile
+++ b/target/linux/armvirt/Makefile
@@ -9,9 +9,7 @@
 ARCH:=arm
 BOARD:=armvirt
 BOARDNAME:=QEMU ARM Virtual Machine
-FEATURES:=fpu pci rtc usb
-FEATURES+=cpiogz ext4 ramdisk squashfs targz
-CPU_TYPE:=cortex-a15
-CPU_SUBTYPE:=neon-vfpv4
+FEATURES:=pci
+CPU_TYPE:=cortex-a7
 MAINTAINER:=Yousong Zhou <yszhou4tech@gmail.com>
 
---

Return once you finished.
EOF

	exit 1
}

[ -e "$OPENWRT_OR_LEDE_TOOLCHAIN_FOR_ARM7_WITHOUT_VFP" ] || no_toolchain

export PATH="$PATH:$OPENWRT_OR_LEDE_TOOLCHAIN_FOR_ARM7_WITHOUT_VFP"

arm-openwrt-linux-gcc -v || no_toolchain
arm-openwrt-linux-ld -v || no_toolchain

make clean || die "Can't clean old cruft"

make fritz4040 || die "Failed to set build target"

make || die "Failure during u-boot build"

[ -e u-boot.bin ] || die "Build succeeded. But u-boot.bin wasn't created"

fritz/fritzcreator.sh || die "Failure during Fritzing"

[ -e uboot-fritz4040.bin ] || die "No idea, but the uboot-fritz4040.bin wasn't created."
