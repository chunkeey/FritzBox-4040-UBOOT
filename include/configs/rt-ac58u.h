#define CONFIG_SYS_BOOTM_LEN	(32 << 20)	/* 32 MB */

#define CONFIG_MODEL		"RT-AC58U"
#define CONFIG_UBI_SUPPORT
#define CONFIG_LZO
#define CONFIG_CMD_UBIFS

#undef CONFIG_SYS_TEXT_BASE
#define CONFIG_SYS_TEXT_BASE		0x80208000

#define CONFIG_IMG_LOAD_ADDR		0x80308000
#define CONFIG_SYS_LONGHELP
#define CONFIG_LZMA

#define CONFIG_SPI_NAND_GIGA
#define CONFIG_SPI_NAND_ATO
#define CONFIG_SPI_NAND_MACRONIX
#define CONFIG_SPI_NAND_WINBOND

#define XMK_STR(_x)	#_x
#define MK_STR(_x)	XMK_STR(_x)

#define SYSUPGRADE_BOARD "asus_rt-ac58u"

#define SYSUPGRADE_KERNEL_VOLUME "linux"

/*
 * Environment variables.
 */
#define CONFIG_IPADDR		192.168.1.1
#define CONFIG_SERVERIP		192.168.1.70
#define CONFIG_NETMASK		255.255.255.0
#define CONFIG_BOOTFILE		CONFIG_MODEL ".trx"		/* RT-AC88Q.trx */

#define CONFIG_EXTRA_ENV_SETTINGS	\
	"imgaddr=0x84000000\0" \
	"initubi=mtdpart default; ubi part ubi 2048\0" \
	"delmisc=ubi remove jffs2; ubi remove linux; ubi remove kernel; ubi remove rootfs; ubi remove rootfs_data\0" \
	"sysup=sysupgrade\0" \
	"extr=imagecheck "MK_STR(CONFIG_IMG_LOAD_ADDR)"\0" \
	"flashme=run initubi; run delmisc; run extr sysup; reset\0" \
	"preferred_nic=eth0\0"

/*
 * Enable commands
 */
#define CONFIG_CMD_LOADB
#define CONFIG_CMD_SYSUPGRADE

#define CONFIG_IPQ_MAX_SPI_DEVICE       2
#define CONFIG_IPQ_MAX_NAND_DEVICE      1

#define CONFIG_IPQ_NAND_NAND_INFO_IDX   0
#define CONFIG_QPIC_NAND_NAND_INFO_IDX  0
#define CONFIG_IPQ_SPI_NAND_INFO_IDX    1
#define CONFIG_IPQ_SPI_NOR_INFO_IDX     2

#define CONFIG_BOOTCOMMAND		"run flashme"
#define CONFIG_MAC_PARTITION		"0:ART"

#include <configs/ipq40xx_cdp.h>

#define MTDIDS_DEFAULT			"nand1=nand1"
#define MTDPARTS_DEFAULT		"mtdparts=nand1:-(ubi)"

#undef CONFIG_BOOTDELAY
#define CONFIG_BOOTDELAY 3

#undef V_PROMPT
#define V_PROMPT			"(" CONFIG_MODEL ") # "
