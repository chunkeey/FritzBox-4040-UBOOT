/*
 * Configuration for Huawei AP4050DN
 */

#ifndef __CONFIG_H
#define __CONFIG_H

#include <configs/ipq40xx_cdp.h>

#define CONFIG_MODEL_HUAWEI_AP4050DN
#define CONFIG_MODEL		"AP4050DN"
#define MTDIDS_DEFAULT		"nand0=nand0" // TODO
#define MTDPARTS_DEFAULT	"mtdparts=nand0:256k(0:SBL1),256k(0:MIBIB),512k(0:QSEE),256k(0:CDT),256k(0:DDRPARAMS),1024k(0:APPSBL),256k(0:ART),256k(0:APPSBLENV),512k(ResultA),2560k(configA),1024k(bootimageA),512k(uboot),25088k(SysImageA),256k(1:SBL1),256k(1:MIBIB),512k(1:QSEE),256k(1:CDT),256k(1:DDRPARAMS),1024k(1:APPSBL),512k(Reservel),512k(ResultB),2560k(configB),1024k(bootimageB),25600k(SysImageB)"

#undef CONFIG_BOOTDELAY
#define CONFIG_BOOTDELAY 3

#undef CONFIG_BOOTCOMMAND
#define CONFIG_BOOTCOMMAND		"run huaweiboot" // TODO

#define CONFIG_MAC_PARTITION	"ResultA"  // TODO: ???

#define CONFIG_EXTRA_ENV_SETTINGS				\
	"mtdids=" MTDIDS_DEFAULT "\0"				\
	"mtdparts=" MTDPARTS_DEFAULT "\0"			\
	"huaweiboot=nboot SysImageA && bootm\0"		\
	"bootargs=console=ttyMSM0,9600n8\0"			\

#undef V_PROMPT
#define V_PROMPT				"(" CONFIG_MODEL ") # "

#undef CONFIG_BAUDRATE
#define CONFIG_BAUDRATE		9600
#define CONFIG_SERVERIP		192.168.1.10
#define CONFIG_NETMASK		255.255.255.0
#define CONFIG_BOOTFILE		"openwrt-ipq40xx-generic-huawei_ap4050dn-initramfs-uImage.itb"
#define CONFIG_LZO
#define CONFIG_LZMA
#define CONFIG_SYS_LONGHELP
#define CONFIG_AUTO_COMPLETE
#define CONFIG_SYS_HUSH_PARSER
#define CONFIG_HW_WATCHDOG

#define CONFIG_CMD_MISC
#define CONFIG_CMD_ELF
#define CONFIG_CMD_IMI
#define CONFIG_CMD_LOADB
#define CONFIG_CMD_SPI
#define CONFIG_CMD_TFTPSRV
#define CONFIG_CMD_ASKENV
#define CONFIG_CMD_BDI		/* bdinfo			*/
#define CONFIG_CMD_BOOTD	/* bootd			*/
#define CONFIG_CMD_BSP		/* Board Specific functions	*/
#define CONFIG_CMD_CONSOLE	/* coninfo			*/
#define CONFIG_CMD_DHCP		/* DHCP Support			*/
#define CONFIG_CMD_DIAG		/* Diagnostics			*/
#define CONFIG_CMD_ECHO		/* echo arguments		*/
#define CONFIG_CMD_EDITENV	/* editenv			*/
#define CONFIG_CMD_FLASH	/* flinfo, erase, protect	*/
#define CONFIG_CMD_IMMAP	/* IMMR dump support		*/
#define CONFIG_CMD_LOADS	/* loads			*/
#define CONFIG_CMD_PORTIO	/* Port I/O			*/
#define CONFIG_CMD_REGINFO	/* Register dump		*/
#define CONFIG_CMD_SAVES	/* save S record dump		*/
#define CONFIG_CMD_SDRAM	/* SDRAM DIMM SPD info printout */
#define CONFIG_CMD_SETEXPR	/* setexpr support		*/

#undef CONFIG_SYS_LOAD_ADDR
#define CONFIG_SYS_LOAD_ADDR	0x85000000

#undef CONFIG_SYS_TEXT_BASE
#define CONFIG_SYS_TEXT_BASE	0x84000040

#endif /* __CONFIG_H */
