/*
 * Configuration for the AVM Fritz!Repeater 3000
 */

#ifndef __CONFIG_H
#define __CONFIG_H

#include <configs/ipq40xx_cdp.h>

#define CONFIG_MODEL_FRITZ3000
#define CONFIG_MODEL		"FRITZ3000"
#define MTDIDS_DEFAULT		"nand1=nand1"
#define MTDPARTS_DEFAULT	"mtdparts=nand1:2816k(urlader)ro,8448k(nand-tffs)ro,4096k(kernel)ro,4096k(reserved-kernel)ro,111616k(ubi)"

#undef CONFIG_BOOTDELAY
#define CONFIG_BOOTDELAY 3

#undef CONFIG_BOOTCOMMAND
#define CONFIG_BOOTCOMMAND		"run fritzboot"

#define CONFIG_EXTRA_ENV_SETTINGS				\
	"mtdids=" MTDIDS_DEFAULT "\0"				\
	"mtdparts=" MTDPARTS_DEFAULT "\0"			\
	"nandboot=ubi part ubi && ubi read 0x85000000 kernel && bootm\0"	\
	"tftpboot=tftpboot && bootm; sleep 5; run tftpboot\0"	\
	"fritzboot=run nandboot || run tftpboot;\0"		\

#undef V_PROMPT
#define V_PROMPT		"(" CONFIG_MODEL ") # "

#define CONFIG_AVM_QPIC_NAND
#define CONFIG_AVM_EVA_MAC_EXTRACT
#define CONFIG_AVM_EVA_CFG_OFFSET	0x2BE800

#define CONFIG_SERVERIP         192.168.1.70
#define CONFIG_NETMASK          255.255.255.0
#define CONFIG_BOOTFILE         CONFIG_MODEL ".bin"
#define CONFIG_LZO
#define CONFIG_LZMA
#define CONFIG_SYS_LONGHELP

#define CONFIG_CMD_MISC
#define CONFIG_CMD_ELF
#define CONFIG_CMD_IMI
#define CONFIG_CMD_LOADB
#define CONFIG_CMD_SPI
#define CONFIG_CMD_TFTPSRV

#undef CONFIG_SYS_LOAD_ADDR
#define CONFIG_SYS_LOAD_ADDR    0x85000000

#undef CONFIG_SYS_TEXT_BASE
#define CONFIG_SYS_TEXT_BASE	0x84200000

#endif

