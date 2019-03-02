/*
 *
 * Copyright (c) 2015,2016 The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of The Linux Foundation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <common.h>
#include <asm/global_data.h>
#include <asm/io.h>
#include <asm/arch-qcom-common/gpio.h>
#include <asm/errno.h>
#include <asm/arch-ipq40xx/ess/ipq40xx_edma.h>
#include <environment.h>
#include <configs/ipq40xx_cdp.h>
#include "ipq40xx_cdp.h"
#include "ipq40xx_board_param.h"
#include <asm/arch-ipq40xx/scm.h>
#include <nand.h>
#include <phy.h>
#include <part.h>
#include <mmc.h>
#include "ipq40xx_edma_eth.h"
#ifdef CONFIG_IPQ_NAND
#include <linux/mtd/ipq_nand.h>
#include <asm/arch-qcom-common/nand.h>
#else
#include <asm/arch-qcom-common/qpic_nand.h>
#endif
#include <mtd_node.h>
#include <jffs2/load_kernel.h>
#include <asm/arch-qcom-common/clk.h>
#include <asm/arch-ipq40xx/smem.h>

DECLARE_GLOBAL_DATA_PTR;

loff_t board_env_offset;
loff_t board_env_range;
loff_t board_env_size;
extern int nand_env_device;
char *env_name_spec;
extern char *mmc_env_name_spec;
extern char *nand_env_name_spec;
int (*saveenv)(void);
env_t *env_ptr;
extern env_t *mmc_env_ptr;
extern env_t *nand_env_ptr;
extern int nand_env_init(void);
extern int nand_saveenv(void);
extern int qpic_nand_init(struct qpic_nand_init_config *config);
extern void nand_env_relocate_spec(void);
extern int ipq40xx_edma_init(ipq40xx_edma_board_cfg_t *edma_cfg);
extern int ipq40xx_qca8075_phy_init(struct ipq40xx_eth_dev *cfg);
extern void ipq40xx_register_switch(
	int (*sw_init)(struct ipq40xx_eth_dev *cfg));
extern int mmc_env_init(void);
extern int mmc_saveenv(void);
extern void mmc_env_relocate_spec(void);
extern int fdt_node_set_part_info(void *blob, int parent_offset,
					struct mtd_device *dev);
#ifdef CONFIG_IPQ40XX_SPI
extern int ipq_spi_init(u16 idx);
#endif
#ifdef CONFIG_QCA_MMC
qca_mmc mmc_host;
#endif

/*
 * Don't have this as a '.bss' variable. The '.bss' and '.rel.dyn'
 * sections seem to overlap.
 *
 * $ arm-none-linux-gnueabi-objdump -h u-boot
 * . . .
 *  8 .rel.dyn      00004ba8  40630b0c  40630b0c  00038b0c  2**2
 *                  CONTENTS, ALLOC, LOAD, READONLY, DATA
 *  9 .bss          0000559c  40630b0c  40630b0c  00000000  2**3
 *                  ALLOC
 * . . .
 *
 * board_early_init_f() initializes this variable, resulting in one
 * of the relocation entries present in '.rel.dyn' section getting
 * corrupted. Hence, when relocate_code()'s 'fixrel' executes, it
 * patches a wrong address, which incorrectly modifies some global
 * variable resulting in a crash.
 *
 * Moral of the story: Global variables that are written before
 * relocate_code() gets executed cannot be in '.bss'
 */
board_ipq40xx_params_t *gboard_param = (board_ipq40xx_params_t *)0xbadb0ad;

#define SET_MAGIC 0x1
#define CLEAR_MAGIC 0x0
#define SCM_CMD_TZ_CONFIG_HW_FOR_RAM_DUMP_ID 0x9
#define SCM_CMD_TZ_FORCE_DLOAD_ID 0x10

#define BOOT_VERSION	0
#define TZ_VERSION	1
/*******************************************************
 Function description: Board specific initialization.
 I/P : None
 O/P : integer, 0 - no error.

********************************************************/
static board_ipq40xx_params_t *get_board_param(unsigned int machid)
{
	unsigned int index;

	printf("machid : 0x%0x\n", machid);
	for (index = 0; index < NUM_IPQ40XX_BOARDS; index++) {
		if (machid == board_params[index].machid)
			return &board_params[index];
	}
	BUG_ON(index == NUM_IPQ40XX_BOARDS);
	printf("cdp: Invalid machine id 0x%x\n", machid);
	for (;;);
}


int env_init(void)
{
	int ret = 0;
	qca_smem_flash_info_t sfi;

	smem_get_boot_flash(&sfi.flash_type,
				&sfi.flash_index,
				&sfi.flash_chip_select,
				&sfi.flash_block_size,
				&sfi.flash_density);

#if 0
	if (sfi.flash_type != SMEM_BOOT_MMC_FLASH) {
		ret = nand_env_init();
#ifdef CONFIG_QCA_MMC
	} else {
		ret = mmc_env_init();
#endif
	}
#endif

	return ret;
}

void env_relocate_spec(void)
{
	qca_smem_flash_info_t sfi;

	smem_get_boot_flash(&sfi.flash_type,
				&sfi.flash_index,
				&sfi.flash_chip_select,
				&sfi.flash_block_size,
				&sfi.flash_density);

#if 0
	if (sfi.flash_type != SMEM_BOOT_MMC_FLASH) {
		nand_env_relocate_spec();
#ifdef CONFIG_QCA_MMC
	} else {
		mmc_env_relocate_spec();
#endif
	}
#endif

};

int board_init(void)
{
	int ret;
	uint32_t start_blocks;
	uint32_t size_blocks;

	qca_smem_flash_info_t *sfi = &qca_smem_flash_info;

	gd->bd->bi_boot_params = QCA_BOOT_PARAMS_ADDR;
	gd->bd->bi_arch_number = smem_get_board_platform_type();
	gboard_param = get_board_param(gd->bd->bi_arch_number);

	ret = smem_get_boot_flash(&sfi->flash_type,
					&sfi->flash_index,
					&sfi->flash_chip_select,
					&sfi->flash_block_size,
					&sfi->flash_density);
	if (ret < 0) {
		printf("cdp: get boot flash failed\n");
		return ret;
	}

	/*
	 * Should be inited, before env_relocate() is called,
	 * since env. offset is obtained from SMEM.
	 */
	if (sfi->flash_type != SMEM_BOOT_MMC_FLASH) {
		ret = smem_ptable_init();
		if (ret < 0) {
			printf("cdp: SMEM init failed\n");
			return ret;
		}
	}

	if (sfi->flash_type == SMEM_BOOT_NAND_FLASH) {
		nand_env_device = CONFIG_QPIC_NAND_NAND_INFO_IDX;
	} else if (sfi->flash_type == SMEM_BOOT_SPI_FLASH) {
		nand_env_device = CONFIG_IPQ_SPI_NOR_INFO_IDX;
	} else if (sfi->flash_type != SMEM_BOOT_MMC_FLASH) {
		printf("BUG: unsupported flash type : %d\n", sfi->flash_type);
		BUG();
	}

	if (sfi->flash_type != SMEM_BOOT_MMC_FLASH) {
		board_env_range = CONFIG_ENV_SIZE;
		board_env_size = CONFIG_ENV_SIZE;

		ret = smem_getpart("0:APPSBLENV", &start_blocks, &size_blocks);
		if (ret < 0) {
			printf("cdp: get environment part failed\n");
			return ret;
		}

		board_env_offset = ((loff_t) sfi->flash_block_size) * start_blocks;
		board_env_size = ((loff_t) sfi->flash_block_size) * size_blocks;
	}

	if (sfi->flash_type == SMEM_BOOT_NAND_FLASH) {
		board_env_range = CONFIG_ENV_SIZE_MAX;
		BUG_ON(board_env_size < CONFIG_ENV_SIZE_MAX);
	} else if (sfi->flash_type == SMEM_BOOT_SPI_FLASH) {
		board_env_range = board_env_size;
		BUG_ON(board_env_size > CONFIG_ENV_SIZE_MAX);
#ifdef CONFIG_QCA_MMC
	} else if (sfi->flash_type == SMEM_BOOT_MMC_FLASH) {
		board_env_range = CONFIG_ENV_SIZE_MAX;
#endif
	} else {
		printf("BUG: unsupported flash type : %d\n", sfi->flash_type);
		BUG();
	}

	if (sfi->flash_type != SMEM_BOOT_MMC_FLASH) {
		saveenv = nand_saveenv;
		env_ptr = nand_env_ptr;
		env_name_spec = nand_env_name_spec;
#ifdef CONFIG_QCA_MMC
	} else {
		saveenv = mmc_saveenv;
		env_ptr = mmc_env_ptr;
		env_name_spec = mmc_env_name_spec;
#endif
	}
	return 0;
}

void qca_get_part_details(void)
{
	smem_listparts();

#if 0
	int ret, i;
	uint32_t start;         /* block number */
	uint32_t size;          /* no. of blocks */

	qca_smem_flash_info_t *smem = &qca_smem_flash_info;

	struct { char *name; qca_part_entry_t *part; } entries[] = {
		{ "0:HLOS", &smem->hlos },
		{ "rootfs", &smem->rootfs },
	};

	for (i = 0; i < ARRAY_SIZE(entries); i++) {
		ret = smem_getpart(entries[i].name, &start, &size);
		if (ret < 0) {
			qca_part_entry_t *part = entries[i].part;
			debug("cdp: get part failed for %s\n", entries[i].name);
			part->offset = 0xBAD0FF5E;
			part->size = 0xBAD0FF5E;
		} else {
			qca_set_part_entry(entries[i].name, smem, entries[i].part, start, size);
		}
	}

#endif
	return;
}

int board_late_init(void)
{
	unsigned int machid;
	qca_smem_flash_info_t *sfi = &qca_smem_flash_info;

	if (sfi->flash_type != SMEM_BOOT_MMC_FLASH) {
		qca_get_part_details();
	}

	/* get machine type from SMEM and set in env */
	machid = gd->bd->bi_arch_number;
	printf("machid: %x\n", machid);
	if (machid != 0) {
		setenv_addr("machid", (void *)machid);
		gd->bd->bi_arch_number = machid;
	}

	return 0;
}

/*
 * This function is called in the very beginning.
 * Retreive the machtype info from SMEM and map the board specific
 * parameters. Shared memory region at Dram address 0x40400000
 * contains the machine id/ board type data polulated by SBL.
 */
int board_early_init_f(void)
{
	/* Retrieve from SMEM */
	gboard_param = get_board_param(smem_get_board_platform_type());
	return 0;
}

void enable_caches(void)
{
	icache_enable();
}

void clear_l2cache_err(void)
{
	return;
}

static void reset_crashdump(void)
{
	unsigned int magic_cookie = CLEAR_MAGIC;
	unsigned int clear_info[] =
		{ 1 /* Disable wdog debug */, 0 /* SDI enable*/, };
	scm_call(SCM_SVC_BOOT, SCM_CMD_TZ_CONFIG_HW_FOR_RAM_DUMP_ID,
		(const void *)&clear_info, sizeof(clear_info), NULL, 0);
	scm_call(SCM_SVC_BOOT, SCM_CMD_TZ_FORCE_DLOAD_ID, &magic_cookie,
			sizeof(magic_cookie), NULL, 0);
}
void reset_cpu(ulong addr)
{
	/* Clear Debug sw entry register */
	reset_crashdump();
	/* clear ps-hold bit to reset the soc */
	writel(0, GCNT_PSHOLD);
	while (1);
}

int dram_init(void)
{
	struct smem_ram_ptable rtable;
	int i;
	int mx = ARRAY_SIZE(rtable.parts);

	if (smem_ram_ptable_init(&rtable) > 0) {
		gd->ram_size = 0;
		for (i = 0; i < mx; i++) {
			if (rtable.parts[i].category == RAM_PARTITION_SDRAM &&
			    rtable.parts[i].type == RAM_PARTITION_SYS_MEMORY) {
				gd->ram_size += rtable.parts[i].size;
			}
		}
		gboard_param->ddr_size = gd->ram_size;
	} else {
		gd->ram_size = gboard_param->ddr_size;
	}
	return 0;
}

void board_nand_init(void)
{
	gpio_func_data_t *gpio;
#ifdef CONFIG_IPQ_NAND
	ipq_nand_init(IPQ_NAND_LAYOUT_LINUX, QCOM_NAND_QPIC);
#else
	if ((gboard_param->machid == MACH_TYPE_IPQ40XX_AP_DK04_1_C1) ||
		(gboard_param->machid == MACH_TYPE_IPQ40XX_DB_DK02_1_C1) ||
		(gboard_param->machid == MACH_TYPE_IPQ40XX_AP_DK04_1_C3) ||
		(gboard_param->machid == MACH_TYPE_IPQ40XX_AP_DK06_1_C1)) {

		struct qpic_nand_init_config config;
		config.pipes.read_pipe = DATA_PRODUCER_PIPE;
		config.pipes.write_pipe = DATA_CONSUMER_PIPE;
		config.pipes.cmd_pipe = CMD_PIPE;

		config.pipes.read_pipe_grp = DATA_PRODUCER_PIPE_GRP;
		config.pipes.write_pipe_grp = DATA_CONSUMER_PIPE_GRP;
		config.pipes.cmd_pipe_grp = CMD_PIPE_GRP;

		config.bam_base = IPQ40xx_QPIC_BAM_CTRL;
		config.nand_base = IPQ40xx_EBI2ND_BASE;
		config.ee = QPIC_NAND_EE;
		config.max_desc_len = QPIC_NAND_MAX_DESC_LEN;
		gpio = gboard_param->nand_gpio;
		if (gpio) {
			qca_configure_gpio(gpio,
				gboard_param->nand_gpio_count);
		}
		gpio = gboard_param->spi_nor_gpio;
		if (gpio) {
			qca_configure_gpio(gpio,
				gboard_param->spi_nor_gpio_count);
		}
		qpic_nand_init(&config);
	}
#endif
#ifdef CONFIG_IPQ40XX_SPI
	ipq_spi_init(CONFIG_IPQ_SPI_NOR_INFO_IDX);
#endif
}

/*
 * Gets the ethernet address from the ART partition table and return the value
 */
int get_eth_mac_address(uchar *enetaddr, uint no_of_macs)
{
	s32 ret = 0 ;
	u32 start_blocks;
	u32 size_blocks;
	u32 length = (6 * no_of_macs);
	u32 flash_type;
	loff_t art_offset;
	qca_smem_flash_info_t *sfi = &qca_smem_flash_info;
#ifdef CONFIG_QCA_MMC
	block_dev_desc_t *blk_dev;
	disk_partition_t disk_info;
	struct mmc *mmc;
	char mmc_blks[512];
#endif

#if defined CONFIG_AVM_EVA_MAC_EXTRACT
	const u32 *urconfig;

	/* ART partition 0th position will contain Mac address. */
	u8 data[1024];
	length = sizeof(data);
	art_offset = CONFIG_AVM_EVA_CFG_OFFSET;

	#if defined CONFIG_AVM_SPI_NOR
	ret = nand_read(&nand_info[CONFIG_IPQ_SPI_NOR_INFO_IDX], art_offset,
			&length, data);
	#elif defined CONFIG_AVM_QPIC_NAND
	ret = nand_read(&nand_info[CONFIG_QPIC_NAND_NAND_INFO_IDX], art_offset,
			&length, data);
	#endif

	if (ret < 0) {
		printf("ART partition read failed..\n");
		return -EINVAL;
	}

	printf("Read %d bytes from 0%x\n", length, art_offset);
	if (length < sizeof(data))
		return -EINVAL;

	urconfig = (const u32 *)&data[0x98];
	if (*urconfig > (art_offset + length - 6) || *urconfig < art_offset) {
		printf("maca pointer invalid: %x\n", *urconfig);
		return -EINVAL;
	}

	eth_parse_enetaddr(&data[*urconfig - art_offset], enetaddr);

	printf("maca: %x:%x:%x:%x:%x:%x\n", enetaddr[0], enetaddr[1], enetaddr[2],
		enetaddr[3], enetaddr[4], enetaddr[5]);

	urconfig = (const uint32_t *)&data[0xA0];
	if (*urconfig > (art_offset + length - 6) || *urconfig < art_offset) {
		printf("macb pointer invalid: %x\n", urconfig[0x28]);
		return -EINVAL;
	}

	eth_parse_enetaddr(&data[*urconfig - art_offset], &enetaddr[6]);

	printf("macb: %x:%x:%x:%x:%x:%x\n", enetaddr[6], enetaddr[7], enetaddr[8],
		enetaddr[9], enetaddr[10], enetaddr[11]);

	return 0;
#else
	if (sfi->flash_type != SMEM_BOOT_MMC_FLASH) {
		if (qca_smem_flash_info.flash_type == SMEM_BOOT_SPI_FLASH)
			flash_type = CONFIG_IPQ_SPI_NOR_INFO_IDX;
		else if (qca_smem_flash_info.flash_type == SMEM_BOOT_NAND_FLASH)
			flash_type = CONFIG_IPQ_NAND_NAND_INFO_IDX;
		else {
			printf("Unknown flash type\n");
			return -EINVAL;
		}

		ret = smem_getpart("0:APPSBL", &start_blocks, &size_blocks);
		if (ret < 0) {
			printf("No ART partition found\n");
			return ret;
		}

		ret = nand_read(&nand_info[flash_type], art_offset, &length, enetaddr);
		if (ret < 0)
			printf("ART partition read failed..\n");
#ifdef CONFIG_QCA_MMC
	} else {
		blk_dev = mmc_get_dev(mmc_host.dev_num);
		ret = find_part_efi(blk_dev, "0:ART", &disk_info);
		/*
		 * ART partition 0th position will contain MAC address.
		 * Read 1 block.
		 */
		if (ret > 0) {
			mmc = mmc_host.mmc;
			ret = mmc->block_dev.block_read
				(mmc_host.dev_num, disk_info.start,
						1, mmc_blks);
			memcpy(enetaddr, mmc_blks, length);
                }
		if (ret < 0)
			printf("ART partition read failed..\n");
#endif
#endif
	return ret;
}

static void ipq40xx_set_ethmac_addr(void)
{
	int i, ret;
	uchar enetaddr[CONFIG_IPQ_NO_MACS * 6];
	uchar *mac_addr;
	char ethaddr[16] = "ethaddr";
	char mac[64];
	/* Get the MAC address from ART partition */
	ret = get_eth_mac_address(enetaddr, CONFIG_IPQ_NO_MACS);
	for (i = 0; (ret >= 0) && (i < CONFIG_IPQ_NO_MACS); i++) {
		mac_addr = &enetaddr[i * 6];
		if (!is_valid_ether_addr(mac_addr)) {
			printf("eth%d MAC Address from ART is not valid\n", i);
		} else {
			/*
			 * U-Boot uses these to patch the 'local-mac-address'
			 * dts entry for the ethernet entries, which in turn
			 * will be picked up by the HLOS driver
			 */
			sprintf(mac, "%x:%x:%x:%x:%x:%x",
					mac_addr[0], mac_addr[1],
					mac_addr[2], mac_addr[3],
					mac_addr[4], mac_addr[5]);
			setenv(ethaddr, mac);
		}
		sprintf(ethaddr, "eth%daddr", (i + 1));
	}
}

static void ipq40xx_edma_common_init(void)
{
	writel(1, GCC_ESS_BCR);
	mdelay(10);
	writel(0, GCC_ESS_BCR);
	mdelay(100);

	writel(1, GCC_MDIO_AHB_CBCR);
	writel(MDIO_CTRL_0_DIV(0xff) |
		MDIO_CTRL_0_MDC_MODE |
		MDIO_CTRL_0_GPHY(0xa), MDIO_CTRL_0_REG);
}

int board_eth_init(bd_t *bis)
{
	u32 status;
	gpio_func_data_t *gpio;
	ipq40xx_edma_common_init();
	gpio = gboard_param->sw_gpio;
	if (gpio) {
		printf("Configure GPIOS");
		qca_configure_gpio(gpio, gboard_param->sw_gpio_count);
	}
	switch (gboard_param->machid) {
	case MACH_TYPE_IPQ40XX_AP_DK01_1_S1:
		mdelay(100);
		writel(GPIO_OUT, GPIO_IN_OUT_ADDR(62));
		ipq40xx_register_switch(ipq40xx_qca8075_phy_init);
		break;
	case MACH_TYPE_IPQ40XX_AP_DK01_1_C1:
		mdelay(100);
		writel(GPIO_OUT, GPIO_IN_OUT_ADDR(59));
		ipq40xx_register_switch(ipq40xx_qca8075_phy_init);
		break;
	case MACH_TYPE_IPQ40XX_AP_DK01_1_C2:
		mdelay(100);
		writel(GPIO_OUT, GPIO_IN_OUT_ADDR(62));
		ipq40xx_register_switch(ipq40xx_qca8075_phy_init);
		break;
	case MACH_TYPE_IPQ40XX_AP_DK04_1_C1:
	case MACH_TYPE_IPQ40XX_AP_DK04_1_C3:
		mdelay(100);
		writel(GPIO_OUT, GPIO_IN_OUT_ADDR(47));
		ipq40xx_register_switch(ipq40xx_qca8075_phy_init);
		break;
	 case MACH_TYPE_IPQ40XX_AP_DK04_1_C2:
		mdelay(100);
		writel(GPIO_OUT, GPIO_IN_OUT_ADDR(67));
		ipq40xx_register_switch(ipq40xx_qca8075_phy_init);
		break;
	 case MACH_TYPE_IPQ40XX_AP_DK06_1_C1:
		mdelay(100);
		writel(GPIO_OUT, GPIO_IN_OUT_ADDR(19));
		ipq40xx_register_switch(ipq40xx_qca8075_phy_init);
		break;
	case MACH_TYPE_IPQ40XX_DB_DK01_1_C1:
	case MACH_TYPE_IPQ40XX_DB_DK02_1_C1:
		gpio = gboard_param->rgmii_gpio;
		if (gpio) {
			qca_configure_gpio(gpio, gboard_param->rgmii_gpio_count);
		}
		break;
	default:
		break;
	}
	status = ipq40xx_edma_init(gboard_param->edma_cfg);
	return status;
}

void qca_configure_gpio(gpio_func_data_t *gpio, uint count)
{
	int i;

	for (i = 0; i < count; i++) {
		gpio_tlmm_config(gpio->gpio, gpio->func, gpio->out,
			gpio->pull, gpio->drvstr, gpio->oe,
			gpio->gpio_vm, gpio->gpio_od_en, gpio->gpio_pu_res);
		gpio++;
	}
}

#ifdef CONFIG_OF_BOARD_SETUP
struct flash_node_info {
	const char *compat;	/* compatible string */
	int type;		/* mtd flash type */
	int idx;		/* flash index */
};

void ipq_fdt_fixup_version(void *blob)
{
	int nodeoff, ret;
	char ver[OEM_VERSION_STRING_LENGTH + VERSION_STRING_LENGTH + 1];

	nodeoff = fdt_node_offset_by_compatible(blob, -1, "qcom,ipq4019");

	if (nodeoff < 0) {
		debug("ipq: fdt fixup unable to find compatible node\n");
		return;
	}

	if (!smem_get_build_version(ver, sizeof(ver), BOOT_VERSION)) {
		debug("BOOT Build Version:  %s\n", ver);
		ret = fdt_setprop(blob, nodeoff, "boot_version",
				ver, strlen(ver));
		if (ret)
			debug("%s: unable to set Boot version\n", __func__);
	}

	if (!smem_get_build_version(ver, sizeof(ver), TZ_VERSION)) {
		debug("TZ Build Version:  %s\n", ver);
		ret = fdt_setprop(blob, nodeoff, "tz_version",
				ver, strlen(ver));
		if (ret)
			debug("%s: unable to set TZ version\n", __func__);
	}
}

void ipq_fdt_fixup_mtdparts(void *blob, struct flash_node_info *ni)
{
	struct mtd_device *dev;
	char *parts;
	int noff;

	parts = getenv("mtdparts");
	if (!parts)
		return;

	if (mtdparts_init() != 0)
		return;

	for (; ni->compat; ni++) {
		noff = fdt_node_offset_by_compatible(blob, -1, ni->compat);
		while (noff != -FDT_ERR_NOTFOUND) {
			dev = device_find(ni->type, ni->idx);
			if (dev) {
				if (fdt_node_set_part_info(blob, noff, dev))
					return; /* return on error */
			}

			/* Jump to next flash node */
			noff = fdt_node_offset_by_compatible(blob, noff,
							     ni->compat);
		}
	}
}
/*
 * For newer kernel that boot with device tree (3.14+), all of memory is
 * described in the /memory node, including areas that the kernel should not be
 * touching.
 *
 * By default, u-boot will walk the dram bank info and populate the /memory
 * node; here, overwrite this behavior so we describe all of memory instead.
 */
void ft_board_setup(void *blob, bd_t *bd)
{
	u64 memory_start = CONFIG_SYS_SDRAM_BASE;
	u64 memory_size = gboard_param->ddr_size;
	char *mtdparts = NULL;
	char parts_str[256];
	qca_smem_flash_info_t *sfi = &qca_smem_flash_info;

	fdt_fixup_memory_banks(blob, &memory_start, &memory_size, 1);
	ipq_fdt_fixup_version(blob);

	ipq40xx_set_ethmac_addr();

	fdt_fixup_ethernet(blob);
}

#endif /* CONFIG_OF_BOARD_SETUP */

#ifdef CONFIG_QCA_MMC
int board_mmc_env_init(void)
{
	block_dev_desc_t *blk_dev;
	disk_partition_t disk_info;
	int ret = 0;

	if (mmc_init(mmc_host.mmc)) {
		/* The HS mode command(cmd6) is getting timed out. So mmc card is
		 * not getting initialized properly. Since the env partition is not
		 * visible, the env default values are writing into the default
		 * partition (start of the mmc device). So do a reset again.
		 */
		if (mmc_init(mmc_host.mmc)) {
			printf("MMC init failed \n");
			return -1;
		}
	}
	blk_dev = mmc_get_dev(mmc_host.dev_num);
	ret = find_part_efi(blk_dev, "0:APPSBLENV", &disk_info);

	if (ret > 0) {
		board_env_offset = disk_info.start * disk_info.blksz;
		board_env_size = disk_info.size * disk_info.blksz;
		board_env_range = board_env_size;
		BUG_ON(board_env_size > CONFIG_ENV_SIZE_MAX);
	}
	return ret;
}

int board_mmc_init(bd_t *bis)
{
	int ret;
	qca_smem_flash_info_t *sfi = &qca_smem_flash_info;

	if (!gboard_param->mmc_gpio_count)
		return 0;

	qca_configure_gpio(gboard_param->mmc_gpio,
			gboard_param->mmc_gpio_count);

	mmc_host.base = MSM_SDC1_BASE;
	mmc_host.clk_mode = MMC_IDENTIFY_MODE;
	emmc_clock_config(mmc_host.clk_mode);

	ret = qca_mmc_init(bis, &mmc_host);

	if (!ret && sfi->flash_type == SMEM_BOOT_MMC_FLASH) {
		ret = board_mmc_env_init();
	}

	return ret;
}

void board_mmc_deinit(void)
{
	emmc_clock_disable();
}
#endif

#ifdef CONFIG_IPQ40XX_PCI
void pcie_config_gpio(pcie_params_t *cfg, int enable)
{
	int i;
	gpio_func_data_t *gpio_data;
	gpio_data = cfg->pci_gpio;

	for (i = 0; i < cfg->pci_gpio_count; i++) {
		if (enable)
			gpio_tlmm_config(gpio_data->gpio, gpio_data->func,
					gpio_data->out, gpio_data->pull,
					gpio_data->drvstr, gpio_data->oe,
					gpio_data->gpio_vm, gpio_data->gpio_od_en,
					gpio_data->gpio_pu_res);
		else
			gpio_tlmm_config(gpio_data->gpio, gpio_data->func,
					GPIO_OUT_LOW, GPIO_NO_PULL,
					GPIO_2MA, GPIO_OE_DISABLE,
					GPIO_VM_DISABLE, GPIO_OD_DISABLE,
					gpio_data->gpio_pu_res);
		gpio_data++;
	}
}

void pcie_controller_reset(int id)
{
	uint32_t val;
	pcie_params_t *cfg;
	cfg = &gboard_param->pcie_cfg[id];

	/* Enable PCIE CLKS */
	pcie_clock_enable(GCC_PCIE_SLEEP_CBCR);
	pcie_clock_enable(GCC_PCIE_AXI_M_CBCR);
	pcie_clock_enable(GCC_PCIE_AXI_S_CBCR);
	pcie_clock_enable(GCC_PCIE_AHB_CBCR);

	/* Assert cc_pcie20_core_ares */
	writel(PCIE_RST_CTRL_PIPE_ARES, cfg->pcie_rst);

	/* Assert cc_pcie20_core_sticky_area */
	val = readl(cfg->pcie_rst);
	val |= PCIE_RST_CTRL_PIPE_STICKY_ARES;
	writel(val, cfg->pcie_rst);

	/* Assert cc_pcie20_phy_ahb_ares */
	val = readl(cfg->pcie_rst);
	val |= PCIE_RST_CTRL_PIPE_PHY_AHB_ARES;
	writel(val, cfg->pcie_rst);

	gpio_set_value(PCIE_RST_GPIO, GPIO_OUT_LOW);

	/* Assert cc_pcie20_mstr_axi_ares */
	val = readl(cfg->pcie_rst);
	val |= PCIE_RST_CTRL_AXI_M_ARES;
	writel(val, cfg->pcie_rst);

	/* Assert cc_pcie20_mstr_sticky_ares */
	val = readl(cfg->pcie_rst);
	val |= PCIE_RST_CTRL_AXI_M_STICKY_ARES;
	writel(val, cfg->pcie_rst);

	/* Assert cc_pcie20_slv_axi_ares */
	val = readl(cfg->pcie_rst);
	val |= PCIE_RST_CTRL_AXI_S_ARES;
	writel(val, cfg->pcie_rst);

	/* Assert cc_pcie20_ahb_ares;  */
	val = readl(cfg->pcie_rst);
	val |= PCIE_RST_CTRL_AHB_ARES;
	writel(val, cfg->pcie_rst);

	/* DeAssert cc_pcie20_phy_ahb_ares  */
	val = readl(cfg->pcie_rst);
	val &= ~(PCIE_RST_CTRL_AHB_ARES);
	writel(val, cfg->pcie_rst);

	/* DeAssert cc_pcie20_pciephy_phy_ares*/
	val = readl(cfg->pcie_rst);
	val &= ~(PCIE_RST_CTRL_PIPE_ARES);
	writel(val, cfg->pcie_rst);

	/* DeAssert cc_pcie20_core_sticky_ares */
	val = readl(cfg->pcie_rst);
	val &= ~(PCIE_RST_CTRL_PIPE_STICKY_ARES);
	writel(val, cfg->pcie_rst);

	mdelay(5);

	gpio_set_value(PCIE_RST_GPIO, GPIO_OUT_HIGH);

	/* DeAssert cc_pcie20_mstr_axi_ares */
	val = readl(cfg->pcie_rst);
	val &= ~(PCIE_RST_CTRL_AXI_M_ARES);
	writel(val, cfg->pcie_rst);

	/* DeAssert cc_pcie20_mstr_axi_ares */
	val = readl(cfg->pcie_rst);
	val &= ~(PCIE_RST_CTRL_AXI_M_STICKY_ARES);
	writel(val, cfg->pcie_rst);

	/* DeAssert cc_pcie20_slv_axi_ares */
	val = readl(cfg->pcie_rst);
	val &= ~(PCIE_RST_CTRL_AXI_S_ARES);
	writel(val, cfg->pcie_rst);

	/* DeAssert cc_pcie20_ahb_ares */
	val = readl(cfg->pcie_rst);
	val &= ~(PCIE_RST_CTRL_PIPE_PHY_AHB_ARES);
	writel(val, cfg->pcie_rst);
}

static void ipq_pcie_config_controller(int id)
{
	pcie_params_t 	*cfg;
	cfg = &gboard_param->pcie_cfg[id];

	/*
	 * program and enable address translation region 0 (device config
	 * address space); region type config;
	 * axi config address range to device config address range
	 */
	writel(0, cfg->pcie20 + PCIE20_PLR_IATU_VIEWPORT);

	writel(4, cfg->pcie20 + PCIE20_PLR_IATU_CTRL1);
	writel((1 << 31), cfg->pcie20 + PCIE20_PLR_IATU_CTRL2);
	writel(cfg->axi_conf , cfg->pcie20 + PCIE20_PLR_IATU_LBAR);
	writel(0, cfg->pcie20 + PCIE20_PLR_IATU_UBAR);
	writel((cfg->axi_conf + PCIE_AXI_CONF_SIZE - 1),
				cfg->pcie20 + PCIE20_PLR_IATU_LAR);
	writel(MSM_PCIE_DEV_CFG_ADDR,
				cfg->pcie20 + PCIE20_PLR_IATU_LTAR);
	writel(0, cfg->pcie20 + PCIE20_PLR_IATU_UTAR);

	/*
	 * program and enable address translation region 2 (device resource
	 * address space); region type memory;
	 * axi device bar address range to device bar address range
	 */
	writel(2, cfg->pcie20 + PCIE20_PLR_IATU_VIEWPORT);

	writel(0, cfg->pcie20 + PCIE20_PLR_IATU_CTRL1);
	writel((1 << 31), cfg->pcie20 + PCIE20_PLR_IATU_CTRL2);
	writel(cfg->axi_bar_start, cfg->pcie20 + PCIE20_PLR_IATU_LBAR);
	writel(0, cfg->pcie20 + PCIE20_PLR_IATU_UBAR);
	writel((cfg->axi_bar_start + cfg->axi_bar_size
		- PCIE_AXI_CONF_SIZE - 1), cfg->pcie20 + PCIE20_PLR_IATU_LAR);
	writel(cfg->axi_bar_start, cfg->pcie20 + PCIE20_PLR_IATU_LTAR);
	writel(0, cfg->pcie20 + PCIE20_PLR_IATU_UTAR);

	/* 1K PCIE buffer setting */
	writel(0x3, cfg->pcie20 + PCIE20_AXI_MSTR_RESP_COMP_CTRL0);
	writel(0x1, cfg->pcie20 + PCIE20_AXI_MSTR_RESP_COMP_CTRL1);
}

void pcie_linkup(int id)
{
	int j, val;
	pcie_params_t 		*cfg;
	cfg = &gboard_param->pcie_cfg[id];

	pcie_clock_enable(GCC_PCIE_SLEEP_CBCR);
	pcie_clock_enable(GCC_PCIE_AXI_M_CBCR);
	pcie_clock_enable(GCC_PCIE_AXI_S_CBCR);
	pcie_clock_enable(GCC_PCIE_AHB_CBCR);

	pcie_controller_reset(id);
	mdelay(200);

	writel(SLV_ADDR_SPACE_SZ, cfg->parf + PARF_SLV_ADDR_SPACE_SIZE);
	mdelay(100);

	writel(0x0, cfg->pcie20 + PCIE_0_PORT_FORCE_REG);
	val = (L1_ENTRANCE_LATENCY(3) |
		L0_ENTRANCE_LATENCY(3) |
		COMMON_CLK_N_FTS(128) |
		ACK_N_FTS(128));
	writel(val, cfg->pcie20 + PCIE_0_ACK_F_ASPM_CTRL_REG);

	val = (FAST_TRAINING_SEQ(128) |
		NUM_OF_LANES(2) |
		DIRECT_SPEED_CHANGE);
	writel(val, cfg->pcie20 + PCIE_0_GEN2_CTRL_REG);
	writel(PCI_TYPE0_BUS_MASTER_EN,
		cfg->pcie20 + PCIE_0_TYPE0_STATUS_COMMAND_REG_1);

	writel(DBI_RO_WR_EN, cfg->pcie20 + PCIE_0_MISC_CONTROL_1_REG);
	writel(0x0002FD7F, cfg->pcie20 + 0x84);

	val = (PCIE_CAP_ASPM_OPT_COMPLIANCE |
		PCIE_CAP_LINK_BW_NOT_CAP |
		PCIE_CAP_DLL_ACTIVE_REP_CAP |
		PCIE_CAP_L1_EXIT_LATENCY(4) |
		PCIE_CAP_L0S_EXIT_LATENCY(4) |
		PCIE_CAP_MAX_LINK_WIDTH(1) |
		PCIE_CAP_MAX_LINK_SPEED(1));
	writel(val, cfg->pcie20 + PCIE_0_LINK_CAPABILITIES_REG);

	writel(PCIE_CAP_CPL_TIMEOUT_DISABLE,
		cfg->pcie20 + PCIE_0_DEVICE_CONTROL2_DEVICE_STATUS2_REG);

	writel(0x10110008, cfg->pcie20 + PCIE_0_TYPE0_LINK_CONTROL_LINK_STATUS_REG_1);

	writel(LTSSM_EN, cfg->parf + PCIE_0_PCIE20_PARF_LTSSM);

	mdelay(200);

	for (j = 0; j < 400; j++) {
		val = readl(cfg->pcie20 + PCIE_0_TYPE0_LINK_CONTROL_LINK_STATUS_REG_1);
		if (val & (1 << 29)) {
			printf("PCI%d Link Intialized\n", id);
			cfg->linkup = 1;
			break;
		}
		udelay(100);
	}
	ipq_pcie_config_controller(id);
}

void board_pci_init()
{
	int i;
	pcie_params_t *cfg;

	for (i = 0; i < PCI_MAX_DEVICES; i++) {
		cfg = &gboard_param->pcie_cfg[i];
		pcie_config_gpio(cfg, ENABLE);

		pcie_controller_reset(i);

		pcie_linkup(i);
	}
}

void board_pci_deinit(void)
{
	int i;
	pcie_params_t 		*cfg;

	for (i = 0; i < PCI_MAX_DEVICES; i++) {
		cfg = &gboard_param->pcie_cfg[i];

		writel(1, cfg->parf + PCIE20_PARF_PHY_CTRL);

		pcie_config_gpio(cfg, DISABLE);
	}

	/* Disable PCIE CLKS */
	pcie_clock_disable(GCC_PCIE_SLEEP_CBCR);
	pcie_clock_disable(GCC_PCIE_AXI_M_CBCR);
	pcie_clock_disable(GCC_PCIE_AXI_S_CBCR);
	pcie_clock_disable(GCC_PCIE_AHB_CBCR);
}
#endif /* CONFIG_IPQ40XX_PCI */
