/*
 * (C) 2018 Christian Lamparter <chunkeey@gmail.com>
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * sysupgrade extract
 */
#include <config.h>
#include <common.h>
#include <command.h>
#include <linux/ctype.h>
#include <linux/types.h>
#include <stdarg.h>
#include <stdbool.h>

#include <malloc.h>         /* malloc, free, realloc*/
#include <watchdog.h>
#include <asm/byteorder.h>
#include <u-boot/zlib.h>
#include <asm/unaligned.h>
#include <asm/global_data.h>
#include <sysupgrade/fwimage.h>
#include <sysupgrade/tar.h>

struct tar_node {
	char *name;
	size_t offset;
	size_t length;
	unsigned char type;
	struct tar_node *next;
};

struct tar_struct {
	size_t blocksize;
	size_t size;
	struct tar_node *start;
	unsigned char *data;
};

static int verify_header_checksum(const struct posix_header *posix)
{
	unsigned int checksum = 0;
	char checksum_buf[sizeof(posix->chksum)] = { 0 };
	size_t i;

	for (i = 0; i < sizeof(*posix); i++) {
		if (i < offsetof(typeof(*posix), chksum) ||
		    i >= offsetof(typeof(*posix), chksum) + sizeof(posix->chksum)) {
			unsigned char val = ((unsigned char*)posix)[i];
			checksum += val;
		} else {
			if (checksum != 0) {
				/*
				 * When calculating the checksum, the chksum field
				 * is treated as if it were all blanks.
				 */
				checksum += ' ';
			}
		}
	}

	if (checksum) {
		snprintf(checksum_buf, sizeof(checksum_buf), "%-.6o", checksum);
		return strncmp(posix->chksum, checksum_buf, sizeof(checksum_buf));
	} else {
		return 0;
	}
}

static struct posix_header *get_tar_header(const struct tar_struct *tar, const size_t offset)
{
	struct posix_header *posix;

	if (offset >= tar->size)
		return NULL;

	posix = (struct posix_header *)&tar->data[offset];

	if (verify_header_checksum(posix))
		return NULL;

	if (!strncmp(MAGIC, posix->magic_and_version, TMAGLEN))
		return posix;

	return NULL;
}

#define TAR_ALIGN(val, align) ((((val) + (align) - 1) / (align) + 1) * (align) )

static int read_tar(struct tar_struct *tar) {
	size_t offset = 0;
	struct posix_header *posix;
	struct tar_node *start = NULL, *dir = NULL, *old = NULL;

	while ((posix = get_tar_header(tar, offset))) {
		long size = simple_strtoul(posix->size, NULL, 8);

		if (size < 0)
			return 1;

		dir = malloc(sizeof(*dir));
		if (!dir)
			break;

		dir->name = posix->name;
		dir->length = (size_t)size;
		dir->offset = offset;
		dir->type = posix->typeflag[1];

		offset += TAR_ALIGN(size, tar->blocksize);
		if (!start)
			start = dir;
		else
			old->next = dir;
		old = dir;
	}
	if (dir)
		dir->next = NULL;

	tar->start = start;
	return 0;
}

#define FOR_EACH_NODE(iter, start)	\
	for (iter = start; iter; iter = iter->next)

static void dump_tar(struct tar_struct *tar)
{
	struct tar_node *dir;
	int i = 0;

	FOR_EACH_NODE(dir, tar->start) {
#if defined(CONFIG_HW_WATCHDOG) || defined(CONFIG_WATCHDOG)
	WATCHDOG_RESET();
#endif	/* CONFIG_HW_WATCHDOG || CONFIG_WATCHDOG */

		printf("- Entry %d\n", i);
		switch (dir->type) {
		case REGTYPE:
		case AREGTYPE:
			printf("\ttype:FILE\n"
			       "\tname:%s\n"
			       "\toffset:%x (%u)\n"
			       "\tlength:%u\n",
				dir->name, dir->offset, dir->offset, dir->length);
			break;
		case DIRTYPE:
			printf("\ttype:DIRECTORY\n\tname:%s\n", dir->name);
			break;
		}
		i++;
	}
}

static const void *find_tar(struct tar_struct *tar, size_t *len, const char *name, ...)
{
	char buf[100];
	struct tar_node *dir;
	va_list vl;

	va_start(vl, name);
	vsnprintf(buf, sizeof(buf), name, vl);
	va_end(vl);

	FOR_EACH_NODE(dir, tar->start) {
#if defined(CONFIG_HW_WATCHDOG) || defined(CONFIG_WATCHDOG)
	WATCHDOG_RESET();
#endif	/* CONFIG_HW_WATCHDOG || CONFIG_WATCHDOG */

		if (!(dir->type == REGTYPE || dir->type == AREGTYPE))
			continue;

		if (strncmp(buf, dir->name, sizeof(((struct posix_header*)NULL)->name)))
			continue;

		*len = dir->length;
		return &tar->data[dir->offset + tar->blocksize];
	}
	return NULL;
}

static void free_tar(struct tar_struct *tar)
{
	struct tar_node *tmp, *dir = tar->start;

	while (dir) {
		tmp = dir;
		dir = dir->next;
		free(tmp);
	}
}

static int verify_fw(const unsigned char *data, size_t *len)
{
	struct fwimage_trailer tmp_tr;
	struct fwimage_trailer *tr;
	size_t tr_pos;

	if (*len < 512 * 1024)
		return 1;

	tr_pos = *len - sizeof(*tr);

	tr = (struct fwimage_trailer *)(&data[tr_pos]);
	memcpy(&tmp_tr, tr, sizeof(*tr));

	if (tmp_tr.magic != cpu_to_be32(FWIMAGE_MAGIC)) {
		eprintf("fwtool magic not found.\n");
		return 1;
	}

	if (be32_to_cpu(tmp_tr.crc32) != crc32_no_comp(~0, data, tr_pos)) {
		eprintf("crc32 mismatch.\n");
		return 1;
	}
	printf("crc32 matched - seems like a valid sysupgrade image.\n");
	*len -= be32_to_cpu(tmp_tr.size);
	return 0;
}

static const char *get_option(int argc, char * const argv[],
		       int pos, const char *optstring)
{
	const char * arg;
	if (pos >= argc)
		return NULL;

	arg = argv[pos];

	if (arg && arg[0] == '-' && isalpha(arg[1])) {
		for (;*optstring;optstring++)
			if (isalpha(*optstring) && *optstring == arg[1])
				return optstring;
	}
	return NULL;
}

static const char *optarg;
static char optopt;
int optind = 1;

/*
 * open-coded getopt() function
 *
 * This function "almost" works like the gnu "getopt" function provided by libc.
 * But without opterr support.
 *
 * This functions takes the argc, and argv parameters that are provided by the
 * caller (usally main) and "optstring". The optstring consists of string of
 * alphabet letters ([A-Z][a-z]) and colons ':'). Refere to the "getopt" man-page
 * for a full run-down of the functions capabilities.
 *
 * As an example, consider this optstring:
 * 	"fo::r:" where:
 * 		-f = a simple (f)lag option that does not take any arguments
 *		-o = option with an (o)ptional argument
 *		-r = option that (r)equires argument
 *
 * If the option has an argument, getopt returns the argument by storing it in the
 * variable optarg. You don’t ordinarily need to copy the optarg string, since it
 * is a pointer into the original argv array, not into a static area that might be
 * overwritten.
 */

static int mini_getopt(int argc, char * const argv[],
                       const char *optstring)
{
        const char *cur;
        size_t cur_len;
	const char *this_opt;
	bool has_arg = false, has_opt = false;
	char ret;

	/* Paranoid input validation check. (fuzzying) */
	if (!optstring || !optstring[0])
		return -1;

	/*
	 * since this function manages optind(ex). It has to stop once
	 * optind is past  the last argument.
	 */
	if (optind >= argc)
		return -1;

	cur = argv[optind];
	/* check if argv[optind] is actually a non-empty string. (fuzzying) */
	if (!cur && cur[0])
		return -1;

	cur_len = strlen(cur);

	/*
	 * "The special argument ‘--’ forces in all cases the end of
	 * option scanning."
	 */
	if (cur_len == 2 && cur[0] == '-' && cur[1] == '-')
		return -1;

	ret = cur[1];
	this_opt = get_option(argc, argv, optind, optstring);
	if (!this_opt) {
		/* first non-option argument or "unknown option" */
		if (cur[0] == '-') {
			/*
			 * When getopt encounters an unknown option character,
			 * it stores that option character in this variable and
			 * return '?'.
			 */
			optopt = ret;
			ret = '?';
			goto out;
		}
		return -1;
	}

	if (this_opt[1] == ':') {
		/*
		 * An option character can be followed by a colon (‘:’) to
		 * indicate that it takes a required argument. If an option
		 * character is followed by two colons (‘::’), its argument
		 * is optional; this is a GNU extension.
		 */
		has_arg = true;

		if (this_opt[2] == ':')
			has_opt = true;
	}

	if (!has_arg) {
		/* "Flag" Option case to catch simply "-f" */
		optarg = NULL;
		if (cur_len != 2) {
			/*
			 * flags are not supposed to have any appended
			 * arguments
			 */
			optopt = ret;
			ret = '?';
			goto out;
		}
	} else if (cur_len > 2) {
		/*
		 * Case for required or optional arguments that are appended
		 * to the option string. "-atest" -> optarg = test
		 */
		optarg = &cur[2];
	} else {
		const char *next_opt;

		next_opt = get_option(argc, argv, optind + 1, optstring);
		if (has_opt && next_opt) {
			/*
			 * For cases where an option with an optional argument
			 * was followed by another valid option. i.e.: "-o -f"
			 */
			optarg = NULL;
		} else {
			if (has_arg && !has_opt) {
				/*
				 * For cases where an option with an required
				 * argument is followed by a valid option
				 * instead of the argument.
				 *
				 * getopt returns ‘:’ and sets the external
				 * variable optopt to the actual option
				 * character.
				 */
				if (next_opt || optind + 1 >= argc) {
					optopt = ret;
					ret = ':';
					goto out;
				}
			}
			optarg = argv[optind + 1];
			optind++;
		}
	}

out:
        optind++;
	return ret;
}

static int do_cmd(bool verbose, bool suppress, bool tryrun, const char *fmt, ...)
{
	char buf[80];
	int off;
	int ret = 0;
	va_list vl;

	va_start(vl, fmt);
	off = vsnprintf(buf, sizeof(buf), fmt, vl);
	va_end(vl);

	if (off == sizeof(buf)) {
		eprintf("ran out of internal buffer space.\n");
		return 1;
	}

	if (verbose)
		printf("'%s'\n", buf);

	if (!tryrun) {
		ret = run_command(buf, 0);
		if (ret && !suppress)
			eprintf("error '%d' returned while executing '%s'\n", ret, buf);
	}

	return ret;
}

static const char *getenv_format(const char *fmt, ...)
{
	char pbuf[33];
	va_list vl;

	va_start(vl, fmt);
	vsprintf(pbuf, fmt, vl);
	va_end(vl);

	return getenv(pbuf);
}

static int validate_image_size(struct tar_struct *tar, const char *board, const char *name, size_t max)
{
	char pbuf[100];
	const void *paddr;
	const char *tmp;
	size_t len = 0, min = 0;

	sprintf(pbuf, "sysupgrade-%s/%s", board, name);
	paddr = find_tar(tar, &len, "sysupgrade-%s/%s", board, name);
	if (!paddr)
		return 1;

	tmp = getenv_format("openwrt_min_%s_size", name);
	if (tmp) {
		min = simple_strtoul(tmp, NULL, 16);
		if (!min)
			return 2;
	}

	if (!max) {
		tmp = getenv_format("openwrt_max_%s_size", name);
		if (tmp) {
			max = simple_strtoul(tmp, NULL, 16);
			if (!max)
				return 3;
		}
	}

	if (min > 0 && max > 0 && min > max) {
		eprintf("internal error, min(%x) > max(%x) size for '%s'", min, max, name);
		return 4;
	}

	if (min && len < min) {
		eprintf("image '%s' size (%x) is smaller than min of '%x'\n", name, len, min);
		return 5;
	}

	if (max && len > max) {
		eprintf("image '%s' size (%x) is bigger than max of '%x'\n", name, len, max);
		return 6;
	}

	return 0;
}

static int do_volume(struct tar_struct *tar, char mode, bool verbose,
		     bool tryrun, const char *board, const char *img_name,
		     const char *volume, bool dynamic, size_t clamp)
{
	const void *addr;
	size_t len;
	int err;

	addr = find_tar(tar, &len, "sysupgrade-%s/%s", board, img_name);
	if (!addr) {
		eprintf("No '%s' image found for '%s' board.\n", img_name, board);
		return 1;
	}

	if (verbose)
		printf("%s image @ 0x%p (0x%x bytes)\n", img_name, addr, len);

	if (mode == 'R' || mode == 'B') {
		err = do_cmd(verbose, true, tryrun, "ubi remove %s", volume);
		if (err) {
			eprintf("failed to remove '%s' volume.\n"
				"this is not fatal on the first installation.\n", volume);
		}
	}

	if (mode == 'C' || mode == 'B') {
		err = do_cmd(verbose, false, tryrun, "ubi create %s %.8x %c", volume, clamp ? clamp : len, dynamic ? 'd' : 's');
		if (err)
			return err;

		err = do_cmd(verbose, false, tryrun, "ubi write %.8x %s %.8x", addr, volume, len);
		if (err)
			return err;
	}

	return 0;
}

enum {
	KERNEL_VOL,
	ROOTFS_VOL,

	/* KEEP LAST */
	__VOLUME_NUM,
};

#ifndef SYSUPGRADE_UBI_PARTITION
#define SYSUPGRADE_UBI_PARTITION "ubi"
#endif

#ifndef SYSUPGRADE_BOARD
#define SYSUPGRADE_BOARD "not_configured"
#endif

#ifndef SYSUPGRADE_KERNEL_VOLUME
#define SYSUPGRADE_KERNEL_VOLUME "kernel"
#endif

#ifndef SYSUPGRADE_KERNEL_VOLUME_CLAMP_SIZE
#define SYSUPGRADE_KERNEL_VOLUME_CLAMP_SIZE (0)
#endif

#ifndef SYSUPGRADE_ROOTFS_VOLUME
#define SYSUPGRADE_ROOTFS_VOLUME "rootfs"
#endif

#ifndef SYSUPGRADE_ROOTFS_VOLUME_CLAMP_SIZE
#define SYSUPGRADE_ROOTFS_VOLUME_CLAMP_SIZE (0)
#endif

#ifndef SYSUPGRADE_ROOTFS_DATA_VOLUME_SIZE
#define SYSUPGRADE_ROOTFS_DATA_VOLUME_SIZE (0)
#endif

#ifndef SYSUPGRADE_VERBOSE
#define SYSUPGRADE_VERBOSE false
#endif

static int verify_board(struct tar_struct *tar, const char *board, bool verbose)
{
	const char *control;
	char buf[64];
	size_t len;
	int err;

	if (!board) {
		eprintf("board not set.\n");
		return 1;
	}

	control = (const char *)find_tar(tar, &len, "sysupgrade-%s/CONTROL", board);
	if (!control || len <= 6) {
		eprintf("sysupgrade image does not have a valid CONTROL file.\n");
		return 1;
	}

	if (verbose) {
		printf("configured board: '%s'\n", board);
		printf("sysupgrade's control: '%.*s'\n", len, control);
	}

	err = snprintf(buf, 63, "BOARD=%s\n", board);
	if (strncmp(buf, control, min(len, err))) {
		eprintf("board does not match\n");
		if (verbose) {
			printf("expected:'%s' != got: '%.*s'",
				buf, len, control);
		}
		return 1;
	}
	return 0;
}

static const char * const modes[] = { "B", "RC" };

static int do_sysupgrade(cmd_tbl_t * cmdtp, int flag, int argc, char * const argv[])
{
	struct sysupgrade_image_struct {
		const char *sysupgrade_name;
		const char *ubi_volume;
		bool dynamic;
		size_t clamp_size;
	} fixed_sysupgrade_images[__VOLUME_NUM] = {
		[KERNEL_VOL] = { "kernel", SYSUPGRADE_KERNEL_VOLUME, false, SYSUPGRADE_KERNEL_VOLUME_CLAMP_SIZE },
		[ROOTFS_VOL] = { "root", SYSUPGRADE_ROOTFS_VOLUME, true, SYSUPGRADE_ROOTFS_VOLUME_CLAMP_SIZE },
	};

	struct tar_struct tar = {
		.blocksize = 512,
	};
	ulong addr = 0;
	size_t len = 0, rootfs_data_len = SYSUPGRADE_ROOTFS_DATA_VOLUME_SIZE;
	const char *board = SYSUPGRADE_BOARD;
	const char *ubi_part = SYSUPGRADE_UBI_PARTITION;
	const char *tmp;
	unsigned char *data;
	int err = 0, c, mode = 0;
	bool verbose = SYSUPGRADE_VERBOSE, tryrun = false, addr_set = false;

	tmp = getenv("openwrt_rootfs_data_size");
	if (tmp)
		rootfs_data_len = simple_strtoul(tmp, NULL, 16);

	tmp = getenv("openwrt_board");
	if (tmp)
		board = tmp;

	tmp = getenv("filesize");
	if (tmp)
		len = simple_strtoul(tmp, NULL, 16);

	tmp = getenv("fileaddr");
	if (tmp) {
		addr_set = true;
		addr = simple_strtoul(tmp, NULL, 16);
	}

	tmp = getenv("openwrt_ubi_part");
	if (tmp)
		ubi_part = tmp;

	mode = getenv_ulong("openwrt_sysupgrade_mode", 16, 0);
	if (mode >= ARRAY_SIZE(modes)) {
		eprintf("invalid sysupgrade mode '%d' selected\n", mode);
		return 1;
	}

	for (c = 0; c < __VOLUME_NUM; c++) {
		struct sysupgrade_image_struct *iter = &fixed_sysupgrade_images[c];
		tmp = getenv_format("openwrt_%s_volume_name", iter->sysupgrade_name);
		if (tmp)
			fixed_sysupgrade_images[c].ubi_volume = tmp;

		tmp = getenv_format("openwrt_%s_volume_clamp", iter->sysupgrade_name);
                if (tmp)
                        iter->clamp_size = simple_strtoul(tmp, NULL, 16);
	}

	optind = 1;
	while ((c = mini_getopt(argc, argv, "Tb:a:s:u:k:r:m:v")) != -1) {
		switch (c) {
		case 'T':
			if (verbose)
				printf("tryrun set\n");
			tryrun = true;
			break;
		case 'v':
			verbose = true;
			printf("verbose enabled\n");
			break;
		case 'b':
			board = optarg;
			if (verbose)
				printf("board set to '%s'\n", board);
			break;
		case 'a':
			if (addr_set) {
				eprintf("duplicated address argument\n");
				return 1;
			}
			addr_set = true;
			addr = simple_strtoul(optarg, NULL, 16);
			if (verbose)
				printf("addr set to %x\n", (u32) addr);
			break;
		case 's':
			len = simple_strtoul(optarg, NULL, 16);
			if (verbose)
				printf("len set to %x\n", len);
			break;
		case 'u':
			ubi_part = optarg;
			if (verbose)
				printf("ubi_part set to '%s'\n", ubi_part);
			break;
		case 'k':
			fixed_sysupgrade_images[KERNEL_VOL].ubi_volume = optarg;
			if (verbose)
				printf("kernel_ubi set to '%s'\n", optarg);
			break;
		case 'r':
			fixed_sysupgrade_images[ROOTFS_VOL].ubi_volume = optarg;
			if (verbose)
				printf("rootfs_ubi set to '%s'\n", optarg);
			break;
		case ':':
			eprintf("option '%c' lacks argument\n", optopt);
			return 1;
		case '?':
			eprintf("unknown option '%c'\n", optopt);
			return 1;
		default:
			eprintf("unhandled option '%c'\n", c);
			return 1;
		}

#if defined(CONFIG_HW_WATCHDOG) || defined(CONFIG_WATCHDOG)
		WATCHDOG_RESET();
#endif	/* CONFIG_HW_WATCHDOG || CONFIG_WATCHDOG */
	}

	if (!addr_set || !len) {
		eprintf("image location and/or size not set.\n");
		return 1;
	}

	data = (unsigned char *)addr;

	if (!ubi_part || !ubi_part[0]) {
		eprintf("ubi partition not defined.\n");
		return 1;
	} else if (verbose) {
		printf("ubi partition is: '%s' --- testing\n", ubi_part);
	}

	if (verbose) {
		printf("performing sysupgrade for image @ 0x%p (0x%x bytes)\n", data, len);
		printf("verbose:%d tryrun:%d board:'%s'\n", verbose, tryrun, board);
		printf("ubi_part:'%s' kernel_vol:'%s' rootfs_vol:'%s'\n",
			ubi_part, fixed_sysupgrade_images[KERNEL_VOL].ubi_volume,
			fixed_sysupgrade_images[ROOTFS_VOL].ubi_volume);
	}

	err = verify_fw(data, &len);
	if (err)
		return err;

	tar.size = len;
	tar.data = data;

	read_tar(&tar);

	if (verbose) {
		printf("sysupgrade image content:\n");
		dump_tar(&tar);
		printf("-------------------------\n");
	}

	err = verify_board(&tar, board, verbose);
	if (err)
		goto err;

	for (c = 0; c < __VOLUME_NUM; c++) {
		struct sysupgrade_image_struct *iter = &fixed_sysupgrade_images[c];

		err = validate_image_size(&tar, board, iter->sysupgrade_name,
					  iter->clamp_size);
		if (err) {
			eprintf("'%s' image verification failed. %d\n",
				iter->sysupgrade_name, err);
			goto err;
		}
	}

	err = do_cmd(verbose, false, false, "ubi part %s", ubi_part);
	if (err)
		goto err;

	err = do_cmd(false, true, tryrun, "ubi remove rootfs_data");
	if (err && verbose) {
		eprintf("failed to remove rootfs_data partition.\n"
			"this is not fatal on the first installation.\n");
	}

	for (tmp = modes[mode]; *tmp; tmp++) {
		for (c = 0; c < __VOLUME_NUM; c++) {
			struct sysupgrade_image_struct *iter = &fixed_sysupgrade_images[c];

			err = do_volume(&tar, *tmp, verbose, tryrun, board,
					iter->sysupgrade_name, iter->ubi_volume,
					iter->dynamic, iter->clamp_size);
			if (err)
				goto err;

#if defined(CONFIG_HW_WATCHDOG) || defined(CONFIG_WATCHDOG)
			WATCHDOG_RESET();
#endif	/* CONFIG_HW_WATCHDOG || CONFIG_WATCHDOG */
		}
	}

	err = do_cmd(verbose, false, false, "ubi part %s", ubi_part);
	if (err)
		goto err;

	err = do_cmd(verbose, false, tryrun, "ubi create rootfs_data %.8x d", rootfs_data_len);

err:
	free_tar(&tar);
	return err ? err : 0;
}

U_BOOT_CMD(
	sysupgrade, 10, 0, do_sysupgrade,
	"perform sysupgrade",
	"-T -v -b BOARDNAME -a address -s size -u ubi volume -k kernel_ubi -r rootfs_ubi -m mode\n"
	"    - verifies, extracts sysupgrade image for board <board> at <address> with <size>\n"
	" -T = try run\n"
	" -v = verbose\n"
	" -u = ubi partition name (ubi/UBI-DEV/...)\n"
	" -k = kernel ubi volume name\n"
	" -r = rootfs ubi volume name\n"
	" -m = mode (0 = upgrades kernel and then root, 1 = removes ubi partitions first, before upgrading)\n"
);

static int do_get_image_type(cmd_tbl_t * cmdtp, int flag, int argc, char * const argv[])
{
	ulong addr = 0;
	size_t len = 0;
	const char *tmp;
	unsigned char *data;
	int c;
	bool verbose = false, addr_set = false;

	setenv("image_type", "unknown");

	tmp = getenv("filesize");
	if (tmp)
		len = simple_strtoul(tmp, NULL, 16);

	tmp = getenv("fileaddr");
	if (tmp) {
		addr_set = true;
		addr = simple_strtoul(tmp, NULL, 16);
	}

	optind = 1;
	while ((c = mini_getopt(argc, argv, "a:s:v")) != -1) {
		switch (c) {
		case 'v':
			verbose = true;
			printf("verbose enabled\n");
			break;
		case 'a':
			addr_set = true;
			addr = simple_strtoul(optarg, NULL, 16);
			if (verbose)
				printf("addr set to %x\n", (u32) addr);
			break;
		case 's':
			len = simple_strtoul(optarg, NULL, 16);
			if (verbose)
				printf("len set to %x\n", len);
			break;
		case ':':
			eprintf("option '%c' lacks argument\n", optopt);
			return 1;
		case '?':
			eprintf("unknown option '%c'\n", optopt);
			return 1;
		default:
			eprintf("unhandled option '%c'\n", c);
			return 1;
		}

#if defined(CONFIG_HW_WATCHDOG) || defined(CONFIG_WATCHDOG)
		WATCHDOG_RESET();
#endif	/* CONFIG_HW_WATCHDOG || CONFIG_WATCHDOG */
	}

	if (!addr_set || !len) {
		eprintf("image location and/or size not set.\n");
		return 1;
	}

	data = (unsigned char *)addr;

	if (verbose)
		printf("test image sysupgrade for image @ 0x%p (0x%x bytes)\n", data, len);

	if (verify_fw(data, &len)) {
		/* not a sysupgrade image */

		switch (genimg_get_format(data)) {
		case IMAGE_FORMAT_LEGACY:
			setenv("image_type", "legacy");
                	break;
	        case IMAGE_FORMAT_FIT:
			setenv("image_type", "fit");
			break;
		}
	} else {
		setenv("image_type", "sysupgrade");
	}

	return 0;
}

U_BOOT_CMD(
	get_image_type, 4, 0, do_get_image_type,
	"tests image and sets image_type env variable accordingly",
	" -v -b BOARDNAME -a address -s size\n"
	"    - verifies if the provided image is a sysupgrade image for board <board> at <address> with <size>\n"
	" -v = verbose\n"
	"image_type can be: sysupgrade, fit, legacy or unknown"
);

int
do_imgcheck(cmd_tbl_t * cmdtp, int flag, int argc, char * const argv[])
{
	ulong		addr, data, len;
	char		pbuf[10];
	image_header_t	*hdr;
	int		verify;

	verify = getenv_yesno("verify");

	if (argc > 1) {
		addr = simple_strtoul(argv[1], NULL, 16);
	} else {
		printf("not enough arguments\n");
		return 1;
	}

	switch (genimg_get_format((void *)addr)) {
	case IMAGE_FORMAT_LEGACY:
		printf("## Checking legacy image at %08lx ...\n", addr);

		hdr = (image_header_t *)addr;
		if (!image_check_magic(hdr)) {
			printf("Bad Magic Number\n");
			return 1;
		}

		if (!image_check_hcrc(hdr)) {
			printf("Bad Header Checksum\n");
			return 1;
		}

		if (image_get_comp(hdr) != IH_COMP_NONE) {
			printf("Compressed sub-images are not supported.\n");
			return 1;
		}

		data = image_get_data(hdr);
	        len = image_get_data_size(hdr);

		image_print_contents(hdr);

		if (verify) {
			printf("   Verifying Checksum ... ");
			if (!image_check_dcrc(hdr)) {
				printf("Bad Data CRC\n");
				return 1;
			}
		}

		printf("OK\n");
		break;

	default:
		puts("Invalid image type for imagecheck\n");
		return 1;
	}

	sprintf(pbuf, "%08lx", data);
	setenv("fileaddr", pbuf);
	sprintf(pbuf, "%08lx", len);
	setenv("filesize", pbuf);

	return 0;
}

U_BOOT_CMD(
	imagecheck, 4, 1, do_imgcheck,
	"checks legacy image",
	"addr\n"
	"    - checks image at <addr>"
);
