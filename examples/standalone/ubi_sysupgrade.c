/*
 * (C) 2018 Christian Lamparter <chunkeey@gmail.com>
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

static int app_entry(int argc, char * const argv[]);

/*
 * Because all u-boot apps are compiled with "-fno-toplevel-reorder",
 * the start function needs to be located at the top to match the
 * CONFIG_STANDALONE_LOAD_ADDR defined entry point.
 */
int __start(int argc, char * const argv[])
{
	return app_entry(argc, argv);
}

#include <common.h>
#include <exports.h>

#include <config.h>
#include <image.h>

#include <linux/ctype.h>
#include <linux/types.h>
#include <stdarg.h>
#include <stdbool.h>

#include <malloc.h>         /* malloc, free, realloc*/
#include <asm/byteorder.h>
#include <asm/unaligned.h>
#include <asm/global_data.h>
#include <sysupgrade/fwimage.h>
#include <sysupgrade/tar.h>

#include <asm-generic/errno.h>

#include "tinyprintf.c"

/* library functions */
int strncmp(const char* s1, const char* s2, size_t n)
{
	while(n--) {
		if (*s1++ != *s2++)
			return *(unsigned char*)(s1 - 1) - *(unsigned char*)(s2 - 1);
	}
	return 0;
}

size_t strlen(const char *s)
{
	size_t len;

	for (len = 0; *s; ++s, ++len);

	return len;
}

void *memcpy(void *dst, const void *src, size_t len)
{
	void *end = dst + len;

	for (; dst != end; dst++, src++)
		*((unsigned char*)dst) = *((unsigned char *)src);

	return dst;
}

void *memset(void *dst, int c, size_t len)
{
	void *end = dst + len;

	for (; dst != end; dst++)
		*((unsigned char*)dst) = (unsigned char)c;

	return dst;
}

static unsigned int crc_table[256];

static void crc32_filltable(void)
{
        unsigned int polynomial = 0xedb88320;
        unsigned int c;
        int i, j;

	unsigned int *table = crc_table;

        for (i = 0; i < 256; i++) {
                c = i;
                for (j = 8; j; j--)
                        c = (c&1) ? ((c >> 1) ^ polynomial) : (c >> 1);

                *table++ = c;
        }
}

static unsigned int _crc32_no_comp(unsigned int val, const void *buf, size_t len)
{
        const void *end = (unsigned char*)buf + len;

        while (buf != end) {
                val = crc_table[(unsigned char)val ^ *(unsigned char*)buf] ^ (val >> 8);
                buf = (unsigned char*)buf + 1;
        }
        return val;
}

static unsigned int _crc32(unsigned int crc, const void *p, size_t len)
{
     return _crc32_no_comp(crc ^ 0xffffffff, p, len) ^ 0xffffffff;
}

#undef isalpha

static inline int isalpha(int c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/* sysupgrade.c */

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

static void to_oct_string(char *buf, int val, int size)
{
	memset(buf, '0', size - 2);
	buf[size - 1] = '\0';
	buf = buf + size - 2;

	for (;val; val >>=3)
		*(buf--) = (val & 7) + '0';
}

static int verify_header_checksum(const struct posix_header *posix)
{
	unsigned int checksum = 0;
	char checksum_buf[sizeof(posix->chksum)];
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

	/* posix is 500 bytes... 255 * 50 = 127500 => 0371014 */
	if (checksum) {
		/* not supported by tinyprintf
		 * snprintf(checksum_buf, sizeof(checksum_buf), "%-.6o", checksum);
		 */

		to_oct_string(checksum_buf, checksum, sizeof(checksum_buf));
		return strncmp(posix->chksum, checksum_buf, sizeof(checksum_buf) - 1);
	}

	return 1;
}

int raise(int sig)
{
	printf("received signal: %d\n", sig);
	return 0;
}

static struct posix_header *get_tar_header(const struct tar_struct *tar, const size_t offset)
{
	struct posix_header *posix;

	if (offset >= tar->size)
		return NULL;

	posix = (struct posix_header *)&tar->data[offset];

	if (verify_header_checksum(posix)) {
		return NULL;
	}

	if (!strncmp(MAGIC, posix->magic_and_version, TMAGLEN)) {
		return posix;
	}

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
	else
		return 1;

	tar->start = start;
	return 0;
}

#define FOR_EACH_NODE(iter, start)	\
	for (iter = start; iter; iter = iter->next)

static void dump_tar(struct tar_struct *tar)
{
	struct tar_node *dir;
	int i = 0;

	printf("sysupgrade image content:\n");

	FOR_EACH_NODE(dir, tar->start) {
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

	printf("------------------------- %d entries\n", i);
}

static const void *find_tar(struct tar_struct *tar, size_t *len, const char *name, ...)
{
	char buf[100];
	struct tar_node *dir;
	va_list vl;

	va_start(vl, name);
	vsnprintf(buf, sizeof(buf), name, vl);
	va_end(vl);

	int name_len = strlen(buf);

	FOR_EACH_NODE(dir, tar->start) {
		if (!(dir->type == REGTYPE || dir->type == AREGTYPE))
			continue;

		if (strncmp(buf, dir->name, name_len))
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

static const char* const size_prefix(unsigned int value, unsigned int *ret)
{
	static const char * const prefix[] = { "", "Ki", "Me", "Gi" } ;
	int i;

	for (i = 0; value > 10239 && i < ARRAY_SIZE(prefix); value >>= 10, ++i);
	if (ret)
		*ret = value;

	return prefix[i];
}

static int verify_fw(const unsigned char *data, size_t *len)
{
	struct fwimage_trailer tmp_tr;
	struct fwimage_trailer *tr;
	size_t tr_pos;

#define MIN_IMG_SIZE (512 * 1024)
#define MAX_IMG_SIZE (64 * 1024 * 1024)

	if (*len < MIN_IMG_SIZE) {
		unsigned int min, tmp;
		const char *minp, *tmpp;

		minp = size_prefix(MIN_IMG_SIZE, &min);
		tmpp = size_prefix(*len, &tmp);

		printf("image too small size: %d%s B > %d%s B\n",
			 min, minp, tmp, tmpp);
		return -EMSGSIZE;
	}

	if (*len >= MAX_IMG_SIZE) {
		unsigned int max, tmp;
		const char *maxp, *tmpp;

		maxp = size_prefix(MAX_IMG_SIZE, &max);
		tmpp = size_prefix(*len, &tmp);

		printf("Image too big: %d%s B >= %d%s B\n",
			 tmp, tmpp, max, maxp);
		return -EFBIG;
	}

	tr_pos = *len - sizeof(*tr);

	tr = (struct fwimage_trailer *)(&data[tr_pos]);
	memcpy(&tmp_tr, tr, sizeof(*tr));

	if (tmp_tr.magic != cpu_to_be32(FWIMAGE_MAGIC)) {
		printf("fwtool magic not found.\n");
		return -EINVAL;
	}

	if (be32_to_cpu(tmp_tr.crc32) != _crc32_no_comp(~0, data, tr_pos)) {
		printf("crc32 mismatch.\n");
		return -EBADMSG;
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
 * Resets mini_getopt file-local variables. This is necessary if a user
 * starts the app a second/multiple times...
 */
static void mini_getopt_reset(void)
{

	optarg = NULL;
	optopt = '\0';
	optind = 1;
}

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

static struct script_struct {
	int off;
	image_header_t hdr;
	struct {
		__be32 size;
		__be32 null_padding; /* skipped over by cmd_source */
		char buf[511];
	} data;
	char null;
} __packed cmd = {
	.hdr = {
		.ih_magic = cpu_to_uimage(IH_MAGIC),
		.ih_os = IH_OS_INVALID,
		.ih_arch = IH_ARCH_INVALID,
		.ih_type = IH_TYPE_SCRIPT,
		.ih_comp = IH_COMP_NONE,
		.ih_name = "sysupgrade script",
	}
};

int run_command(const char *command, int flag)
{
	cmd.off += sprintf(&cmd.data.buf[cmd.off], "%s\n", command);

	return 0;
}

static int do_cmd(bool verbose, bool tryrun, const char *fmt, ...)
{
	char buf[80];
	int off;
	int ret = 0;
	va_list vl;

	va_start(vl, fmt);
	off = vsnprintf(buf, sizeof(buf), fmt, vl);
	va_end(vl);

	if (off == sizeof(buf)) {
		printf("ran out of internal buffer space.\n");
		return 1;
	}

	if (verbose)
		printf("'%s'\n", buf);

	if (!tryrun) {
		ret = run_command(buf, 0);
		if (ret)
			printf("error '%d' returned while executing '%s'\n", ret, buf);
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
		printf("internal error, min(%x) > max(%x) size for '%s'", min, max, name);
		return 4;
	}

	if (min && len < min) {
		printf("image '%s' size (%x) is smaller than min of '%x'\n", name, len, min);
		return 5;
	}

	if (max && len > max) {
		printf("image '%s' size (%x) is bigger than max of '%x'\n", name, len, max);
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
		printf("No '%s' image found for '%s' board.\n", img_name, board);
		return 1;
	}

	if (verbose)
		printf("%s image @ 0x%p (0x%x bytes)\n", img_name, addr, len);

	if (mode == 'R' || mode == 'B') {
		err = do_cmd(verbose, tryrun, "ubi remove %s", volume);
		if (err && verbose) {
			printf("failed to remove '%s' volume.\n"
				"this is not fatal on the first installation.\n", volume);
		}
	}

	if (mode == 'C' || mode == 'B') {
		err = do_cmd(verbose, tryrun, "ubi create %s %.8x %c", volume, clamp ? clamp : len, dynamic ? 'd' : 's');
		if (err)
			return err;

		err = do_cmd(verbose, tryrun, "ubi write %.8x %s %.8x", addr, volume, len);
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

static const char * const modes[] = { "B", "RC" };

static void sysupgrade_help(void)
{
	int i;

	/* printf doesn't like having one big Helptext string. we do it in piecemeal fashion. */
	static const char * const helptext[] = {
		"syntax: sysupgrade -h -T -v -b BOARDNAME -a address -s size -u ubi volume -k kernel_ubi -r rootfs_ubi -m mode\n",
		"    - verifies, extracts sysupgrade image for board <board> at <address> with <size>\n",
		" -h = show this helptext\n",
		" -T = try run (default = false)\n",
		" -v = verbose (default = false)\n",
		" -b = board (default = " SYSUPGRADE_BOARD" )\n",
		" -a = image address location (overwrites fileaddr env)\n",
		" -s = image size (overwrites filesize env)\n",
		" -u = ubi partition name (ubi/UBI-DEV/...) (default = " SYSUPGRADE_UBI_PARTITION ")\n",
		" -k = kernel ubi volume name (default = " SYSUPGRADE_KERNEL_VOLUME " )\n",
		" -r = rootfs ubi volume name (default = " SYSUPGRADE_ROOTFS_VOLUME " )\n",
		" -m = mode (0 = upgrades kernel and then root (default), 1 = removes ubi partitions first, before upgrading)\n",
		"This tool also reads the following env settings, these will overwrite the default values:\n",
		" filesize\n - usually set by tftpboot\n",
		" fileaddr\n - usually set by tftpboot\n",
		" openwrt_board - same as -b parameter\n",
		" openwrt_ubi_part - same as the -u parameter\n",
		" openwrt_sysupgrade_mode - same as -m parameter\n",
		" openwrt_rootfs_data_size\n",
		" openwrt_[kernel|root]_volume_name\n",
		" openwrt_[kernel|root]_volume_clamp\n",

};

	for (i = 0; i < ARRAY_SIZE(helptext); i++)
		printf(helptext[i]);
}

static void create_script(void)
{
	cmd.hdr.ih_size = cpu_to_uimage(cmd.off + 1 + 8 /* size + padding */);
	cmd.data.size = cpu_to_uimage(cmd.off + 1);
	cmd.hdr.ih_dcrc = cpu_to_uimage(_crc32(0, &cmd.data, cmd.off + 1 +8));
	cmd.hdr.ih_hcrc = cpu_to_uimage(_crc32(0, &cmd.hdr, sizeof(cmd.hdr)));
}

int sysupgrade(int argc, char * const argv[])
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
	size_t len = 0, rootfs_data_size = SYSUPGRADE_ROOTFS_DATA_VOLUME_SIZE;
	const void *paddr = NULL;
	const char *board = SYSUPGRADE_BOARD;
	const char *ubi_part = SYSUPGRADE_UBI_PARTITION;
	const char *tmp;
	unsigned char *data;
	int err = 0, c, mode = 0;
	bool verbose = false, tryrun = false, addr_set = false;

	crc32_filltable();

	tmp = getenv("openwrt_rootfs_data_size");
	if (tmp)
		rootfs_data_size = simple_strtoul(tmp, NULL, 16);

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

	tmp = getenv("openwrt_sysupgrade_mode");
	if (tmp) {
		mode = simple_strtoul(tmp, NULL, 16);
		if (mode >= ARRAY_SIZE(modes)) {
			printf("invalid sysupgrade mode '%d' selected\n", mode);
			sysupgrade_help();
			return 1;
		}
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
	while ((c = mini_getopt(argc, argv, "Tb:a:s:u:k:r:m:vh")) != -1) {
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
			printf("option '%c' lacks argument\n", optopt);
			sysupgrade_help();
			return 1;
		case '?':
			printf("unknown option '%c'\n", optopt);
			sysupgrade_help();
			return 1;
		case 'h':
			sysupgrade_help();
			return 0;
		default:
			printf("unhandled option '%c'\n", c);
			sysupgrade_help();
			return 1;
		}
	}

	if (!addr_set || !len) {
		printf("image location and/or size not set.\n");
		sysupgrade_help();
		return 1;
	}

	data = (unsigned char *)addr;

	if (!board) {
		printf("board not set.\n");
		sysupgrade_help();
		return 1;
	}

	if (!ubi_part || !ubi_part[0]) {
		printf("ubi partition not defined.\n");
		sysupgrade_help();
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

	printf("Testing Image at: %p, %d Bytes\n", data, len);
	err = verify_fw(data, &len);
	if (err) {
		if (argc == 1)
			sysupgrade_help();
		return err;
	}

	if (verbose)
		printf("basic sysupgrade image verification successful.\n");

	tar.size = len;
	tar.data = data;

	err = read_tar(&tar);
	if (err) {
		printf("reading tar failed.\n");
		return err;
	}

	if (verbose) {
		dump_tar(&tar);
	}

	paddr = find_tar(&tar, &len, "sysupgrade-%s/CONTROL", board);
	if (!paddr || len == 0) {
		printf("sysupgrade image does not have a valid CONTROL file.\n");
		err = 1;
		goto err;
	} else {
		char buf[40];

		if (verbose) {
			printf("configured board: '%s'\n", board);
			printf("sysupgrade's control: '%.*s'\n", len, (const char *)paddr);
		}

		err = snprintf(buf, 38, "BOARD=%s\n", board);
		if (strncmp(buf, paddr, min(len, err))) {
			printf("board does not match\n");
			if (verbose)
				printf("%s %d %.*s %d", buf, err, len, (const char *)paddr, len);
			err = 1;
			goto err;
		}
	}

	for (c = 0; c < __VOLUME_NUM; c++) {
		struct sysupgrade_image_struct *iter = &fixed_sysupgrade_images[c];

		err = validate_image_size(&tar, board, iter->sysupgrade_name,
					  iter->clamp_size);
		if (err) {
			printf("'%s' image verification failed. %d\n",
				iter->sysupgrade_name, err);
			goto err;
		}
	}

	err = do_cmd(verbose, false, "ubi part %s", ubi_part);
	if (err) {
		printf("failed to init ubi\n");
		goto err;
	}

	err = do_cmd(false, tryrun, "ubi remove rootfs_data");
	if (err && verbose) {
		printf("failed to remove rootfs_data partition.\n"
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
		}
	}

	err = do_cmd(verbose, false, "ubi part %s", ubi_part);
	if (err)
		goto err;

	err = do_cmd(verbose, tryrun, "ubi create rootfs_data %.8x d",
		     rootfs_data_size);

	printf(" --- script commands ---\n");
	printf("%s", cmd.data.buf);
	printf("------------------------\n");

	create_script();

	printf("Finished verifying and extracting the image.\n"
		"In order to flash it, please enter the following command in the u-boot prompt:\n"
	       " # source %p\n", &cmd.hdr);

err:
	free_tar(&tar);
	return err ? err : 0;
}

static int app_entry(int argc, char * const argv[])
{
        /* Print the ABI version */
	app_startup(argv);
	if (XF_VERSION != (int)get_version()) {
		printf ("APP expects ABI version %d\n", XF_VERSION);
		printf ("Actual U-Boot ABI version %d\n", (int)get_version());
		return 1;
	}

	mini_getopt_reset();

	/*
	 * The first argument is the address of the program in RAM.
	 */
	return sysupgrade(argc, argv);
}
