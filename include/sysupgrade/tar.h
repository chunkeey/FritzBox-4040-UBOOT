#ifndef __TAR_H
#define __TAR_H

/* https://www.gnu.org/software/tar/manual/html_node/Standard.html */
/* tar Header Block, from POSIX 1003.1-1990.  */

/* POSIX header.  */

struct posix_header {		/* byte offset */
  char name[100];		/*   0 */
  char mode[8];			/* 100 */
  char uid[8];			/* 108 */
  char gid[8];			/* 116 */
  char size[12];		/* 124 */
  char mtime[12];		/* 136 */
  char chksum[7];		/* 148 */
  char typeflag[3];		/* 155 */
  char linkname[99];		/* 157 */
  char magic_and_version[7];	/* 257 */
  char uname[32];		/* 265 */
  char gname[32];		/* 297 */
  char devmajor[8];		/* 329 */
  char devminor[8];		/* 337 */
  char prefix[155];		/* 345 */
				/* 500 */
};

#define MAGIC		"ustar  "	/* ustar and a null */
#define TMAGLEN		7

/* Values used in typeflag field.  */
#define REGTYPE 	'0'	/* regular file */
#define AREGTYPE	'\0'	/* regular file */
#define LNKTYPE		'1'	/* link */
#define SYMTYPE		'2'	/* reserved */
#define CHRTYPE		'3'	/* character special */
#define BLKTYPE		'4'	/* block special */
#define DIRTYPE		'5'	/* directory */
#define FIFOTYPE	'6'	/* FIFO special */
#define CONTTYPE	'7'	/* reserved */

#define XHDTYPE		'x'	/* Extended header referring to the
				   next file in the archive */
#define XGLTYPE		'g'	/* Global extended header */

#endif /* __TAR_H */
