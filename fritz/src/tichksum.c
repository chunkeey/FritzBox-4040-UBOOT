/*
 * Author: Gene Rudoy <gene@freetz.org>
 * Date:   Tue Aug 9 21:56:55 2016 +0000
 * add "tichksum for target"-package
 * git-svn-id: http://svn.freetz.org/trunk@13880 f5190166-0702-4917-9039-51ec32eddaf5
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>

enum {
  /* indicates technical errors like unsucessful open, seek, read, write, etc. */
  CS_TECHNICAL_ERROR = -1,

  /* indicates successful execution of the requested operation */
  CS_SUCCESS         = EXIT_SUCCESS,

  /* indicates unsuccessful execution of the requested operation */
  CS_FAILURE         = EXIT_FAILURE
};

#define MAGIC_NUMBER 0xC453DE23

typedef struct cksum_t {
  uint8_t ck_magic[4];
  uint8_t ck_crc[4];
} cksum_t;

/*
 * Build crc table. Takes about 0.02ms on a 7170
 * Standard CRC32 Polynom: x32 + x26 + x23 + x22 + x16 + x12 + x11 + x10 + x8 + x7 + x5 + x4 + x2 + x1 + x0 = 0x104C11DB7
 */
void
crctab_init (uint32_t *crctab)
{
  uint32_t poly = (uint32_t)0x104C11DB7;
  uint32_t i;
  crctab[0] = 0;
  for (i = 1; i < 0x100; i++) {
    uint32_t prev = i / 2;
    uint32_t crc = crctab[prev];
    uint32_t c = (crc >> 31) ^ (i & 1);
    crc <<= 1;
    if (c & 1)
      crc ^= poly;
    crctab[i] = crc;
  }
}

uint32_t
get_le32 (void *p)
{
  uint8_t *cp = p;
  return (cp[0] << (0 * 8)) | (cp[1] << (1 * 8)) | (cp[2] << (2 * 8)) | (cp[3] << (3 * 8));
}

void
set_le32 (void *p, uint32_t v)
{
  uint8_t *cp = p;
  cp[0] = v >> (0 * 8);
  cp[1] = v >> (1 * 8);
  cp[2] = v >> (2 * 8);
  cp[3] = v >> (3 * 8);
}

int
cs_is_tagged (int fd, uint32_t *saved_sum, off_t *payload_length)
{
  cksum_t cksum;
  off_t len;

  len = lseek (fd, 0, SEEK_END);
  if (len < 0)
    return CS_TECHNICAL_ERROR;

  if (payload_length)
    *payload_length = len;

  if (len < (off_t) sizeof (cksum_t))
    return false;

  len = lseek (fd, len - sizeof (cksum_t), SEEK_SET);
  if (len < 0)
    return CS_TECHNICAL_ERROR;
  if (read(fd, &cksum, sizeof (cksum_t)) != sizeof (cksum_t))
    return CS_TECHNICAL_ERROR;

  if (get_le32 (cksum.ck_magic) != MAGIC_NUMBER)
    return false;

  if (saved_sum)
    *saved_sum = get_le32 (cksum.ck_crc);
  if (payload_length)
    *payload_length -= sizeof (cksum_t);

  return true;
}

#define ADD_CRC(crc, val) ({				\
uint32_t _crc = (crc);					\
uint8_t _val = (val);					\
_crc = (_crc << 8) ^ crctab[(_crc >> 24) ^ _val];	\
(crc) = _crc;						\
})

#define BUFLEN (1 << 16)

static
int
cs_calc_sum (int fd, off_t payload_length, uint32_t *calculated_sum)
{
  uint8_t buf[BUFLEN];
  uint32_t crc = 0;
  uint32_t crctab[0x100];
  off_t  pos;
  long buflen;

  if (payload_length < 0 || lseek (fd, 0, SEEK_SET) != 0)
    return CS_TECHNICAL_ERROR;

  crctab_init (crctab);
  for (pos = 0; pos < payload_length; pos += buflen) {
    uint8_t *cp = buf;
    int i;
    buflen = sizeof (buf);
    if (buflen > payload_length - pos)
      buflen = payload_length - pos;
    if (read (fd, buf, buflen) != buflen)
      return CS_TECHNICAL_ERROR;
    for (i = 0; i < buflen; ++i, ++cp)
      ADD_CRC (crc, *cp);
  }

  for (; payload_length; payload_length >>= 8)
    ADD_CRC (crc, payload_length);

  crc = ~crc & 0xFFFFFFFF;

  *calculated_sum = crc;

  return CS_SUCCESS;
}

int
cs_add_sum (int fd, uint32_t *calculated_sum, int force)
{
  off_t payload_length;
  cksum_t cksum;
  int rc;

  rc = cs_is_tagged (fd, NULL, &payload_length);
  if (rc == CS_TECHNICAL_ERROR)
    return CS_TECHNICAL_ERROR;
  if (rc == true) {
    if (!force)
      return CS_FAILURE;

    payload_length += sizeof (cksum_t);
  }

  rc = cs_calc_sum (fd, payload_length, calculated_sum);
  if (rc != CS_SUCCESS)
    return rc;

  set_le32 (cksum.ck_magic, MAGIC_NUMBER);
  set_le32 (cksum.ck_crc, *calculated_sum);
  if (write (fd, &cksum, sizeof (cksum_t)) != sizeof (cksum_t))
    return CS_TECHNICAL_ERROR;

  return CS_SUCCESS;
}

int
cs_verify_sum (int fd, uint32_t *calculated_sum, uint32_t *saved_sum)
{
  off_t payload_length;
  int rc;

  rc = cs_is_tagged (fd, saved_sum, &payload_length);
  if (rc == CS_TECHNICAL_ERROR)
    return CS_TECHNICAL_ERROR;
  if (rc == false)
    return CS_FAILURE;

  rc = cs_calc_sum (fd, payload_length, calculated_sum);
  if (rc != CS_SUCCESS)
    return rc;

  return (*calculated_sum == *saved_sum) ? CS_SUCCESS : CS_FAILURE;
}

int
cs_remove_sum (int fd, uint32_t *saved_sum)
{
  off_t payload_length;
  int rc;

  rc = cs_is_tagged (fd, saved_sum, &payload_length);
  if (rc == CS_TECHNICAL_ERROR)
    return CS_TECHNICAL_ERROR;
  if (rc == false)
    return CS_FAILURE;

  if (ftruncate (fd, payload_length))
    return CS_TECHNICAL_ERROR;

  return CS_SUCCESS;
}

int
main (int argc, char **argv)
{
  int fd;
  int fn_ind = 1;
  char const *fn;

  uint32_t calculated_sum = 0;
  uint32_t saved_sum = 0;

  enum action {
    ACT_DEFAULT,
    ACT_ADD,
    ACT_ADD_FORCIBLE,
    ACT_VERIFY,
    ACT_REMOVE,
    ACT_ERR,
  } act = ACT_DEFAULT;

  int rc = CS_FAILURE;

  if (argc > 1 && argv[1][0] == '-') {
    switch (argv[1][1]) {
    case 'a':
      act = (argv[1][2] == 'a') ? ACT_ADD_FORCIBLE : ACT_ADD;
      break;
    case 'v':
      act = ACT_VERIFY;
      break;
    case 'r':
      act = ACT_REMOVE;
      break;
    case '-':
      break;
    default:
      act = ACT_ERR;
      break;
    }
    fn_ind++;
  }
  if (argc <= fn_ind || act == ACT_ERR) {
    printf ("Usage: %s [-a|-aa|-v|-r|--] filename\n", argv[0]);
    return CS_FAILURE;
  }

  fn = argv[fn_ind];
  fd = open (fn, act == ACT_VERIFY ? O_RDONLY : O_RDWR);
  if (fd < 0) {
    perror (fn);
    return CS_TECHNICAL_ERROR;
  }

  if (act == ACT_DEFAULT) {
    if (cs_is_tagged (fd, NULL, NULL) == false) {
      printf ("File doesn't contain the checksum, adding\n");
      act = ACT_ADD;
    } else {
      printf ("File already contains the checksum, verifying\n");
      act = ACT_VERIFY;
    }
  }

  switch (act) {
  case ACT_ADD:
  case ACT_ADD_FORCIBLE:
    rc = cs_add_sum (fd, &calculated_sum, act == ACT_ADD_FORCIBLE);
    if (rc == CS_SUCCESS) {
      printf ("Calculated checksum is 0x%08X\n", calculated_sum);
      printf ("Added successfully\n");
    } else {
      if (rc == CS_FAILURE) {
        printf ("File already contains the checksum\n");
      }
      printf ("Adding failed\n");
    }
    break;

  case ACT_VERIFY:
    rc = cs_verify_sum (fd, &calculated_sum, &saved_sum);
    if (rc != CS_TECHNICAL_ERROR && (calculated_sum != 0 || saved_sum !=0)) {
      printf ("Calculated checksum is 0x%08X\n", calculated_sum);
      printf ("Saved checksum is 0x%08X\n", saved_sum);
    }
    if (rc == CS_SUCCESS) {
      printf ("Checksum validation successful\n");
    } else {
      printf ("Checksum validation failed\n");
    }
    break;

  case ACT_REMOVE:
    rc = cs_remove_sum (fd, NULL);
    if (rc == CS_SUCCESS) {
      printf ("Checksum remove successful\n");
    } else {
      printf ("Checksum remove failed\n");
    }
    break;

  default:
    rc = CS_FAILURE;
    break;
  }

  close (fd);

  return rc;
}
