/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2013, Dependable Systems Laboratory, EPFL
 * Copyright (c) 2017-2018, Cyberhaven
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 *  The S2E VM image format.
 *
 *  Traditional image formats are not suitable for multi-path execution, because
 *  they usually mutate internal bookkeeping structures on read operations.
 *  Worse, they write these mutations back to the disk image file, causing
 *  VM image corruptions. QCOW2 is one example of such formats.
 *
 *  The S2E image format, unlike the other formats, is multi-path aware.
 *  When in S2E mode, writes are local to each state and do not clobber other states.
 *  Moreover, writes are NEVER written on the image. This makes it possible
 *  to share one disk image among many instances of S2E.
 *
 *  The S2E image format is identical to the RAW format, except that the
 *  image file name has the ".s2e" extension. Therefore, to convert from
 *  RAW to S2E, renaming the file is enough (a symlink is fine too).
 *
 *  Snapshots are stored in a separate file, suffixed by the name of the
 *  snapshot. For example, if the base image is called "my_image.raw.s2e",
 *  the snapshot "ready" (as in "savevm ready") will be saved in the file
 *  "my_image.raw.s2e.ready" in the same folder as "my_image.raw.s2e".
 *
 *  If the base image is modified, all snapshots become invalid.
 */

#include <dirent.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <inttypes.h>

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "block/qdict.h"
#include "qemu/osdep.h"
#include "block/block_int.h"
#include "qapi/error.h"
#include "qemu/option.h"


int kvm_disk_rw(void *buffer, uint64_t sector, int count, int is_write) __attribute__((weak));
int kvm_has_disk_rw(void) __attribute__((weak));

static int __hook_bdrv_read(struct BlockDriverState *bs, int64_t sector_num,
                  uint8_t *buf, int nb_sectors)
{
    assert(kvm_has_disk_rw && kvm_disk_rw);
    return kvm_disk_rw(buf, sector_num, nb_sectors, false);
}

static int __hook_bdrv_write(struct BlockDriverState *bs, int64_t sector_num,
                   uint8_t *buf, int nb_sectors)
{
    assert(kvm_has_disk_rw && kvm_disk_rw);
    return kvm_disk_rw(buf, sector_num, nb_sectors, true);
}


#define S2EB_L2_SIZE 65536
#define S2EB_SECTOR_SIZE BDRV_SECTOR_SIZE
#define S2EB_L2_SECTORS (S2EB_L2_SIZE / S2EB_SECTOR_SIZE)

typedef uint64_t bitmap_entry_t;
#define S2EB_BITS_PER_ENTRY (sizeof(bitmap_entry_t) * 8)


typedef struct S2EBLKL2 {
    /* The sectors that differ from the base snapshot */
    bitmap_entry_t dirty_bitmap[S2EB_L2_SECTORS / S2EB_BITS_PER_ENTRY];
    uint8_t block[S2EB_L2_SIZE];
} S2EBLKL2;

typedef struct BDRVS2EState {
    uint64_t sector_count;
    uint64_t dirty_count;
    uint64_t l1_entries;
    S2EBLKL2 **l1;

    /* Temporary vm state */
    uint8_t *snapshot_vmstate;
    size_t snapshot_vmstate_size;

    /* valid after we've opened a snapshot */
    FILE *snapshot_fp;
    uint64_t vmstate_start; /* in sectors */
    uint64_t vmstate_size; /* in bytes */

    /* This is used when read_only = 1 and a snapshot is loaded */
    bitmap_entry_t *vmstate_dirty_bitmap;
    uint32_t *vmstate_sector_map;
    uint64_t vmstate_sector_map_entries;
    uint64_t vmstate_sectors_start;

    FILE *image_file;
    uint64_t image_size;
    char *image_file_path;
} BDRVS2EState;

typedef struct S2ESnapshotHeader {
    /* Used to detect changes in the base image */
    uint64_t base_image_timestamp;

    uint64_t sector_map_offset;
    uint64_t sector_map_entries;
    uint64_t sectors_start;

    /* The VM state is saved after the disk data */
    uint64_t vmstate_start; /* In sectors */
    uint64_t vmstate_size; /* In bytes */

    char id_str[128]; /* unique snapshot id */
    /* the following fields are informative. They are not needed for
       the consistency of the snapshot */
    char name[256]; /* user chosen name */

    uint32_t date_sec; /* UTC date of the snapshot */
    uint32_t date_nsec;
    uint64_t vm_clock_nsec; /* VM clock relative to boot */
} S2ESnapshotHeader;

/* Ensure that S2ESnapshotHeader is < 512 bytes at compile time */
static uint8_t __hdrcheck[sizeof(S2ESnapshotHeader) > 512 ? -1 : 0] __attribute__((unused));

static void s2e_blk_init(BlockDriverState *bs)
{
    BDRVS2EState *s = bs->opaque;

    s->snapshot_vmstate_size = 0;
    s->snapshot_vmstate = NULL;

    s->vmstate_sector_map = NULL;
    s->vmstate_dirty_bitmap = NULL;
    s->vmstate_sector_map_entries = 0;
    s->vmstate_sectors_start = 0;

    /* Initialize the copy-on-write page table */
    uint64_t length = s->image_size & BDRV_SECTOR_MASK;
    s->sector_count = length / S2EB_SECTOR_SIZE;

    s->l1_entries = s->sector_count / S2EB_L2_SECTORS;
    s->l1 = g_malloc0(sizeof(*s->l1) * s->l1_entries);

    s->snapshot_fp = NULL;
}

static bool get_file_size(FILE *fp, uint64_t *size)
{
    bool ret = false;

    if (fseek(fp, 0L, SEEK_END) < 0) {
        goto err;
    }

    *size = ftell(fp);
    if (*size == LONG_MAX) {
        errno = EISDIR;
        goto err;
    }

    if (fseek(fp, 0L, SEEK_SET) < 0) {
        goto err;
    }

    ret = true;

err:
    return ret;
}

static int s2e_open(BlockDriverState *bs, QDict *options, int flags,
                    Error **errp)
{
    int ret = 0;

    const char *base_file = qdict_get_try_str(options, "file");
    if (!base_file) {
        fprintf(stderr, "Please use the file= parameter to specifiy the image to use.\n");
        ret = ENOENT;
        goto err;
    }

    BDRVS2EState *s = bs->opaque;
    memset(s, 0, sizeof(*s));

    s->image_file = fopen(base_file, "rb");
    if (!s->image_file) {
        ret = errno;
        goto err;
    }

    if (!get_file_size(s->image_file, &s->image_size)) {
        fprintf(stderr, "Could not determine size of %s\n", base_file);
        ret = errno;
        goto err;
    }

    s->image_file_path = strdup(base_file);
    if (!s->image_file_path) {
        ret = ENOMEM;
        goto err;
    }

    s2e_blk_init(bs);

err:
    if (ret < 0) {
        if (s->image_file) {
            fclose(s->image_file);
        }

        free(s->image_file_path);
    }

    qdict_del(options, "file");

    return -ret;
}

static int s2e_reopen_fd(BlockDriverState *bs)
{
    int ret = 0;
    BDRVS2EState *s = bs->opaque;

    if (fclose(s->image_file) < 0) {
        ret = errno;
        fprintf(stderr, "Could not close old file descriptor for %s\n", s->image_file_path);
        goto err;
    }

    s->image_file = fopen(s->image_file_path, "rb");
    if (!s->image_file) {
        fprintf(stderr, "Could not open %s\n", s->image_file_path);
        ret = errno;
        goto err;
    }

err:
    return -ret;
}

static int s2e_blk_is_dirty(BDRVS2EState *s, uint64_t sector_num)
{
    uint64_t l1_index = sector_num / S2EB_L2_SECTORS;
    uint64_t l2_index = sector_num % S2EB_L2_SECTORS;
    if (!s->l1[l1_index]) {
        return 0;
    }

    uint64_t word = s->l1[l1_index]->dirty_bitmap[l2_index / S2EB_BITS_PER_ENTRY];
    if (word & (1ULL << (l2_index % S2EB_BITS_PER_ENTRY))) {
        return 1;
    }
    return 0;
}

static void s2e_blk_print_stats(BlockDriverState *bs)
{
    BDRVS2EState *s = bs->opaque;

    uint64_t wasted_sectors = 0;
    unsigned i, j;

    for (i = 0; i < s->l1_entries; ++i) {
        if (!s->l1[i]) {
            continue;
        }

        for (j = 0; j < S2EB_L2_SECTORS; ++j) {
            wasted_sectors += !s2e_blk_is_dirty(s, i * S2EB_L2_SECTORS + j);
        }
    }

    printf("s2e-block: wasted sectors: %"PRIu64"\n", wasted_sectors);
}

static void s2e_blk_copy_and_set_dirty(BDRVS2EState *s, uint8_t *buffer, uint64_t sector_num, unsigned count)
{
    uint64_t l1_index = sector_num / S2EB_L2_SECTORS;
    uint64_t l2_index = sector_num % S2EB_L2_SECTORS;

    assert(l2_index + count <= S2EB_L2_SECTORS);
    assert(l1_index < s->l1_entries);

    if (!s->l1[l1_index]) {
        s->l1[l1_index] = g_malloc0(sizeof(S2EBLKL2));
    }

    S2EBLKL2 *b = s->l1[l1_index];

    uint64_t idx = l2_index;
    uint64_t cnt = count;
    while (cnt > 0) {
        bitmap_entry_t mask = 1ULL << (idx % S2EB_BITS_PER_ENTRY);
        unsigned entry_idx = idx / S2EB_BITS_PER_ENTRY;

        if (!(b->dirty_bitmap[entry_idx] & mask)) {
            s->dirty_count++;
        }

        b->dirty_bitmap[entry_idx] |= mask;
        ++idx;
        --cnt;
    }

    uint8_t *dest = &b->block[l2_index * S2EB_SECTOR_SIZE];
    memcpy(dest, buffer, count * S2EB_SECTOR_SIZE);
}

static uint64_t s2e_find_dirty_sector_location(BDRVS2EState *s, uint64_t sector_num)
{
    /* binary search (cf Knuth) */
    uint64_t m_min = 0;
    uint64_t m_max = s->vmstate_sector_map_entries - 1;
    while (m_min <= m_max) {
        uint64_t m = (m_min + m_max) >> 1;
        uint32_t cur_sector = s->vmstate_sector_map[m];

        if (cur_sector == sector_num)
            return s->vmstate_sectors_start + m;
        else if (sector_num < cur_sector) {
            m_max = m - 1;
        } else {
            m_min = m + 1;
        }
    }

    /**
     * Sector 0 is the snapshot's header and can therefore be
     * used to indicate an error.
     */
    return 0;
}

static int s2e_read_dirty_from_snapshot_file(BDRVS2EState *s, uint8_t *buffer, uint64_t sector_num, int nb_sectors)
{
    assert(s->snapshot_fp != NULL);
    int found_dirty = 0;

    if (!s->vmstate_dirty_bitmap) {
        return found_dirty;
    }

    while (nb_sectors > 0) {
        uint64_t i1 = sector_num / S2EB_BITS_PER_ENTRY;
        uint64_t i2 = sector_num % S2EB_BITS_PER_ENTRY;

        if (!s->vmstate_dirty_bitmap[i1]) {
            /* ok if it gets negative */
            sector_num += S2EB_BITS_PER_ENTRY;
            nb_sectors -= S2EB_BITS_PER_ENTRY;
            buffer += BDRV_SECTOR_SIZE * S2EB_BITS_PER_ENTRY;
            continue;
        }

        if (s->vmstate_dirty_bitmap[i1] & (1ULL << i2)) {
            found_dirty = 1;

            //Locate the dirty sector on the disk
            uint64_t sector_on_image = s2e_find_dirty_sector_location(s, sector_num);
            assert(sector_on_image > 0);
            if (fseek(s->snapshot_fp, sector_on_image * S2EB_SECTOR_SIZE, SEEK_SET) < 0) {
                assert(false && "seek failed");
            }
            if (fread(buffer, S2EB_SECTOR_SIZE, 1, s->snapshot_fp) != 1) {
                assert(false && "read failed");
            }
        }

        nb_sectors--;
        sector_num++;
        buffer += BDRV_SECTOR_SIZE;
    }

    return found_dirty;
}

static int s2e_read_dirty(BDRVS2EState *s, uint8_t *buffer, uint64_t sector_num, int nb_sectors)
{
    /* Check for copy-on-write data */
    int found_dirty = 0;

    while (nb_sectors > 0) {
        uint64_t l1_index = ((uint64_t) sector_num) / S2EB_L2_SECTORS;
        uint64_t l2_index = ((uint64_t) sector_num) % S2EB_L2_SECTORS;

        /* Quick check if the entire page is non-dirty */
        if (!s->l1[l1_index]) {
            /* increment may be bigger than nb_sector, but it's ok,
               nb_sectors is signed. */
            uint64_t increment = S2EB_L2_SECTORS - l2_index;
            nb_sectors -= increment;
            sector_num += increment;
            buffer += increment * BDRV_SECTOR_SIZE;
            continue;
        }

        if (s2e_blk_is_dirty(s, sector_num)) {
            uint8_t *data = s->l1[l1_index]->block;
            memcpy(buffer, &data[l2_index * BDRV_SECTOR_SIZE], BDRV_SECTOR_SIZE);
            found_dirty = 1;
        }

        buffer += BDRV_SECTOR_SIZE;
        nb_sectors--;
        sector_num++;
    }

    return found_dirty;
}

/* This is for S2E mode, add latest writes from the current state */
static int s2e_read_dirty_klee(BlockDriverState *bs, uint8_t *buffer, uint64_t sector_num, unsigned nb_sectors)
{
    int found_dirty = false;

    while (nb_sectors) {
        int read_count = __hook_bdrv_read(bs, sector_num, buffer, nb_sectors);
        if (read_count > 0) {
            found_dirty = true;
            sector_num += read_count;
            nb_sectors -= read_count;
            buffer += S2EB_SECTOR_SIZE * read_count;
        } else {
            ++sector_num;
            --nb_sectors;
            buffer += S2EB_SECTOR_SIZE;
        }
    }

    return found_dirty;
}

static int coroutine_fn s2e_co_readv(BlockDriverState *bs, int64_t sector_num,
                                     int nb_sectors, QEMUIOVector *qiov)
{
    BDRVS2EState *s = bs->opaque;
    //printf("read %ld %d\n", sector_num, nb_sectors);

    assert(nb_sectors > 0 && "Something wrong happened in the block layer");

    unsigned alloc_bytes = qiov->size;
    assert(alloc_bytes >= nb_sectors * BDRV_SECTOR_SIZE);
    uint8_t *temp_buffer = qemu_memalign(BDRV_SECTOR_SIZE, alloc_bytes);

    // First, read the base image
    if (fseek(s->image_file, sector_num * BDRV_SECTOR_SIZE, SEEK_SET) < 0) {
        abort();
    }

    if (fread(temp_buffer, BDRV_SECTOR_SIZE, nb_sectors, s->image_file) != nb_sectors) {
        abort();
    }

    int found_dirty = 0;

    // 2nd, read any data saved in the snapshot
    if (s->snapshot_fp) {
        found_dirty |= s2e_read_dirty_from_snapshot_file(s, temp_buffer, sector_num, nb_sectors);
    }

    // 3rd, read any data written locally
    found_dirty |= s2e_read_dirty(s, temp_buffer, sector_num, nb_sectors);

    // Finally, if multi-path execution is running, check for any per-path data
    if (kvm_has_disk_rw && kvm_has_disk_rw()) {
        found_dirty |= s2e_read_dirty_klee(bs, temp_buffer, sector_num, nb_sectors);
    }

    qemu_iovec_from_buf(qiov, 0, temp_buffer, alloc_bytes);

    qemu_vfree(temp_buffer);

    return 0;
}

static void s2e_write_dirty(BDRVS2EState *s, uint8_t *buffer, uint64_t sector_num, unsigned nb_sectors)
{
    while (nb_sectors > 0) {
        uint64_t offset = (uint64_t) sector_num % S2EB_L2_SECTORS;
        uint64_t transfer_count = S2EB_L2_SECTORS - offset;
        if (transfer_count > nb_sectors) {
            transfer_count = nb_sectors;
        }

        s2e_blk_copy_and_set_dirty(s, buffer, sector_num, transfer_count);

        nb_sectors -= transfer_count;
        sector_num += transfer_count;
        buffer += transfer_count * S2EB_SECTOR_SIZE;
    }
}

static int coroutine_fn s2e_co_writev(BlockDriverState *bs,
                                      int64_t sector_num, int nb_sectors, QEMUIOVector *qiov, int flags)
{
    BDRVS2EState *s = bs->opaque;

    assert(nb_sectors > 0 && "Something wrong happened in the block layer");
    /* Don't write beyond the disk boundaries */
    if (sector_num >= s->sector_count || sector_num + nb_sectors > s->sector_count) {
        assert(0);
        return -1;
    }

    //printf("write %ld %d\n", sector_num, nb_sectors);

    /* The entire block goes into the copy-on-write store */
    unsigned alloc_bytes = qiov->size;
    assert(alloc_bytes >= nb_sectors * BDRV_SECTOR_SIZE);

    uint8_t *temp_buffer = qemu_memalign(BDRV_SECTOR_SIZE, alloc_bytes);
    qemu_iovec_to_buf(qiov, 0, temp_buffer, alloc_bytes);

    if (kvm_has_disk_rw && kvm_has_disk_rw()) {
        int ret = __hook_bdrv_write(bs, sector_num, temp_buffer, nb_sectors);
        assert(ret == 0);
        goto end1;
    }

    s2e_write_dirty(s, temp_buffer, sector_num, nb_sectors);

    end1:
    qemu_vfree(temp_buffer);
    return 0;
}

static void s2e_blk_close(BlockDriverState *bs)
{
    BDRVS2EState *s = bs->opaque;
    int64_t i;

    printf("s2e-block: dirty sectors on close:%ld\n", s->dirty_count);
    if (s->l1) {
        for (i = 0; i < s->l1_entries; ++i) {
            if (s->l1[i]) {
                g_free(s->l1[i]);
            }
        }
        g_free(s->l1);
    }

    if (s->snapshot_vmstate) {
        g_free(s->snapshot_vmstate);
    }

    s->dirty_count = 0;
    s->l1 = NULL;
    s->l1_entries = 0;

    if (s->snapshot_fp) {
        fclose(s->snapshot_fp);
    }

    if (s->vmstate_dirty_bitmap) {
        g_free(s->vmstate_dirty_bitmap);
    }

    if (s->vmstate_sector_map) {
        g_free(s->vmstate_sector_map);
    }
}

static int64_t s2e_getlength(BlockDriverState *bs)
{
    BDRVS2EState *s = bs->opaque;
    return s->image_size;
}

static int s2e_ioctl(BlockDriverState *bs, unsigned long int req, void *buf)
{
   return bdrv_co_ioctl(bs->file->bs, req, buf);
}

static char *s2e_get_snapshot_file(const char *base_image, const char *snapshot)
{
    char snapshot_file[1024];
    int max_len = sizeof(snapshot_file) - 1;
    strncpy(snapshot_file, base_image, max_len);
    strncat(snapshot_file, ".", max_len);
    strncat(snapshot_file, snapshot, max_len);
    return strdup(snapshot_file);
}

static time_t s2e_get_mtime(const char *path)
{
    struct stat statbuf;
    if (stat(path, &statbuf) == -1) {
        perror(path);
        exit(1);
    }
    return statbuf.st_mtime;
}

static int s2e_snapshot_create(BlockDriverState *bs, QEMUSnapshotInfo *sn_info)
{
    //printf("s2e_snapshot_create\n");
    int ret = 0;
    BDRVS2EState *s = bs->opaque;

    char *snapshot_filename = s2e_get_snapshot_file(s->image_file_path, sn_info->name);
    if (!snapshot_filename) {
        ret = -1;
        goto fail1;
    }

    FILE *fp = fopen(snapshot_filename, "wb");
    if (!fp) {
        ret = -1;
        goto fail2;
    }

    S2ESnapshotHeader header;
    memcpy(header.name, sn_info->name, sizeof(header.name));
    memcpy(header.id_str, sn_info->id_str, sizeof(header.id_str));
    header.date_sec = sn_info->date_sec;
    header.date_nsec = sn_info->date_nsec;
    header.vm_clock_nsec = sn_info->vm_clock_nsec;

    header.base_image_timestamp = s2e_get_mtime(s->image_file_path);
    header.sector_map_offset = 1;
    header.sector_map_entries = s->dirty_count;

    printf("s2e-block: dirty at save: %ld\n", s->dirty_count);

    unsigned sector_map_size = header.sector_map_entries * sizeof(uint32_t);
    header.sectors_start = 1 + sector_map_size / S2EB_SECTOR_SIZE;
    if (sector_map_size % S2EB_SECTOR_SIZE) {
        header.sectors_start++;
    }

    header.vmstate_start = header.sectors_start + s->dirty_count;
    header.vmstate_size = s->snapshot_vmstate_size;

    if (fwrite(&header, sizeof(header), 1, fp) != 1) {
        ret = -1;
        goto fail2;
    }

    if (fseek(fp, S2EB_SECTOR_SIZE, SEEK_SET) < 0) {
        ret = -1;
        goto fail2;
    }

    /* Build the list of dirty sectors */
    uint32_t *sector_map = g_malloc0(header.sector_map_entries * sizeof(uint32_t));
    uint8_t *sector_data = g_malloc0(header.sector_map_entries * S2EB_SECTOR_SIZE);

    unsigned written = 0;
    if (header.sector_map_entries > 0) {
        uint32_t *sector_map_ptr = sector_map;
        uint8_t *sector_data_ptr = sector_data;
        uint64_t i;
        unsigned j;

        for (i = 0; i < s->l1_entries; ++i) {
            if (!s->l1[i]) {
                continue;
            }

            uint64_t sector_index = i * S2EB_L2_SECTORS;
            for (j = 0; j < S2EB_L2_SECTORS; ++j) {
                if (s2e_blk_is_dirty(s, sector_index + j)) {
                    *sector_map_ptr = sector_index + j;
                    memcpy(sector_data_ptr, s->l1[i]->block + (j * S2EB_SECTOR_SIZE), S2EB_SECTOR_SIZE);

                    ++sector_map_ptr;
                    sector_data_ptr += S2EB_SECTOR_SIZE;
                    ++written;
                }
            }
        }

        assert(written == s->dirty_count);

        /* Write them to disk */

        if (fwrite(sector_map, header.sector_map_entries * sizeof(uint32_t), 1, fp) != 1) {
            ret = -1;
            goto fail3;
        }

        if (fseek(fp, header.sectors_start * S2EB_SECTOR_SIZE, SEEK_SET) < 0) {
            ret = -1;
            goto fail3;
        }

        if (fwrite(sector_data, header.sector_map_entries * S2EB_SECTOR_SIZE, 1, fp) != 1) {
            ret = 1;
            goto fail3;
        }
    }

    /* Write the VM state */
    if (fseek(fp, header.vmstate_start * S2EB_SECTOR_SIZE, SEEK_SET) < 0) {
        ret = -1;
        goto fail3;
    }

    if (fwrite(s->snapshot_vmstate, s->snapshot_vmstate_size, 1, fp) != 1) {
        ret = -1;
        goto fail3;
    }


    free(s->snapshot_vmstate);
    s->snapshot_vmstate = NULL;
    s->snapshot_vmstate_size = 0;

    fail3: g_free(sector_data);
           g_free(sector_map);

    fail2: fclose(fp);
    fail1: free(snapshot_filename);
           return ret;
}

static FILE *s2e_read_snapshot_info(BlockDriverState *bs, const char *snapshot_name, S2ESnapshotHeader *header)
{
    BDRVS2EState *s = bs->opaque;

    char *snapshot_file = s2e_get_snapshot_file(s->image_file_path, snapshot_name);
    if (!snapshot_file) {
        return NULL;
    }

    FILE *fp = fopen(snapshot_file, "rb");
    if (!fp) {
        return NULL;
    }

    if (fread(header, sizeof(*header), 1, fp) != 1) {
        fclose(fp);
        return NULL;
    }

    return fp;
}

static int s2e_snapshot_load_disk_data(BDRVS2EState *s, const S2ESnapshotHeader *header)
{
    int ret = -1;
    uint64_t i;

    if (!header->sector_map_entries) {
        /* No disk data to load */
        return 0;
    }

    if (fseek(s->snapshot_fp, header->sector_map_offset * S2EB_SECTOR_SIZE, 0) < 0) {
        goto fail0;
    }

    uint32_t *sector_map = g_malloc(header->sector_map_entries * sizeof(uint32_t));

    if (fread(sector_map, header->sector_map_entries * sizeof(uint32_t), 1, s->snapshot_fp) != 1) {
        goto fail1;
    }

    if (fseek(s->snapshot_fp, header->sectors_start * S2EB_SECTOR_SIZE, 0) < 0) {
        goto fail1;
    }


    uint8_t *sector_data = g_malloc(header->sector_map_entries * S2EB_SECTOR_SIZE);
    if (fread(sector_data, header->sector_map_entries * S2EB_SECTOR_SIZE, 1, s->snapshot_fp) != 1) {
        goto fail2;
    }

    uint8_t *sector_data_ptr = sector_data;
    for (i = 0; i < header->sector_map_entries; ++i) {
        uint64_t sector_num = sector_map[i];
        s2e_blk_copy_and_set_dirty(s, sector_data_ptr, sector_num, 1);
        sector_data_ptr += S2EB_SECTOR_SIZE;
    }

    s->dirty_count = header->sector_map_entries;

    ret = 0;

    fail2: g_free(sector_data);
    fail1: g_free(sector_map);
    fail0: return ret;
}

static int s2e_snapshot_load_disk_data_ro(BDRVS2EState *s, const S2ESnapshotHeader *header)
{
    int ret = -1;
    uint64_t i;

    if (!header->sector_map_entries) {
        /* No disk data to load */
        return 0;
    }

    if (fseek(s->snapshot_fp, header->sector_map_offset * S2EB_SECTOR_SIZE, 0) < 0) {
        goto fail0;
    }

    uint32_t *sector_map = g_malloc(header->sector_map_entries * sizeof(uint32_t));

    if (fread(sector_map, header->sector_map_entries * sizeof(uint32_t), 1, s->snapshot_fp) != 1) {
        goto fail1;
    }

    s->vmstate_sector_map = sector_map;
    s->vmstate_sector_map_entries = header->sector_map_entries;
    s->vmstate_sectors_start = header->sectors_start;

    uint64_t count = s->sector_count / S2EB_BITS_PER_ENTRY;
    s->vmstate_dirty_bitmap = g_malloc0(count * sizeof(*s->vmstate_dirty_bitmap));

    for (i = 0; i < header->sector_map_entries; ++i) {
        uint64_t sector_num = sector_map[i];
        uint64_t i0 = sector_num / S2EB_BITS_PER_ENTRY;
        uint64_t i1 = sector_num % S2EB_BITS_PER_ENTRY;
        s->vmstate_dirty_bitmap[i0] |= 1ULL << i1;
    }

    s->dirty_count = header->sector_map_entries;

    return 0;

    fail1: g_free(sector_map);
    fail0: return ret;
}

static int s2e_snapshot_goto(BlockDriverState *bs, const char *snapshot_id)
{
    BDRVS2EState *s = bs->opaque;

    S2ESnapshotHeader header;
    FILE *fp = s2e_read_snapshot_info(bs, snapshot_id, &header);
    if (!fp) {
        return -1;
    }

    time_t mtime = s2e_get_mtime(s->image_file_path);
    if (header.base_image_timestamp != mtime) {
        printf("Modification timestamp of '%s' changed since the creation of the snapshot '%s'"
               " (st_mtime %" PRIu64 " != %" PRIu64 ").\n"
               "Please recreate a new snapshot.\n",
               bs->filename, snapshot_id, (uint64_t) mtime, header.base_image_timestamp);
        fclose(fp);
        return -1;
    }

    /* Discard whatever state we had before */
    s2e_blk_close(bs);
    s2e_blk_init(bs);

    s->snapshot_fp = fp;
    s->vmstate_start = header.vmstate_start;
    s->vmstate_size = header.vmstate_size;

    int ret;
    bool read_only = kvm_has_disk_rw && kvm_has_disk_rw();
    if (read_only) {
        ret = s2e_snapshot_load_disk_data_ro(s, &header);
    } else {
        ret = s2e_snapshot_load_disk_data(s, &header);
    }

    if (ret < 0) {
        fclose(fp);
        return -1;
    }

    printf("s2e-block: dirty after restore: %ld (ro=%d)\n", s->dirty_count, read_only);

    s2e_blk_print_stats(bs);

    return 0;
}

static int s2e_snapshot_delete(BlockDriverState *bs,
                               const char *snapshot_id,
                               const char *name,
                               Error **errp)
{
    BDRVS2EState *s = bs->opaque;
    char *snapshot_file = s2e_get_snapshot_file(s->image_file_path, snapshot_id);
    return unlink(snapshot_file);
}


static int s2e_snapshot_list(BlockDriverState *bs, QEMUSnapshotInfo **psn_info)
{
    int ret = 0;
    BDRVS2EState *s = bs->opaque;

    /* List all the snapshots in the base image's directory */
    char *dirstring = strdup(s->image_file_path);
    char *filestring = strdup(s->image_file_path);
    char *directory = dirname(dirstring);
    char *image_name = basename(filestring);
    size_t image_name_len = strlen(image_name);

    DIR *dir = opendir (directory);
    if (!dir) {
        ret = -1;
        goto fail1;
    }

    struct dirent *ent;
    unsigned snapshot_count = 0;
    QEMUSnapshotInfo *sn_tab = NULL, *sn_info;

    while ((ent = readdir (dir)) != NULL) {
        if (strstr(ent->d_name, image_name) == ent->d_name) {
            const char *snapshot_name = ent->d_name + image_name_len;
            if (snapshot_name[0] != '.' || snapshot_name[1] == 0) {
                continue;
            }

            snapshot_name++;
            //printf ("snapshot: %s (%s)\n", ent->d_name, snapshot_name);

            S2ESnapshotHeader header;
            FILE *fp = s2e_read_snapshot_info(bs, snapshot_name, &header);
            if (!fp) {
                continue;
            }
            fclose(fp);

            ++snapshot_count;
            sn_tab = realloc(sn_tab, snapshot_count * sizeof(QEMUSnapshotInfo));
            sn_info = sn_tab + snapshot_count - 1;

            memcpy(sn_info->name, header.name, sizeof(sn_info->name));
            memcpy(sn_info->id_str, header.id_str, sizeof(sn_info->id_str));
            sn_info->vm_state_size = header.vmstate_size;
            sn_info->date_sec = header.date_sec;
            sn_info->date_nsec = header.date_nsec;
            sn_info->vm_clock_nsec = header.vm_clock_nsec;
        }
    }

    *psn_info = sn_tab;
    ret = snapshot_count;

    closedir (dir);

    fail1:
    free(dirstring);
    free(filestring);
    return ret;
}

static int s2e_get_info(BlockDriverState *bs, BlockDriverInfo *bdi)
{
    bdi->cluster_size = S2EB_SECTOR_SIZE;
    bdi->vm_state_offset = 0;
    return 0;
}

static int s2e_save_vmstate(BlockDriverState *bs, QEMUIOVector *qiov, int64_t pos)
{
    BDRVS2EState *s = bs->opaque;


    /* Accumulate the data into the temporary buffer */
    if (pos + qiov->size > s->snapshot_vmstate_size) {
        s->snapshot_vmstate = realloc(s->snapshot_vmstate, pos + qiov->size);
        s->snapshot_vmstate_size = pos + qiov->size;
    }

    qemu_iovec_to_buf(qiov, 0, s->snapshot_vmstate + pos, qiov->size);
    return 0;
}

static int s2e_load_vmstate(BlockDriverState *bs, QEMUIOVector *qiov, int64_t pos)
{
    uint64_t size = qiov->size;
    uint8_t *buf = malloc(size);
    if (!buf) {
        size = 0;
        goto err;
    }

    BDRVS2EState *s = bs->opaque;

    assert(s->snapshot_fp != NULL);

    /* Don't overflow */
    if (pos + size >= s->vmstate_size) {
        size = s->vmstate_size - pos;
    }

    /* Read the VM data from the snapshot */
    uint64_t offset = s->vmstate_start * S2EB_SECTOR_SIZE + pos;
    if (fseek(s->snapshot_fp, offset, 0) < 0) {
        size = 0;
        goto err;
    }

    if (fread(buf, size, 1, s->snapshot_fp) != 1) {
        size = 0;
        goto err;
    }

    qemu_iovec_from_buf(qiov, 0, buf, size);

    free(buf);

err:
    return size;
}

static void s2e_bdrv_format_default_perms(BlockDriverState *bs, BdrvChild *c,
                               const BdrvChildRole *role,
                               BlockReopenQueue *reopen_queue,
                               uint64_t perm, uint64_t shared,
                               uint64_t *nperm, uint64_t *nshared)
{
    bdrv_format_default_perms(bs, c, role, reopen_queue, perm, shared, nperm, nshared);
    *nperm |= BLK_PERM_WRITE;
    *nshared |= BLK_PERM_WRITE;
}

static int s2e_check_perm(BlockDriverState *bs, uint64_t perm,
                          uint64_t shared, Error **errp)
{
    return 0;
}

static BlockDriver bdrv_s2e = {
    .format_name        = "s2e",

    /* It's really 0, but we need to make g_malloc() happy */
    .instance_size      = sizeof(BDRVS2EState),

    .bdrv_open          = s2e_open,
    .bdrv_close         = s2e_blk_close,
    .bdrv_child_perm    = s2e_bdrv_format_default_perms,
    .bdrv_check_perm    = s2e_check_perm,

    .bdrv_co_readv          = s2e_co_readv,
    .bdrv_co_writev         = s2e_co_writev,

    .bdrv_getlength     = s2e_getlength,

    .bdrv_snapshot_create   = s2e_snapshot_create,
    .bdrv_snapshot_goto     = s2e_snapshot_goto,
    .bdrv_snapshot_delete   = s2e_snapshot_delete,
    .bdrv_snapshot_list     = s2e_snapshot_list,
    .bdrv_get_info          = s2e_get_info,

    .bdrv_save_vmstate    = s2e_save_vmstate,
    .bdrv_load_vmstate    = s2e_load_vmstate,

    .bdrv_co_ioctl         = s2e_ioctl,

    .bdrv_reopen_fd = s2e_reopen_fd
};

static void bdrv_s2e_init(void)
{
    bdrv_register(&bdrv_s2e);
}

block_init(bdrv_s2e_init);
