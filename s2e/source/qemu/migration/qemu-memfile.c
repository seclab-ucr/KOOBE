/*
 * QEMUFile backend for in-memory snapshots
 *
 * Copyright (c) 2018 Cyberhaven
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdint.h>
#include <stdbool.h>
#include <memory.h>

#include "qemu/osdep.h"
#include "qemu-memfile.h"

typedef struct QEMUFileMemory
{
    QEMUFile *file;
    uint8_t *buffer;
    size_t buffer_size;
} QEMUFileMemory;

static void *qemu_memfile_get_internal_storage(void *opaque, size_t *size)
{
    QEMUFileMemory *s = (QEMUFileMemory*) opaque;
    *size = s->buffer_size;
    return s->buffer;
}

static ssize_t qemu_memfile_get(void *opaque, uint8_t *buf, int64_t pos, size_t size)
{
    QEMUFileMemory *s = opaque;
    ssize_t real_size;
    if (pos + size <= s->buffer_size) {
        real_size = size;
    } else {
        real_size = s->buffer_size - pos;
    }
    memcpy(buf, &s->buffer[pos], real_size);
    return real_size;
}

static int qemu_memfile_put(void *opaque, const uint8_t *buf,
                            int64_t pos, int size)
{
    QEMUFileMemory *s = opaque;
    if (pos + size > s->buffer_size) {
        s->buffer_size = pos + size;
        s->buffer = g_realloc(s->buffer, s->buffer_size);
    }
    memcpy(&s->buffer[pos], buf, size);
    return size;
}

static ssize_t qemu_memfile_write(void *opaque, struct iovec *iov,
                              int iovcnt, int64_t pos)
{
    ssize_t ret = 0;
    for (int i = 0; i < iovcnt; ++i) {
        int sz = qemu_memfile_put(opaque, iov->iov_base, pos, iov->iov_len);
        pos += sz;
        ret += sz;
    }
    return ret;
}

static int qemu_memfile_close(void *opaque)
{
    QEMUFileMemory *s = opaque;
    g_free(s->buffer);
    g_free(s);
    return 0;
}

static const QEMUFileOps qemu_memfile_ops = {
    .get_buffer = qemu_memfile_get,
    .writev_buffer = qemu_memfile_write,
    .close = qemu_memfile_close,
    .get_internal_storage = qemu_memfile_get_internal_storage
};

static const QEMUFileOps qemu_memfile_ops_ro = {
    .get_buffer = qemu_memfile_get,
    .close = qemu_memfile_close,
    .get_internal_storage = qemu_memfile_get_internal_storage
};

QEMUFile *qemu_memfile_open(void)
{
    QEMUFileMemory *s = (QEMUFileMemory *)g_malloc0(sizeof(QEMUFileMemory));
    s->file = qemu_fopen_ops(s, &qemu_memfile_ops);
    return s->file;
}

static int fill_buffer(QEMUFileMemory *s, QEMUMemFileReadCb cb)
{
    uint8_t buffer[0x10000];
    size_t pos=0;
    int ret = 0;

    do {
        ret = cb(buffer, pos, sizeof(buffer));
        if (ret > 0) {
            qemu_memfile_put(s, buffer, pos, ret);
            pos += ret;
        }
    } while (ret > 0);

    if (ret < 0) {
        fprintf(stderr, "qemu-memfile: could not read data\n");
        return ret;
    }

    return 0;
}

QEMUFile *qemu_memfile_open_ro(QEMUMemFileReadCb cb)
{
    QEMUFileMemory *s = (QEMUFileMemory *)g_malloc0(sizeof(QEMUFileMemory));

    if (fill_buffer(s, cb) < 0) {
        return NULL;
    }

    s->file = qemu_fopen_ops(s, &qemu_memfile_ops_ro);
    return s->file;
}
