/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Virtio ISM Device
 *
 * Copyright Alibaba Group. 2022
 *
 * Author(s): Xuan Zhuo <xuanzhuo@linux.alibaba.com>
 *
 * This header is BSD licensed so anyone can use the definitions
 * to implement compatible drivers/servers:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Alibaba nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL Alibaba OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _UAPI_LINUX_VIRTIO_ISM_H
#define _UAPI_LINUX_VIRTIO_ISM_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct virtio_ism_ioctl {
	__u64 size;
	__u64 token;
};

struct virtio_ism_stat {
	__u64 total_size;
	__u64 chunk_size;

	__u64 region_active;
	__u64 region_free;

	__u64 alloc;
	__u64 attach;
	__u64 detach;
	__u64 kick;

	__u64 cmd_err;
	__u64 cmd_success;

	__u64 irq_inuse;
};

#define VIRTIO_ISM_MAGIC 0xDF

#define CMD0(nr, st, rw) _IO##rw(VIRTIO_ISM_MAGIC, nr, st)
#define CMD1(nr, rw) _IO##rw(VIRTIO_ISM_MAGIC, nr, struct virtio_ism_ioctl)
#define CMD2(nr) _IO(VIRTIO_ISM_MAGIC, nr)

#define VIRTIO_ISM_IOCTL_GET_GID      CMD1(0,   W)
#define VIRTIO_ISM_IOCTL_GET_DEVID    CMD1(1,   W)
#define VIRTIO_ISM_IOCTL_ALLOC        CMD1(10,  WR)
#define VIRTIO_ISM_IOCTL_ATTACH       CMD1(11,  R)
#define VIRTIO_ISM_IOCTL_DETACH       CMD2(12)
#define VIRTIO_ISM_IOCTL_KICK         CMD2(20)
#define VIRTIO_ISM_IOCTL_STAT         CMD0(30, struct virtio_ism_stat, W)

#endif /* _UAPI_LINUX_VIRTIO_ISM_H */
