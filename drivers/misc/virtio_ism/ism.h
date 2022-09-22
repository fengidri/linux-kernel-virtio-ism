// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef  _DRIVERS_VIRTIO_ISM_ISM_H
#define _DRIVERS_VIRTIO_ISM_ISM_H

#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/virtio_ism.h>
#include <linux/list.h>


int virtio_ism_misc_init(struct virtio_ism *ism);
void virtio_ism_misc_free(struct virtio_ism *ism);
int virtio_ism_ops_init(struct virtio_ism *ism);
void virtio_ism_ops_exit(struct virtio_ism *ism);

void dev_kick(struct virtio_ism *ism, u64 offset);
int dev_inform_vector(struct virtio_ism *ism, u64 offset, u32 vector);
void dev_detach(struct virtio_ism *ism, u64 token);
int dev_attach(struct virtio_ism *ism, u64 token, void *r, u32 size);
int dev_alloc(struct virtio_ism *ism, u64 *token, void *r, u64 len, u32 size);
#endif


