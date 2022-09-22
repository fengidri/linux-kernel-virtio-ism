// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright Alibaba Group. 2022
 *
 * Author(s): Xuan Zhuo <xuanzhuo@linux.alibaba.com>
 */

#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include "virtio_ism.h"

static irqreturn_t ism_interrupt(int irq, void *_)
{
	struct virtio_ism_irq_cb *cb = _;
	struct virtio_ism *ism = cb->ism;

	if (ism->callback)
		ism->callback(ism, ism->shm_p + cb->offset, cb->notify_data);

	return IRQ_HANDLED;
}

static int virtio_ism_send_command(struct virtio_ism *ism, u8 class, u8 cmd,
				     struct scatterlist *out,
				     struct scatterlist *in)
{
	struct scatterlist *sgs[5], hdr, stat;
	unsigned out_num = 0, in_num = 0, tmp;
	int ret;

	ism->ctrl->status = ~0;
	ism->ctrl->hdr.class = class;
	ism->ctrl->hdr.cmd = cmd;

	/* Add header */
	sg_init_one(&hdr, &ism->ctrl->hdr, sizeof(ism->ctrl->hdr));
	sgs[out_num++] = &hdr;

	if (out)
		sgs[out_num++] = out;

	/* Add return status. */
	sg_init_one(&stat, &ism->ctrl->status, sizeof(ism->ctrl->status));
	sgs[out_num + in_num++] = &stat;

	if (in)
		sgs[out_num + in_num++] = in;

	ret = virtqueue_add_sgs(ism->cvq, sgs, out_num, in_num, ism, GFP_ATOMIC);
	if (ret < 0) {
		dev_warn(&ism->vdev->dev,
			 "Failed to add sgs for command vq: %d\n.", ret);
		return false;
	}

	if (unlikely(!virtqueue_kick(ism->cvq)))
		return ism->ctrl->status;

	/* Spin for a response, the kick causes an ioport write, trapping
	 * into the hypervisor, so the request should be handled immediately.
	 */
	while (!virtqueue_get_buf(ism->cvq, &tmp) &&
	       !virtqueue_is_broken(ism->cvq))
		cpu_relax();

	if (ism->ctrl->status) {
		dev_warn(&ism->vdev->dev, "command status err. %d\n", ism->ctrl->status);

		return -ism->ctrl->status;
	}

	return 0;
}

void virtio_ism_notify(struct virtio_ism *ism, void *p)
{
	u64 offset;
	u8 v = 1;

	offset = p - ism->shm_p;

	iowrite8(v, ism->notify_p + offset / ism->region_size);
}
EXPORT_SYMBOL_GPL(virtio_ism_notify);

static int virtio_ism_inform_vector(struct virtio_ism *ism, u64 offset, u32 vector)
{
	struct virtio_ism_ctrl_irq_vector *vector_out;
	struct scatterlist sgs_out;
	int err;

	vector_out = &ism->ctrl->vector_out;

	vector_out->offset = offset;
	vector_out->vector = vector;

	sg_init_one(&sgs_out, vector_out, sizeof(*vector_out));

	err = virtio_ism_send_command(ism, VIRTIO_ISM_CTRL_EVENT_VECTOR,
				      VIRTIO_ISM_CTRL_EVENT_VECTOR_SET,
				      &sgs_out, NULL);
	return err;
}

static int virtio_ism_bind_irq(struct virtio_ism *ism, u64 offset, void *notify_data)
{
	struct virtio_ism_irq_cb *cb;
	int vector, err;

	vector = ism->free_vector;

	if (vector > ism->vdev->nvec)
		return -ENOSPC;

	ism->free_vector++;

	cb = kmalloc(sizeof(*cb), GFP_KERNEL);
	if (!cb)
		return -ENOMEM;

	cb->ism = ism;
	cb->offset = offset;
	cb->notify_data = notify_data;

	err = request_irq(vp_irq(ism->vdev, vector), ism_interrupt, 0, "ism", cb);
	if (err)
		return err;

	return virtio_ism_inform_vector(ism, offset, vector);
}

void *virtio_ism_alloc(struct virtio_ism *ism, u64 *token, u32 len, void *notify_data)
{
	struct virtio_ism_ctrl_alloc *alloc_out;
	struct virtio_ism_ctrl_alloc_reply *alloc_in;
	struct scatterlist sgs_out, sgs_in;
	int err;
	u64 offset;

	alloc_out = &ism->ctrl->alloc_out;
	alloc_in = &ism->ctrl->alloc_in;

	alloc_out->size = ism->region_size;

	sg_init_one(&sgs_out, alloc_out, sizeof(*alloc_out));
	sg_init_one(&sgs_in, alloc_in, sizeof(*alloc_in));

	err = virtio_ism_send_command(ism, VIRTIO_ISM_CTRL_ALLOC,
				      VIRTIO_ISM_CTRL_ALLOC_REGION,
				      &sgs_out, &sgs_in);
	if (err)
		return ERR_PTR(err);

	offset = le64_to_cpu(alloc_in->offset);

	if (token)
		*token = le64_to_cpu(alloc_in->token);

	err = virtio_ism_bind_irq(ism, offset, notify_data);
	if (err)
		return ERR_PTR(err);

	return ism->shm_p + offset;
}
EXPORT_SYMBOL_GPL(virtio_ism_alloc);

void *virtio_ism_attach(struct virtio_ism *ism, u64 token, u32 len, void *notify_data)
{
	struct virtio_ism_ctrl_attach *attach_out = &ism->ctrl->attach_out;
	struct virtio_ism_ctrl_attach_reply *attach_in = &ism->ctrl->attach_in;
	struct scatterlist sgs_in, sgs_out;
	u64 offset;
	int err;

	memset(attach_out, 0, sizeof(attach_out));

	attach_out->token = cpu_to_le64(token);

	sg_init_one(&sgs_in, attach_in, sizeof(*attach_in));
	sg_init_one(&sgs_out, attach_out, sizeof(*attach_out));

	err = virtio_ism_send_command(ism, VIRTIO_ISM_CTRL_ATTACH,
				       VIRTIO_ISM_CTRL_ATTACH_REGION,
				       &sgs_out, &sgs_in);
	if (err)
		return ERR_PTR(err);

	offset = le64_to_cpu(attach_in->offset);

	err = virtio_ism_bind_irq(ism, offset, notify_data);
	if (err)
		return ERR_PTR(err);

	return ism->shm_p + offset;
}
EXPORT_SYMBOL_GPL(virtio_ism_attach);

void virtio_ism_detach(struct virtio_ism *ism, void *pos)
{
	// TODO
}
EXPORT_SYMBOL_GPL(virtio_ism_detach);

static int virtio_ism_shm_map(struct virtio_ism *ism, struct virtio_device *vdev)
{
	struct dev_pagemap *pgmap;

	if (!devm_request_mem_region(&vdev->dev,
				     ism->shm_reg.addr,
				     ism->shm_reg.len,
				     "virtio-ism"))
	{
		dev_warn(&vdev->dev, "could not reserve region addr=0x%llx len=0x%llx\n",
			 ism->shm_reg.addr, ism->shm_reg.len);
		return -EBUSY;
	}

	pgmap = devm_kzalloc(&vdev->dev, sizeof(*pgmap), GFP_KERNEL);
	if (!pgmap)
		return -ENOMEM;

	pgmap->type = MEMORY_DEVICE_PCI_P2PDMA;

	/* Ideally we would directly use the PCI BAR resource but
	 * devm_memremap_pages() wants its own copy in pgmap.  So
	 * initialize a struct resource from scratch (only the start
	 * and end fields will be used).
	 */
	pgmap->range = (struct range) {
		.start = (phys_addr_t) ism->shm_reg.addr,
		.end = (phys_addr_t) ism->shm_reg.addr + ism->shm_reg.len - 1,
	};
	pgmap->nr_range = 1;

	ism->shm_p = devm_memremap_pages(&vdev->dev, pgmap);
	if (IS_ERR(ism->shm_p)) {
		dev_warn(&vdev->dev, "memremap fail. %ld\n", PTR_ERR(ism->shm_p));
		return PTR_ERR(ism->shm_p);
	}

	return 0;
}

static int virtio_ism_notify_map(struct virtio_ism *ism, struct virtio_device *vdev)
{
	ism->notify_p = devm_ioremap(&vdev->dev, ism->notify_reg.addr, ism->notify_reg.len);


	if (IS_ERR(ism->notify_p)) {
		dev_warn(&vdev->dev, "ioremap fail. %ld\n", PTR_ERR(ism->notify_p));
		return PTR_ERR(ism->notify_p);
	}

	return 0;
}


struct virtio_ism *virtio_ism_dev_alloc(struct virtio_device *vdev)
{
	struct virtio_ism *ism;
	struct virtqueue *cvq;
	bool have_shm, have_notify;
	int rc;

	ism = kzalloc(sizeof(*ism), GFP_KERNEL);
	if (!ism)
		return ERR_PTR(-ENOMEM);

	ism->vdev = vdev;
	vdev->priv = ism;

	virtio_cread_le(vdev, struct virtio_ism_config, gid, &ism->gid);
	virtio_cread_le(vdev, struct virtio_ism_config, devid, &ism->devid);
	virtio_cread_le(vdev, struct virtio_ism_config, region_size, &ism->region_size);
	virtio_cread_le(vdev, struct virtio_ism_config, notify_size, &ism->notify_size);

	ism->ctrl = kzalloc(sizeof(*ism->ctrl), GFP_KERNEL);
	if (!ism) {
		rc = -ENOMEM;
		goto err;
	}

	have_shm = virtio_get_shm_region(vdev, &ism->shm_reg,
					 (u8)VIRTIO_ISM_SHM_ID_REGIONS);

	have_notify = virtio_get_shm_region(vdev, &ism->notify_reg,
					    (u8)VIRTIO_ISM_SHM_ID_NOTIFY);
	rc = -EOPNOTSUPP;
	if (!have_shm || !have_notify)
		goto region_err;

	rc = virtio_ism_shm_map(ism, vdev);
	if (rc)
		goto map_err;

	rc = virtio_ism_notify_map(ism, vdev);
	if (rc)
		goto map_err;

	vdev->nvec = 100; // TODO
	ism->free_vector = 10; // TODO

	cvq = virtio_find_single_vq(vdev, NULL, "ism-cq");
	if (IS_ERR(cvq)) {
		rc = PTR_ERR(cvq);
		goto cq_err;
	}

	ism->cvq = cvq;

	return ism;

cq_err:
map_err:
region_err:
	kfree(ism->ctrl);

err:
	kfree(ism);
	return ERR_PTR(rc);
}
EXPORT_SYMBOL_GPL(virtio_ism_dev_alloc);

void virtio_ism_dev_free(struct virtio_ism *ism)
{
	ism->vdev->config->del_vqs(ism->vdev);

	kfree(ism->ctrl);
	kfree(ism);
}
EXPORT_SYMBOL_GPL(virtio_ism_dev_free);

MODULE_AUTHOR("Xuan Zhuo <xuanzhuo@linux.alibaba.com>");
MODULE_DESCRIPTION("Virtio-ISM common");
MODULE_LICENSE("GPL");
