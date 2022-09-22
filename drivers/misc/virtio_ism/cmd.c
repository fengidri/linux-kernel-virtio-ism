// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright Alibaba Group. 2022
 *
 * Author(s): Xuan Zhuo <xuanzhuo@linux.alibaba.com>
 */

#include "ism.h"

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
		dev_warn(&ism->vdev->dev, "command(%d.%d) status err. %d\n",
			 class, cmd, (int)ism->ctrl->status);
		++ism->stats.cmd_err;

		return -ism->ctrl->status;
	}

	++ism->stats.cmd_success;
	return 0;
}

void dev_kick(struct virtio_ism *ism, u64 offset)
{
	u64 off;
	u8 v = 1;

	off = offset >> ism->chunk_size_shift;
	off = off * ism->notify_size;

	if (off >= ism->notify_reg.len) {
		dev_warn(&ism->vdev->dev, "invalid notify offset: %llu\n.", offset);
		return;
	}

	iowrite8(v, ism->notify_p + off);
	++ism->stats.kick;
}

int dev_inform_vector(struct virtio_ism *ism, u64 token, u32 vector)
{
	struct virtio_ism_ctrl_irq_vector *vector_out;
	struct scatterlist sgs_out;

	vector_out = &ism->ctrl->vector_out;

	vector_out->token = token;
	vector_out->vector = vector;

	sg_init_one(&sgs_out, vector_out, sizeof(*vector_out));

	return virtio_ism_send_command(ism, VIRTIO_ISM_CTRL_EVENT_VECTOR,
				       VIRTIO_ISM_CTRL_EVENT_VECTOR_SET,
				       &sgs_out, NULL);
}

void dev_detach(struct virtio_ism *ism, u64 token)
{
	struct virtio_ism_ctrl_detach *out = &ism->ctrl->detach_out;
	struct scatterlist sgs_out;
	int err;

	out->token = token;
	sg_init_one(&sgs_out, out, sizeof(*out));

	err = virtio_ism_send_command(ism, VIRTIO_ISM_CTRL_DETACH,
				      VIRTIO_ISM_CTRL_DETACH_REGION,
				      &sgs_out, NULL);
	if (err)
		dev_warn(&ism->vdev->dev,
			 "Failed to detach: %llu\n", token);
	++ism->stats.detach;
}

int dev_attach(struct virtio_ism *ism, u64 token, void *r, u32 size)
{
	struct virtio_ism_ctrl_attach *attach_out;
	struct scatterlist sgs_in, sgs_out;
	int err;

	attach_out = &ism->ctrl->attach_out;

	attach_out->token = cpu_to_le64(token);

	sg_init_one(&sgs_in, r, size);
	sg_init_one(&sgs_out, attach_out, sizeof(*attach_out));

	++ism->stats.attach;
	err = virtio_ism_send_command(ism, VIRTIO_ISM_CTRL_ATTACH,
				      VIRTIO_ISM_CTRL_ATTACH_REGION,
				      &sgs_out, &sgs_in);
	if (err)
		return err;

	return 0;
}

int dev_alloc(struct virtio_ism *ism, u64 *token, void *r, u64 len, u32 size)
{
	struct virtio_ism_ctrl_alloc *alloc_out;
	struct scatterlist sgs_out, sgs_in;
	int err;

	alloc_out = &ism->ctrl->alloc_out;

	alloc_out->size = cpu_to_le64(len);

	sg_init_one(&sgs_out, alloc_out, sizeof(*alloc_out));
	sg_init_one(&sgs_in, r, size);

	++ism->stats.alloc;
	err = virtio_ism_send_command(ism, VIRTIO_ISM_CTRL_ALLOC,
				      VIRTIO_ISM_CTRL_ALLOC_REGION,
				      &sgs_out, &sgs_in);
	if (err)
		return err;

	if (token)
		*token = le64_to_cpu(((struct virtio_ism_ctrl_alloc_reply *)r)->token);

	return 0;
}

MODULE_AUTHOR("Xuan Zhuo <xuanzhuo@linux.alibaba.com>");
MODULE_DESCRIPTION("Virtio-ISM driver cmd");
MODULE_LICENSE("GPL");
