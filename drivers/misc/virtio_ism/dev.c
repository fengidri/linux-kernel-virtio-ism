// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright Alibaba Group. 2022
 *
 * Author(s): Xuan Zhuo <xuanzhuo@linux.alibaba.com>
 */

#include "ism.h"
#include <linux/eventpoll.h>
#include <linux/poll.h>

struct virtio_ism_ctx {
	struct virtio_ism *ism;
	void *p;
	u64 token;

	wait_queue_head_t wait;
	bool ready;
};

static int virtio_ism_dev_callback(struct virtio_ism *ism, void *p, void *data)
{
	struct virtio_ism_ctx *ctx = data;

	ctx->ready = true;
	wake_up_interruptible_poll(&ctx->wait, EPOLLIN | EPOLLRDNORM);

	return 0;
}

static int virtio_ism_release(struct inode *inode, struct file *f)
{
	struct virtio_ism_ctx *ctx;

	ctx = f->private_data;

	if (ctx->p)
		ctx->ism->ops->detach(ctx->ism, ctx->token);

	kfree(ctx);
	return 0;
}

static __poll_t virtio_ism_chr_poll(struct file *f, poll_table *wait)
{
	struct virtio_ism_ctx *ctx;
	__poll_t mask = 0;

	ctx = f->private_data;

	poll_wait(f, &ctx->wait, wait);

	if (ctx->ready) {
		ctx->ready = false;
		return POLLIN;
	}

	return mask;
}

static int virtio_ism_mmap(struct file *f, struct vm_area_struct *vma)
{
	unsigned long size = vma->vm_end - vma->vm_start;
	struct virtio_ism_ctx *ctx;
	unsigned long pfn;

	ctx = f->private_data;

	if (!ctx->p)
		return -ENOMEM;

	pfn = vmalloc_to_pfn(ctx->p);

	return io_remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot);
}

static long virtio_ism_ioctl_handler(struct file *f, unsigned int ioctl,
				     unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct virtio_ism_ioctl ctl;
	struct virtio_ism_ctx *ctx;
	struct virtio_ism *ism;
	void *p;

	ctx = f->private_data;
	ism = ctx->ism;

	switch(ioctl) {
	case VIRTIO_ISM_IOCTL_ALLOC:
		if (copy_from_user(&ctl, argp, sizeof ctl))
			return -EFAULT;

		p = ism->ops->alloc(ism, &ctl.token, ctl.size, virtio_ism_dev_callback, ctx);
		if (IS_ERR(p))
			return PTR_ERR(p);

		ctx->token = ctl.token;
		ctx->p = p;

		if (copy_to_user(argp, &ctl, sizeof ctl))
			return -EFAULT;

		return 0;

	case VIRTIO_ISM_IOCTL_ATTACH:
		if (copy_from_user(&ctl, argp, sizeof ctl))
			return -EFAULT;

		p = ism->ops->attach(ism, ctl.token, &ctl.size, virtio_ism_dev_callback, ctx);

		if (IS_ERR(p))
			return PTR_ERR(p);

		ctx->token = ctl.token;
		ctx->p = p;

		return 0;

	case VIRTIO_ISM_IOCTL_KICK:
		if (!ctx->p)
			return -ENOMEM;

		ism->ops->kick(ism, ctx->p);

		return 0;
	}

	return -ENODEV;
}

static int virtio_ism_open(struct inode *inode, struct file *f)
{
	struct virtio_ism_ctx *ctx;

	ctx = kzalloc(sizeof *ctx, GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->ism = container_of(f->private_data, struct virtio_ism, miscdev);
	ctx->p = NULL;

	init_waitqueue_head(&ctx->wait);

	f->private_data = ctx;

	return 0;
}

static const struct file_operations virtio_ism_fops = {
	.owner          = THIS_MODULE,
	.release        = virtio_ism_release,
	.poll           = virtio_ism_chr_poll,
	.unlocked_ioctl = virtio_ism_ioctl_handler,
	.compat_ioctl   = compat_ptr_ioctl,
	.open           = virtio_ism_open,
	.mmap		= virtio_ism_mmap,
	.llseek		= noop_llseek,
};

int virtio_ism_misc_init(struct virtio_ism *ism)
{
	static unsigned int dev_idx;

	ism->miscdev.minor = MISC_DYNAMIC_MINOR;
	ism->miscdev.fops = &virtio_ism_fops;
	ism->miscdev.name = ism->devname;

	snprintf(ism->devname, sizeof(ism->devname), "vism%u", dev_idx++);

	return misc_register(&ism->miscdev);
}

void virtio_ism_misc_free(struct virtio_ism *ism)
{
	misc_deregister(&ism->miscdev);
}

MODULE_AUTHOR("Xuan Zhuo <xuanzhuo@linux.alibaba.com>");
MODULE_DESCRIPTION("Virtio-ISM driver dev ops");
MODULE_LICENSE("GPL");
