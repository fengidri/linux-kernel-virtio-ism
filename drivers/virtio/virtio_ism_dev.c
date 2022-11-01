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
#include <linux/poll.h>
#include <linux/miscdevice.h>
#include "virtio_ism.h"

static struct virtio_ism *ism_device;

struct virtio_ism_ctx {
	struct virtio_ism *ism;
	void *p;

	wait_queue_head_t wait;
	bool ready;
};

static void virtio_ism_ready(struct virtio_ism_ctx *ctx)
{
	ctx->ready = true;
	wake_up_interruptible_poll(&ctx->wait, EPOLLIN | EPOLLRDNORM);
}

static int virtio_ism_release(struct inode *inode, struct file *f)
{
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

	pfn = virt_to_phys(ctx->p) >> PAGE_SHIFT;

	return io_remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot);
}

static long virtio_ism_ioctl_handler(struct file *f, unsigned int ioctl,
				     unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct virtio_ism_ctx *ctx;
	struct virtio_ism_ioctl ctl;
	struct virtio_ism *ism;
	void *p;

	ctx = f->private_data;
	ism = ctx->ism;

	switch(ioctl) {
	case VIRTIO_ISM_IOCTL_ALLOC:
		fallthrough;
	case VIRTIO_ISM_IOCTL_ATTACH:
		if (copy_from_user(&ctl, argp, sizeof ctl))
			return -EFAULT;

		if (ioctl == VIRTIO_ISM_IOCTL_ALLOC)
			p = virtio_ism_alloc(ism, &ctl.token, ctl.size, ctx);
		else
			p = virtio_ism_attach(ism, ctl.token, ctl.size, ctx);

		if (IS_ERR(p))
			return PTR_ERR(p);

		ctx->p = p;

		if (ioctl == VIRTIO_ISM_IOCTL_ALLOC)
			if (copy_to_user(argp, &ctl, sizeof ctl))
				return -EFAULT;

		return 0;

	case VIRTIO_ISM_IOCTL_NOTIFY:
		if (!ctx->p)
			return -ENOMEM;

		virtio_ism_notify(ism, ctx->p);

		return 0;
	}

	return -ENODEV;
}

static int virtio_ism_open(struct inode *inode, struct file *f)
{
	struct virtio_ism_ctx *ctx;

	if (!ism_device)
		return -ENODEV;

	ctx = kvmalloc(sizeof *ctx, GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->ism = ism_device;
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

static struct miscdevice virtio_ism_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "virtio-ism",
	.fops = &virtio_ism_fops,
};

static int virtio_ism_interrupt_handler(struct virtio_ism *ism, void *p, void *data)
{
	struct virtio_ism_ctx *ctx = data;

	virtio_ism_ready(ctx);

	return 0;
}

static int virtio_ism_probe(struct virtio_device *vdev)
{
	struct virtio_ism *ism;

	ism = virtio_ism_dev_alloc(vdev);
	if (IS_ERR(ism))
		return PTR_ERR(ism);

	ism_device = ism;

	ism->callback = virtio_ism_interrupt_handler;

	return 0;
}

static void virtio_ism_remove(struct virtio_device *vdev)
{
	struct virtio_ism *ism;

	ism = vdev->priv;

	virtio_ism_dev_free(ism);
}

static unsigned int virtio_ism_features[] = {
	VIRTIO_ISM_F_EVENT_IRQ
};

static const struct virtio_device_id virtio_ism_id_table[] = {
	{ VIRTIO_ID_ISM, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_ism_driver = {
	.feature_table      = virtio_ism_features,
	.feature_table_size = ARRAY_SIZE(virtio_ism_features),
	.driver.name        = KBUILD_MODNAME,
	.driver.owner       = THIS_MODULE,
	.id_table           = virtio_ism_id_table,
	.probe              = virtio_ism_probe,
	.remove             = virtio_ism_remove,
};

static __init int virtio_ism_driver_init(void)
{
	int err;

	err = register_virtio_driver(&virtio_ism_driver);
	if (err)
		return err;

	err = misc_register(&virtio_ism_misc);
	if (err) {
		unregister_virtio_driver(&virtio_ism_driver);
		return err;
	}

	return err;
}
module_init(virtio_ism_driver_init);

static __exit void virtio_ism_driver_exit(void)
{
	unregister_virtio_driver(&virtio_ism_driver);
}
module_exit(virtio_ism_driver_exit);

MODULE_DEVICE_TABLE(virtio, virtio_ism_id_table);
MODULE_AUTHOR("Xuan Zhuo <xuanzhuo@linux.alibaba.com>");
MODULE_DESCRIPTION("Virtio-ISM driver");
MODULE_LICENSE("GPL");

