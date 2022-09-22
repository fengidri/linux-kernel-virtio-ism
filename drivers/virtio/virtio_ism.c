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

#define DEBUG 1

#ifdef DEBUG
#include <linux/proc_fs.h>
#include <linux/kstrtox.h>
#endif


struct virtio_ism_config {
	u64 gid;
	u64 devid;
	u64 region_size;
	u64 notify_size;
};

struct virtio_ism_event {
	u64 num;
	u64 offset[];
};

enum virtio_ism_shm_id {
	VIRTIO_ISM_SHM_ID_UNDEFINED = 0,
	VIRTIO_ISM_SHM_ID_REGIONS   = 1,
	VIRTIO_ISM_SHM_ID_NOTIFY    = 2,
};

/* ack values */
#define VIRTIO_ISM_OK     0
#define VIRTIO_NET_ERR    1


struct virtio_ism_ctrl_alloc {
	u64 size;
};

struct virtio_ism_ctrl_alloc_reply {
	u64 token;
	u64 offset;
};

#define VIRTIO_ISM_CTRL_ALLOC  0
	#define VIRTIO_ISM_CTRL_ALLOC_REGION 0

struct virtio_ism_ctrl_attach {
	u64 token;
};

struct virtio_ism_ctrl_attach_reply {
	u64 offset;
};

#define VIRTIO_ISM_CTRL_ATTACH  1
	#define VIRTIO_ISM_CTRL_ATTACH_REGION 0

struct virtio_ism_ctrl_detach {
	u64 offset;
};

#define VIRTIO_ISM_CTRL_DETACH  2
	#define VIRTIO_ISM_CTRL_DETACH_REGION 0

struct virtio_ism_ctrl_grant {
	u64 offset;
	u64 peer_devid;
	u64 permissions;
};

#define VIRTIO_ISM_CTRL_GRANT  3
	#define VIRTIO_ISM_CTRL_GRANT_SET 0

#define VIRTIO_ISM_PERM_READ       (1 << 0)
#define VIRTIO_ISM_PERM_WRITE      (1 << 1)
#define VIRTIO_ISM_PERM_ATTACH     (1 << 2)
#define VIRTIO_ISM_PERM_MANAGE     (1 << 3)
#define VIRTIO_ISM_PERM_DENY_OTHER (1 << 4)


struct virtio_ism_ctrl_irq_vector {
	u64 offset;
	u64 vector;
};

#define VIRTIO_ISM_CTRL_EVENT_VECTOR  4
	#define VIRTIO_ISM_CTRL_EVENT_VECTOR_SET 0

#define VIRTIO_ISM_F_EVENT_IRQ 0

struct virtio_ism_ctrl_hdr {
	__u8 class;
	__u8 cmd;
} __attribute__((packed));

struct control_buf {
	u8 status;

	struct virtio_ism_ctrl_hdr hdr;

	struct virtio_ism_ctrl_alloc alloc_out;
	struct virtio_ism_ctrl_alloc_reply alloc_in;

	struct virtio_ism_ctrl_attach attach_out;
	struct virtio_ism_ctrl_attach_reply attach_in;
	struct virtio_ism_ctrl_irq_vector vector_out;
};

struct virtio_ism_irq_cb {
	u64 offset;
	struct virtio_ism *ism;
};

struct virtio_ism {
	struct virtio_device *vdev;

	u64 gid;
	u64 devid;
	u64 region_size;
	u64 notify_size;

	struct control_buf *ctrl;

	struct virtqueue *cvq;

	struct virtio_shm_region notify_reg;
	struct virtio_shm_region shm_reg;

	int free_vector;

	void *shm_p;
	void __iomem *notify_p;
};

#if DEBUG
struct virtio_ism *ISM;
static char *POS;
#endif

static irqreturn_t ism_interrupt(int irq, void *_)
{
	struct virtio_ism_irq_cb *cb = _;

	printk(KERN_ERR "ism recv inter for offset: %llu\n", cb->offset);

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

	if (ism->ctrl->status)
		dev_warn(&ism->vdev->dev, "command status err. %d\n", ism->ctrl->status);

	return ism->ctrl->status;
}

static void virtio_ism_notify(struct virtio_ism *ism, void *p)
{
	u64 offset;
	u8 v = 1;

	offset = p - ism->shm_p;

	iowrite8(v, ism->notify_p + offset / ism->region_size);
}

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

static int virtio_ism_bind_irq(struct virtio_ism *ism, u64 offset)
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

	err = request_irq(vp_irq(ism->vdev, vector), ism_interrupt, 0, "ism", cb);
	if (err)
		return err;

	return virtio_ism_inform_vector(ism, offset, vector);
}

static void *virtio_ism_alloc(struct virtio_ism *ism, u64 *token)
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

	err = virtio_ism_bind_irq(ism, offset);
	if (err)
		return ERR_PTR(err);

	return ism->shm_p + offset;
}

static void *virtio_ism_attach(struct virtio_ism *ism, u64 token)
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

	printk(KERN_ERR "attach offset: %lu\n", offset);

	err = virtio_ism_bind_irq(ism, offset);
	if (err)
		return ERR_PTR(err);

	return ism->shm_p + offset;
}

static void virtio_ism_dettach(struct virtio_ism *ism, void *pos)
{
	// TODO
}


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

#if DEBUG
static struct proc_dir_entry *proc;

static ssize_t	__proc_write(struct file *f, const char __user *ubuf, size_t size, loff_t *l)
{
	char buf[512] = {};
	int i, r;
	void *p;

	struct virtio_ism *ism = ISM;

	r = copy_from_user(buf, ubuf, size);

	for (i = 0; i < size; ++i) {
		if (' ' == buf[i])
			goto found;
	}

	return size;

found:
	if (0 == strncmp(buf, "alloc", i)) {
		u64 token;

		p = virtio_ism_alloc(ism, &token);

		POS = p;

		printk(KERN_ERR "alloc token: %llu %p\n", token, p);
	}

	if (0 == strncmp(buf, "attach", i)) {
		u64 token;

		r = kstrtoull(buf + i + 1, 10, &token);
		if (!r) {
			printk(KERN_ERR "attach token: %lu\n", token);

			p = virtio_ism_attach(ism, token);

			POS = p;

			printk(KERN_ERR "attach: %p\n", p);
		}

	}

	if (0 == strncmp(buf, "write", i)) {
		printk(KERN_ERR "POS: %p\n", POS);

		memcpy(POS, buf + i+1, size - i - 1);

		printk(KERN_ERR "mem: %s\n", POS);

	}

	if (0 == strncmp(buf, "read", i)) {
		printk(KERN_ERR "POS: %p\n", POS);

		printk(KERN_ERR "mem: %s\n", POS);
	}

	if (0 == strncmp(buf, "notify", i)) {
		int r;
		u64 offset;
		r = kstrtoull(buf + i + 1, 10, &offset);

		if (r)
			offset = 0;

		printk(KERN_ERR "offset: %lld %s %d\n", offset, buf + i + 1, r);

		virtio_ism_notify(ism, POS + offset);
	}

	if (0 == strncmp(buf, "dettach", i)) {
		virtio_ism_dettach(ism, 0);

	}

	return size;
}

static ssize_t	proc_write(struct file *f, const char __user *ubuf, size_t size, loff_t *l)
{
	__proc_write(f, ubuf, size, l);
	return size;
}

static struct proc_ops ops ={
	.proc_write = proc_write,
};

static void test(void)
{
    proc = proc_create("test", 0644, NULL, &ops);
    if (!proc){
        printk(KERN_INFO "create proc failed\n");
        return;
    }
}
#endif

static int virtio_ism_probe(struct virtio_device *vdev)
{
	struct virtio_ism *ism;
	struct virtqueue *cvq;
	bool have_shm, have_notify;
	int rc;

	ism = kzalloc(sizeof(*ism), GFP_KERNEL);
	if (!ism)
		return -ENOMEM;

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

#if DEBUG
	ISM = ism;

	test();
#endif
	return 0;

cq_err:
map_err:
region_err:
	kfree(ism->ctrl);

err:
	kfree(ism);
	return rc;
}

static void virtio_ism_remove(struct virtio_device *vdev)
{
	struct virtio_ism *ism;
	int v;

	ism = vdev->priv;

	vdev->config->del_vqs(vdev);

	for (v = 10; v < vdev->nvec; ++v) {
		int irq = vp_irq(vdev, v);
		irq_set_affinity_hint(irq, NULL);
		free_irq(irq, NULL);
	}

	kfree(ism->ctrl);
	kfree(ism);

#if DEBUG
	proc_remove(proc);
#endif
}

static unsigned int virtio_ism_features[] = {
	VIRTIO_ISM_F_EVENT_IRQ
};

static const struct virtio_device_id virtio_ism_id_table[] = {
	{ VIRTIO_ID_ISM, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_ism_driver = {
	.feature_table = virtio_ism_features,
	.feature_table_size = ARRAY_SIZE(virtio_ism_features),
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.id_table = virtio_ism_id_table,
	.probe = virtio_ism_probe,
	.remove = virtio_ism_remove,
};

module_virtio_driver(virtio_ism_driver);
MODULE_DEVICE_TABLE(virtio, virtio_ism_id_table);
MODULE_AUTHOR("Xuan Zhuo <xuanzhuo@linux.alibaba.com>");
MODULE_DESCRIPTION("Virtio-ISM driver");
MODULE_LICENSE("GPL");
