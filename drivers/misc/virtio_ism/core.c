// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright Alibaba Group. 2022
 *
 * Author(s): Xuan Zhuo <xuanzhuo@linux.alibaba.com>
 */

#include "ism.h"

static struct list_head ism_drivers;

static RAW_NOTIFIER_HEAD(vism_chain);

static int virtio_ism_notifier_call(struct virtio_ism *ism, int val)
{
	struct virtio_ism_notifier_info info;
	int ret;

	info.ism = ism;

	ret = raw_notifier_call_chain(&vism_chain, val, &info);

	return ret;
}


int virtio_ism_register_notifier(struct notifier_block *nb)
{
	struct virtio_ism *ism;
	int err;

	err = raw_notifier_chain_register(&vism_chain, nb);
	if (err)
		return err;

	list_for_each_entry(ism, &ism_drivers, node)
		virtio_ism_notifier_call(ism, VIRTIO_ISM_NOTIFIER_EVENT_PROBE);

	return 0;
}
EXPORT_SYMBOL(virtio_ism_register_notifier);

int virtio_ism_unregister_notifier(struct notifier_block *nb)
{
	int err;

	err = raw_notifier_chain_register(&vism_chain, nb);

	return err;
}
EXPORT_SYMBOL(virtio_ism_unregister_notifier);

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

	ism->region_num = ism->shm_reg.len / ism->chunk_size;

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

static int virtio_ism_vqs_vectors_init(struct virtio_ism *ism)
{
	struct virtio_vqs_vectors param = {};
	vq_callback_t *callbacks[1] = { NULL };
	const char *names[1] = { "ism-cq" };
	int err, vector_n;

	param.reserve_vectors = ism->region_num;
	param.nvqs = 1;
	param.vqs = &ism->cvq;
	param.callbacks = callbacks;
	param.names = names;

	err = virtio_find_vqs_and_vectors(ism->vdev, &param);
	if (err) {
		dev_warn(&ism->vdev->dev, "find vqs and vectors fail. %d\n", err);
		return err;
	}

	vector_n = param.vector_end - param.vector_start + 1;

	ism->vector_start = param.vector_start;
	ism->vector_num = vector_n;

	return 0;
}

extern struct virtio_ism_ops vism_ops;

static struct virtio_ism *virtio_ism_dev_alloc(struct virtio_device *vdev)
{
	bool have_shm, have_notify;
	struct virtio_ism *ism;
	int rc;

	ism = kzalloc(sizeof(*ism), GFP_KERNEL);
	if (!ism)
		return ERR_PTR(-ENOMEM);

	ism->ops = &vism_ops;
	ism->vdev = vdev;
	ism->rbtree = RB_ROOT;
	vdev->priv = ism;

	mutex_init(&ism->mutex);

	virtio_cread_le(vdev, struct virtio_ism_config, gid, &ism->gid);
	virtio_cread_le(vdev, struct virtio_ism_config, devid, &ism->devid);
	virtio_cread_le(vdev, struct virtio_ism_config, chunk_size, &ism->chunk_size);
	virtio_cread_le(vdev, struct virtio_ism_config, notify_size, &ism->notify_size);

	if (!is_power_of_2(ism->chunk_size)) {
		dev_warn(&vdev->dev, "chunk size(%lld) must be power of 2.\n", ism->chunk_size);
		goto err;
	}

	ism->chunk_size_shift = ilog2(ism->chunk_size);

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

	rc = virtio_ism_vqs_vectors_init(ism);
	if (rc)
		goto cq_err;

	virtio_ism_notifier_call(ism, VIRTIO_ISM_NOTIFIER_EVENT_PROBE);

	return ism;

cq_err:
map_err:
region_err:
	kfree(ism->ctrl);

err:
	kfree(ism);
	return ERR_PTR(rc);
}

static void virtio_ism_dev_free(struct virtio_ism *ism)
{
	virtio_ism_notifier_call(ism, VIRTIO_ISM_NOTIFIER_EVENT_REMOVE);

	virtio_reset_device(ism->vdev);

	virtio_ism_ops_exit(ism);
	virtio_ism_misc_free(ism);

	ism->vdev->config->del_vqs(ism->vdev);

	kfree(ism->ctrl);
	kfree(ism);
}

static int virtio_ism_probe(struct virtio_device *vdev)
{
	struct virtio_ism *ism;
	int err;

	ism = virtio_ism_dev_alloc(vdev);
	if (IS_ERR(ism))
		return PTR_ERR(ism);

	err = virtio_ism_ops_init(ism);
	if (err) {
		virtio_ism_dev_free(ism);
		return err;
	}

	err = virtio_ism_misc_init(ism);
	if (err) {
		virtio_ism_dev_free(ism);
		return err;
	}

	list_add(&ism->node, &ism_drivers);

	return 0;
}

static void virtio_ism_remove(struct virtio_device *vdev)
{
	struct virtio_ism *ism;

	ism = vdev->priv;

	list_del(&ism->node);

	virtio_ism_dev_free(ism);
}

static unsigned int virtio_ism_features[] = {
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

	RAW_INIT_NOTIFIER_HEAD(&vism_chain);

	INIT_LIST_HEAD(&ism_drivers);

	err = register_virtio_driver(&virtio_ism_driver);
	if (err)
		return err;

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
