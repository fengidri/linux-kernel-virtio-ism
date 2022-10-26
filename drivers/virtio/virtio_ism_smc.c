// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <net/smc.h>

#include "virtio_ism.h"

#define VIRTIO_ISM_SMC_VERSION	"0.1"
#define DMB_NUM			1920	/* max DMB limitation per device */

struct virtio_ism_smc_systemeid {
        u8      seid_string[24];
        u8      serial_number[4];
        u8      type[4];
};

static struct virtio_ism_smc_systemeid SYSTEM_EID = {
	.seid_string = "VIRTIO-ISM-SMC-SEID1",
	.serial_number = "0000",
	.type = "0000",
};

static int virtio_ism_smc_interrupt_handler(struct virtio_ism *ism, void *p, void *notify_data)
{
	smcd_handle_irq_addr(ism->priv, p);
	return 0;
}

static int virtio_ism_smc_notify_dmb(struct smcd_dev *smcd, struct smcd_dmb *dmb)
{
	struct virtio_ism *ism = smcd->priv;

	virtio_ism_notify(ism, dmb->cpu_addr);
	return 0;
}

static int virtio_ism_smc_query_rgid(struct smcd_dev *smcd, u64 peer_rgid,
				     u32 vid_valid, u32 vid)
{
	struct virtio_ism *ism = smcd->priv;

	return ism->gid;
}

static int virtio_ism_smc_alloc_dmb(struct smcd_dev *smcd, struct smcd_dmb *dmb)
{
	struct virtio_ism *ism = smcd->priv;

	dmb->cpu_addr = virtio_ism_alloc(ism, &dmb->dmb_tok, dmb->dmb_len, NULL);
	if (IS_ERR(dmb->cpu_addr))
		return PTR_ERR(dmb->cpu_addr);

	return 0;
}

static int virtio_ism_smc_attach_dmb(struct smcd_dev *smcd, struct smcd_dmb *dmb)
{
	struct virtio_ism *ism = smcd->priv;

	dmb->cpu_addr = virtio_ism_attach(ism, dmb->dmb_tok, dmb->dmb_len, NULL);
	if (IS_ERR(dmb->cpu_addr))
		return PTR_ERR(dmb->cpu_addr);

	return 0;
}

static int virtio_ism_smc_detach_dmb(struct smcd_dev *smcd, struct smcd_dmb *dmb)
{
	// XXX: virtio_ism_detach doesn't be implemented for now.
	return 0;
}

static int virtio_ism_smc_free_dmb(struct smcd_dev *smcd, struct smcd_dmb *dmb)
{
	// XXX: virtio_ism_free doesn't be implemented for now.
	return 0;
}

static int virtio_ism_smc_add_vlan_id(struct smcd_dev *smcd, u64 vlan_id)
{
	return 0;
}

static int virtio_ism_smc_del_vlan_id(struct smcd_dev *smcd, u64 vlan_id)
{
	return 0;
}

static int virtio_ism_smc_signal_ieq(struct smcd_dev *smcd, u64 rgid,
				     u32 trigger_irq, u32 event_code, u64 info)
{
	return 0;
}

static u8 *virtio_ism_smc_get_system_eid(void)
{
	return &SYSTEM_EID.seid_string[0];
}

static u16 virtio_ism_smc_get_chid(struct smcd_dev *smcd)
{
	return 0;
}

static const struct smcd_ops virtio_ism_smc_ops = {
	.query_remote_gid = virtio_ism_smc_query_rgid,
	.alloc_dmb = virtio_ism_smc_alloc_dmb,
	.free_dmb = virtio_ism_smc_free_dmb,
	.attach_dmb = virtio_ism_smc_attach_dmb,
	.detach_dmb = virtio_ism_smc_detach_dmb,
	.notify_dmb = virtio_ism_smc_notify_dmb,
	.add_vlan_id = virtio_ism_smc_add_vlan_id,
	.del_vlan_id = virtio_ism_smc_del_vlan_id,
	.signal_event = virtio_ism_smc_signal_ieq,
	.get_system_eid = virtio_ism_smc_get_system_eid,
	.get_chid = virtio_ism_smc_get_chid,
};

static int virtio_ism_smc_probe(struct virtio_device *vdev)
{
	struct virtio_ism *ism;
	struct smcd_dev *smcd;
	int rc;

	ism = virtio_ism_dev_alloc(vdev);
	if (IS_ERR(ism))
		return PTR_ERR(ism);

	smcd = smcd_alloc_dev(&vdev->dev, dev_name(&vdev->dev),
			      &virtio_ism_smc_ops, DMB_NUM);
	if (!smcd) {
		rc = -EINVAL;
		goto err;
	}
	smcd->shmem = 1;
	smcd->priv = ism;
	smcd->local_gid = ism->gid;
	rc = smcd_register_dev(smcd);
	if (rc)
		goto free_smcd_device;

	ism->priv = smcd;
	ism->callback = virtio_ism_smc_interrupt_handler;

	return 0;

free_smcd_device:
	smcd_free_dev(smcd);
err:
	virtio_ism_dev_free(ism);

	return rc;
}

static void virtio_ism_smc_remove(struct virtio_device *vdev)
{
	struct virtio_ism *ism = vdev->priv;

	smcd_free_dev(ism->priv);

	virtio_ism_dev_free(ism);
}

static unsigned int virtio_ism_features[] = {
	VIRTIO_ISM_F_EVENT_IRQ
};

static const struct virtio_device_id virtio_ism_id_table[] = {
	{ VIRTIO_ID_ISM, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_ism_smc_driver = {
	.feature_table = virtio_ism_features,
	.feature_table_size = ARRAY_SIZE(virtio_ism_features),
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.id_table = virtio_ism_id_table,
	.probe = virtio_ism_smc_probe,
	.remove = virtio_ism_smc_remove,
};

module_virtio_driver(virtio_ism_smc_driver);
MODULE_DEVICE_TABLE(virtio, virtio_ism_id_table);
MODULE_AUTHOR("Tony Lu <tonylu@linux.alibaba.com>");
MODULE_DESCRIPTION("SMC virtio-ism adapter driver");
MODULE_LICENSE("Dual BSD/GPL");
