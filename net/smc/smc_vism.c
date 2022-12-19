// SPDX-License-Identifier: GPL-2.0
/* Shared Memory Communications Direct over ISM devices (SMC-D)
 *
 * Functions for virtio-ism device.
 *
 */

#define KMSG_COMPONENT "smc"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ism.h>
#include <linux/interrupt.h>
#include <net/smc.h>

#include "smc_vism.h"

static struct smc_vism_systemeid SMC_VISM_SYSTEM_EID = {
	.seid_string = "VIRTIO-ISM-SMC-SEID1",
	.serial_number = "0000",
	.type = "0000",
};

static int smc_vism_interrupt_handler(struct virtio_ism *ism, void *p,
				      void *notify_data)
{
	struct smcd_dmb *dmb = notify_data;

	smcd_handle_irq_dmb(dmb->dev, dmb);
	return 0;
}

static int smc_vism_notify_dmb(struct smcd_dev *smcd, struct smcd_dmb *dmb)
{
	struct virtio_ism *ism = smcd->priv;

	ism->ops->kick(ism, dmb->cpu_addr);
	return 0;
}

static int smc_vism_query_rgid(struct smcd_dev *smcd, u64 peer_rgid,
			       u32 vid_valid, u32 vid)
{
	struct virtio_ism *ism = smcd->priv;

	return ism->gid;
}

static int smc_vism_alloc_dmb(struct smcd_dev *smcd, struct smcd_dmb *dmb)
{
	struct virtio_ism *ism = smcd->priv;

	/* virtio-ism current PoC only returns fixed size buffer */
	dmb->dmb_len = SMC_VISM_DMB_SIZE;
	dmb->cpu_addr = ism->ops->alloc(ism, &dmb->dmb_tok, dmb->dmb_len,
					smc_vism_interrupt_handler, dmb);
	if (IS_ERR(dmb->cpu_addr))
		return PTR_ERR(dmb->cpu_addr);

	dmb->dev = smcd;
	return 0;
}

static int smc_vism_attach_dmb(struct smcd_dev *smcd, struct smcd_dmb *dmb)
{
	struct virtio_ism *ism = smcd->priv;

	dmb->cpu_addr = ism->ops->attach(ism, dmb->dmb_tok,
					 (u64 *)&dmb->dmb_len,
					 smc_vism_interrupt_handler, dmb);
	if (IS_ERR(dmb->cpu_addr))
		return PTR_ERR(dmb->cpu_addr);

	dmb->dev = smcd;
	return 0;
}

static int smc_vism_detach_dmb(struct smcd_dev *smcd, struct smcd_dmb *dmb)
{
	struct virtio_ism *ism = smcd->priv;

	ism->ops->detach(ism, dmb->dmb_tok);
	return 0;
}

static int smc_vism_free_dmb(struct smcd_dev *smcd, struct smcd_dmb *dmb)
{
	struct virtio_ism *ism = smcd->priv;

	ism->ops->detach(ism, dmb->dmb_tok);
	return 0;
}

static int smc_vism_add_vlan_id(struct smcd_dev *smcd, u64 vlan_id)
{
	pr_warn_ratelimited("add vlan id in virtio-ism is not implemented\n");
	return 0;
}

static int smc_vism_del_vlan_id(struct smcd_dev *smcd, u64 vlan_id)
{
	pr_warn_ratelimited("del vlan id in virtio-ism is not implemented\n");
	return 0;
}

static int smc_vism_signal_ieq(struct smcd_dev *smcd, u64 rgid,
			       u32 trigger_irq, u32 event_code, u64 info)
{
	pr_warn_ratelimited("signal ieq in virtio-ism is not implemented\n");
	return 0;
}

static u8 *smc_vism_get_system_eid(void)
{
	return &SMC_VISM_SYSTEM_EID.seid_string[0];
}

static u16 smc_vism_get_chid(struct smcd_dev *smcd)
{
	pr_warn_ratelimited("get chid in virtio-ism is not implemented\n");
	return 0;
}

static const struct smcd_ops smc_vism_ops = {
	.query_remote_gid = smc_vism_query_rgid,
	.alloc_dmb = smc_vism_alloc_dmb,
	.free_dmb = smc_vism_free_dmb,
	.attach_dmb = smc_vism_attach_dmb,
	.detach_dmb = smc_vism_detach_dmb,
	.notify_dmb = smc_vism_notify_dmb,
	.add_vlan_id = smc_vism_add_vlan_id,
	.del_vlan_id = smc_vism_del_vlan_id,
	.signal_event = smc_vism_signal_ieq,
	.get_system_eid = smc_vism_get_system_eid,
	.get_chid = smc_vism_get_chid,
};

static int smc_vism_probe(struct virtio_ism *ism)
{
	struct smcd_dev *smcd;
	int rc;

	smcd = smcd_alloc_dev(&ism->vdev->dev, dev_name(&ism->vdev->dev),
			      &smc_vism_ops, SMC_VISM_DMB_NUM);
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

	// TODO: add ism device to smcd-ism tables
	return 0;

free_smcd_device:
	smcd_free_dev(smcd);

err:
	return rc;
}

static void smc_vism_remove(struct virtio_ism *ism)
{
	// TODO: match smcd from smcd-ism tables
	/** smcd_unregister_dev(smcd); */
	/** smcd_free_dev(smcd); */
	pr_warn_ratelimited("vism remove is not implemented\n");
}

static int smc_vism_event_handler(struct notifier_block *this,
				  unsigned long event, void *ptr)
{
	struct virtio_ism_notifier_info *info = ptr;
	struct virtio_ism *event_dev = info->ism;

	switch (event) {
	case VIRTIO_ISM_NOTIFIER_EVENT_REMOVE:
		smc_vism_remove(event_dev);
		return NOTIFY_OK;
	case VIRTIO_ISM_NOTIFIER_EVENT_PROBE:
		smc_vism_probe(event_dev);
		return NOTIFY_OK;
	}

	return NOTIFY_DONE;
}

static struct notifier_block smc_vism_notifier = {
	.notifier_call = smc_vism_event_handler
};

int __init smc_vism_init(void)
{
	return virtio_ism_register_notifier(&smc_vism_notifier);
}

void smc_vism_exit(void)
{
	// TODO: remove all virtio ism devices
	virtio_ism_unregister_notifier(&smc_vism_notifier);
}
