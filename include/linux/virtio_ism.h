#ifndef _LINUX_VIRTIO_ISM_H
#define _LINUX_VIRTIO_ISM_H

#include <uapi/linux/virtio_ism.h>
#include <linux/miscdevice.h>

struct virtio_ism_config {
	__le64 gid;
	__le64 devid;
	__le64 chunk_size;
	__le64 notify_size;
};

#define   VIRTIO_ISM_EVENT_UPDATE (1 << 0)
#define   VIRTIO_ISM_EVENT_ATTACH (1 << 1)
#define   VIRTIO_ISM_EVENT_DETACH (1 << 2)

struct virtio_ism_event_update {
	__le64 ev_type;
	__le64 offset;
	__le64 devid;
};

struct virtio_ism_event_attach_detach {
	__le64 ev_type;
	__le64 offset;
	__le64 devid;
	__le64 peers;
};

enum virtio_ism_shm_id {
	VIRTIO_ISM_SHM_ID_UNDEFINED = 0,
	VIRTIO_ISM_SHM_ID_REGIONS   = 1,
	VIRTIO_ISM_SHM_ID_NOTIFY    = 2,
};

/* ack values */
#define VIRTIO_ISM_OK      0
#define VIRTIO_ISM_ERR     255

#define VIRTIO_ISM_ENOENT  2
#define VIRTIO_ISM_E2BIG   7
#define VIRTIO_ISM_ENOMEM  12
#define VIRTIO_ISM_ENOSPEC 28

#define VIRTIO_ISM_PERM_EATTACH 100
#define VIRTIO_ISM_PERM_EREAD   101
#define VIRTIO_ISM_PERM_EWRITE  102

struct virtio_ism_ctrl_alloc {
	__le64 size;
};

struct virtio_ism_area {
	__le64 offset;
	__le64 size;
};

struct virtio_ism_ctrl_alloc_reply {
	__le64 token;
	__le64 num;
	struct virtio_ism_area area[];
};

#define VIRTIO_ISM_CTRL_ALLOC  0
	#define VIRTIO_ISM_CTRL_ALLOC_REGION 0

struct virtio_ism_ctrl_attach {
	__le64 token;
	__le32 rw_perm;
};

struct virtio_ism_ctrl_attach_reply {
	__le64 num;
	struct virtio_ism_area area[];
};


#define VIRTIO_ISM_CTRL_ATTACH  1
	#define VIRTIO_ISM_CTRL_ATTACH_REGION 0

struct virtio_ism_ctrl_detach {
	__le64 token;
};

#define VIRTIO_ISM_CTRL_DETACH  2
	#define VIRTIO_ISM_CTRL_DETACH_REGION 0


struct virtio_ism_ctrl_grant_default {
	__le64 token;
	__le64 permissions;
};

struct virtio_ism_ctrl_grant {
	__le64 token;
	__le64 permissions;
	__le64 peer_devid;
};

#define VIRTIO_ISM_CTRL_GRANT  3
	#define VIRTIO_ISM_CTRL_GRANT_SET_DEFAULT    0
	#define VIRTIO_ISM_CTRL_GRANT_SET_FOR_DEVICE 1

#define VIRTIO_ISM_PERM_READ       (1 << 0)
#define VIRTIO_ISM_PERM_WRITE      (1 << 1)

#define VIRTIO_ISM_PERM_ATTACH     (1 << 2)

#define VIRTIO_ISM_PERM_MANAGE     (1 << 3)
#define VIRTIO_ISM_PERM_CLEAN_DEFAULT     (1 << 4)


struct virtio_ism_ctrl_irq_vector {
	__le64 token;
	__le64 vector;
};

#define VIRTIO_ISM_CTRL_EVENT_VECTOR  4
	#define VIRTIO_ISM_CTRL_EVENT_VECTOR_SET 0

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

	struct virtio_ism_ctrl_detach detach_out;


	struct virtio_ism_ctrl_irq_vector vector_out;
};

struct virtio_ism;

typedef int (*virtio_ism_callback)(struct virtio_ism *ism, void *p, void *data);

struct virtio_ism_ops {
	u64 (*get_gid)(struct virtio_ism *ism);
	u64 (*get_devid)(struct virtio_ism *ism);
	void *(*alloc)(struct virtio_ism *ism, u64 *token,
		       u64 len, virtio_ism_callback cb, void *notify_data);
	void *(*attach)(struct virtio_ism *ism, u64 token,
			u64 *len, virtio_ism_callback cb, void *notify_data);
	void (*detach)(struct virtio_ism *ism, u64 token);
	void (*kick)(struct virtio_ism *ism, void *);
};

struct virtio_ism {
	struct list_head node;

	struct virtio_device *vdev;
	struct miscdevice miscdev;
	char devname[16];

	u64 gid;
	u64 devid;
	u64 chunk_size;
	u32 chunk_size_shift;
	u64 region_num;
	u64 notify_size;
	u64 ref;

	struct mutex mutex;

	struct control_buf *ctrl;

	struct virtqueue *cvq;

	struct virtio_shm_region notify_reg;
	struct virtio_shm_region shm_reg;

	void *shm_p;
	void __iomem *notify_p;

	u32 vector_start;
	u32 vector_num;

	struct rb_root rbtree;
	struct list_head *irq_ctx_heads;
	u32 irq_ctx_heads_n;
	u32 irq_ctx_min_index;

	const struct virtio_ism_ops *ops;
	struct virtio_ism_stat stats;
	struct virtio_ism_irq_ctx *irq_ctx;

};

enum {
	VIRTIO_ISM_NOTIFIER_EVENT_PROBE,
	VIRTIO_ISM_NOTIFIER_EVENT_REMOVE,
};

struct virtio_ism_notifier_info {
	struct virtio_ism *ism;
};

int virtio_ism_unregister_notifier(struct notifier_block *nb);
int virtio_ism_register_notifier(struct notifier_block *nb);
#endif /* _LINUX_VIRTIO_ISM_H */
