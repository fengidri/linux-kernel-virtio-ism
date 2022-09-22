#ifndef  __VIRTIO_ISM_H__
#define __VIRTIO_ISM_H__

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
	void *notify_data;
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

	void *priv;

	int (*callback)(struct virtio_ism *ism, void *p, void *notify_data);
};

struct virtio_ism *virtio_ism_dev_alloc(struct virtio_device *vdev);
void virtio_ism_dev_free(struct virtio_ism *ism);

void *virtio_ism_attach(struct virtio_ism *ism, u64 token, u32 len, void *notify_data);
void *virtio_ism_alloc(struct virtio_ism *ism, u64 *token, u32 len, void *notify_data);
void virtio_ism_notify(struct virtio_ism *ism, void *p);

#endif


