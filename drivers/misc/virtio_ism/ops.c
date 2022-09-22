// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright Alibaba Group. 2022
 *
 * Author(s): Xuan Zhuo <xuanzhuo@linux.alibaba.com>
 */

#include "ism.h"

/* Since one interrupt needs to manage multiple regions, we have to add
 * proxy between regions and interrupt. */
struct virtio_ism_irq_ctx {
	struct list_head node;
	struct list_head regions;

	spinlock_t lock;

	int num;

	bool has_irq;
};

struct virtio_ism_region {
	struct list_head node;
	struct rb_node rb_node;

	struct virtio_ism *ism;
	struct virtio_ism_irq_ctx *ctx;

	u64 offset;
	u64 size;
	u64 token;

	void *vaddr;
	void *notify_data;
	virtio_ism_callback callback;

	__le64 _token;
	__le64 num;
	struct virtio_ism_area area[];
};

#define rb_to_region(n) rb_entry((n), struct virtio_ism_region, rb_node)

static bool virtio_ism_mod_inc_ref(struct virtio_ism *ism)
{
	if (!ism->ref && !try_module_get(THIS_MODULE))
		return false;

	++ism->ref;

	return true;
}

static void virtio_ism_mod_dec_ref(struct virtio_ism *ism)
{
	--ism->ref;

	if (!ism->ref)
		module_put(THIS_MODULE);
}

static inline bool __region_less(struct rb_node *a, const struct rb_node *b)
{
	struct virtio_ism_region *r1, *r2;

	r1 = rb_entry(a, struct virtio_ism_region, rb_node);
	r2 = rb_entry(b, struct virtio_ism_region, rb_node);

	return r1->token < r2->token;
}

static inline int __region_cmp(const void *key, const struct rb_node *a)
{
	struct virtio_ism_region *r;
	u64 token = (u64)key;

	r = rb_entry(a, struct virtio_ism_region, rb_node);

	if (token < r->token)
		return -1;

	if (token > r->token)
		return 1;

	return 0;
}

static irqreturn_t ism_interrupt(int irq, void *_)
{
	struct virtio_ism_irq_ctx *ctx = _;
	struct virtio_ism_region *r;
	struct virtio_ism *ism;
	unsigned long flags;

	spin_lock_irqsave(&ctx->lock, flags);
	list_for_each_entry(r, &ctx->regions, node) {
		if (r->callback) {
			ism = r->ism;
			r->callback(ism, ism->shm_p + r->offset, r->notify_data);
		}
	}
	spin_unlock_irqrestore(&ctx->lock, flags);

	return IRQ_HANDLED;
}

static void virtio_ism_irq_ctx_unbind(struct virtio_ism_region *r)
{
	struct virtio_ism_irq_ctx *ctx;
	struct list_head *next_head;
	unsigned long flags;

	ctx = r->ctx;

	/* delete region from irq handler */
	spin_lock_irqsave(&ctx->lock, flags);
	list_del(&r->node);
	--ctx->num;
	spin_unlock_irqrestore(&ctx->lock, flags);

	next_head = r->ism->irq_ctx_heads + ctx->num;

	if (ctx->num < r->ism->irq_ctx_min_index)
		r->ism->irq_ctx_min_index = ctx->num;

	/* move high index list to low index - 1 list */
	list_del(&ctx->node);
	list_add(&ctx->node, next_head);
}

static int irq_ctx_2_vector(struct virtio_ism *ism , struct virtio_ism_irq_ctx *ctx)
{
	return ctx - ism->irq_ctx + ism->vector_start;
}

static void virtio_ism_irq_ctx_bind(struct virtio_ism_irq_ctx *ctx,
				    struct virtio_ism_region *r)
{
	struct list_head *next_head;
	unsigned long flags;

	spin_lock_irqsave(&ctx->lock, flags);
	list_add(&r->node, &ctx->regions);
	++ctx->num;
	spin_unlock_irqrestore(&ctx->lock, flags);

	next_head = r->ism->irq_ctx_heads + ctx->num;

	/* move low index list to high index + 1 list */
	list_del(&ctx->node);
	list_add(&ctx->node, next_head);

	r->ctx = ctx;
}

static int virtio_ism_irq_ctx_heads_expand(struct virtio_ism *ism)
{
	struct list_head *heads, *head;
	int n, i;

	n = ism->irq_ctx_heads_n + 5;

	heads = kcalloc(n, sizeof(*ism->irq_ctx_heads), GFP_KERNEL);
	if (!heads)
		return -ENOMEM;

	for (i = 0; i < n; ++i)
		INIT_LIST_HEAD(heads + i);

	for (i = 0; i < ism->irq_ctx_heads_n; ++i) {
		head = ism->irq_ctx_heads + i;

		if (list_empty(head))
			continue;

		list_replace(head, heads + i);
	}

	kfree(ism->irq_ctx_heads);

	ism->irq_ctx_heads = heads;
	ism->irq_ctx_heads_n = n;

	return 0;
}

static struct virtio_ism_irq_ctx *virtio_ism_irq_ctx_find(struct virtio_ism *ism)
{
	struct virtio_ism_irq_ctx *ctx;
	int err, vector, irq, i;
	struct list_head *head;

	for (i = ism->irq_ctx_min_index; i < ism->irq_ctx_heads_n; ++i)
	{
		head = ism->irq_ctx_heads + i;

		ctx = list_first_entry_or_null(head, struct virtio_ism_irq_ctx,
					       node);
		if (!ctx) {
			if (i == ism->irq_ctx_min_index)
				ism->irq_ctx_min_index = i;
			continue;
		}

		if (ctx->has_irq)
			goto found;

		vector = irq_ctx_2_vector(ism, ctx);
		irq = virtio_vector_to_irq(ism->vdev, vector);
		err = request_irq(irq, ism_interrupt, 0, "ism", ctx);
		if (err)
			continue;

		ctx->has_irq = true;
		++ism->stats.irq_inuse;
		goto found;
	}

	dev_warn(&ism->vdev->dev,
		 "No irq resource available. vectors: %d\n.", ism->vector_num);

	return ERR_PTR(-ENOENT);

found:
	if (i == ism->irq_ctx_heads_n - 1) {
		err = virtio_ism_irq_ctx_heads_expand(ism);
		if (err)
			return ERR_PTR(err);
	}

	return ctx;
}

static struct virtio_ism_region *virtio_ism_region_get(struct virtio_ism *ism, u64 token)
{
	struct virtio_ism_region *r;
	struct rb_node *n;

	n = rb_find((void *)token, &ism->rbtree, __region_cmp);
	if (!n)
		return NULL;

	r = rb_to_region(n);
	return r;
}

static void *virtio_ism_region_init(struct virtio_ism *ism,
				    struct virtio_ism_region *r,
				    u64 token,
				    virtio_ism_callback callback,
				    void *notify_data)
{
	struct virtio_ism_irq_ctx *ctx;
	int vector, err, n, i;
	struct page **pgs;
	void *vaddr;
	u64 off, offset;

	r->size = 0;
	for (i = 0; i < le64_to_cpu(r->num); ++i)
		r->size += le64_to_cpu(r->area[i].size);

	r->offset = le64_to_cpu(r->area[0].offset);

	n = r->size >> PAGE_SHIFT;

	pgs = kcalloc(n, sizeof(*pgs), GFP_KERNEL);
	if (!pgs)
		return ERR_PTR(-ENOMEM);

	n = 0;
	for (i = 0; i < le64_to_cpu(r->num); ++i) {
		offset = le64_to_cpu(r->area[i].offset);
		for (off = 0; off < le64_to_cpu(r->area[i].size); off += PAGE_SIZE)
			pgs[n++] = virt_to_page(ism->shm_p + offset + off);
	}

	vaddr = vmap(pgs, n, VM_READ, PAGE_KERNEL);

	kfree(pgs);

	if (!vaddr)
		return ERR_PTR(-ENOMEM);

	r->ism         = ism;
	r->token       = token;
	r->offset      = offset;
	r->callback    = callback;
	r->notify_data = notify_data;
	r->vaddr       = vaddr;

	ctx = virtio_ism_irq_ctx_find(ism);
	if (IS_ERR(ctx)) {
		err = PTR_ERR(ctx);
		goto err_ctx;
	}

	virtio_ism_irq_ctx_bind(ctx, r);

	vector = irq_ctx_2_vector(ism, ctx);
	err = dev_inform_vector(ism, token, vector);
	if (err)
		goto err;

	++ism->stats.region_active;
	rb_add(&r->rb_node, &ism->rbtree, __region_less);
	return vaddr;

err:
	virtio_ism_irq_ctx_unbind(r);
err_ctx:
	vfree(vaddr);
	return ERR_PTR(err);
}

static void virtio_ism_kick(struct virtio_ism *ism, void *addr)
{
	u64 pfn, offset, phy;

	pfn = vmalloc_to_pfn(addr);

	phy = pfn << PAGE_SHIFT;

	if (phy < ism->shm_reg.addr || phy >= (ism->shm_reg.addr + ism->shm_reg.len)) {
		dev_warn(&ism->vdev->dev, "virtio ism kick: invalid addr %p\n.", addr);
		return;
	}

	offset = phy - ism->shm_reg.addr;

	dev_kick(ism , offset);
}

static void virtio_ism_detach(struct virtio_ism *ism, u64 token)
{
	struct virtio_ism_region *r;

	mutex_lock(&ism->mutex);

	r = virtio_ism_region_get(ism, token);
	if (!r)
		goto err;

	rb_erase(&r->rb_node, &ism->rbtree);
	virtio_ism_irq_ctx_unbind(r);
	vfree(r->vaddr);
	kfree(r);

	dev_detach(ism, token);
	virtio_ism_mod_dec_ref(ism);

err:
	mutex_unlock(&ism->mutex);
}

static void *__alloc(struct virtio_ism *ism, bool alloc, u64 *token, u64 *len,
		     virtio_ism_callback cb, void *notify_data)
{
	struct virtio_ism_region *r;
	int chunk_n, err;
	u32 size;
	void *p, *reply;

	mutex_lock(&ism->mutex);

	if (!virtio_ism_mod_inc_ref(ism)) {
		err = -ENODEV;
		goto err_ref;
	}

	chunk_n = (*len >> ism->chunk_size_shift) + 1;
retry:
	size = sizeof(struct virtio_ism_region) + sizeof(struct virtio_ism_area) * chunk_n;

	r = kmalloc(size, GFP_KERNEL);
	if (!r) {
		err = -ENOMEM;
		goto err_ref;
	}

	if (alloc) {
		reply = (void *)&r->_token;
		size -= (char *)reply - (char *)r;
		err = dev_alloc(ism, token, reply, *len, size);

	} else {
		reply = (void *)&r->num;
		size -= (char *)reply - (char *)r;
		err = dev_attach(ism, *token, reply, size);
	}

	if (err == -VIRTIO_ISM_E2BIG) {
		chunk_n = le64_to_cpu(r->num);
		kfree(r);
		goto retry;
	}

	if (err)
		goto err_cmd;

	p = virtio_ism_region_init(ism, r, *token, cb, notify_data);
	if (IS_ERR(p))
		goto err_region;

	if (!alloc)
		*len = r->size;

	mutex_unlock(&ism->mutex);

	return p;

err_region:
	dev_detach(ism, *token);

err_cmd:
	virtio_ism_mod_dec_ref(ism);
	kfree(r);

err_ref:
	mutex_unlock(&ism->mutex);
	return ERR_PTR(err);
}

static void *virtio_ism_attach(struct virtio_ism *ism, u64 token, u64 *len,
			       virtio_ism_callback cb,
			       void *notify_data)
{
	*len = ism->chunk_size * 10;
	return __alloc(ism, false, &token, len, cb, notify_data);
}

static void *virtio_ism_alloc(struct virtio_ism *ism, u64 *token, u64 len,
			      virtio_ism_callback cb,
			      void *notify_data)
{
	return __alloc(ism, true, token, &len, cb, notify_data);
}

static u64 virtio_ism_get_gid(struct virtio_ism *ism)
{
	return ism->gid;
}

static u64 virtio_ism_get_devid(struct virtio_ism *ism)
{
	return ism->devid;
}

struct virtio_ism_ops vism_ops = {
	.get_gid = virtio_ism_get_gid,
	.get_devid = virtio_ism_get_devid,
	.alloc = virtio_ism_alloc,
	.attach = virtio_ism_attach,
	.detach = virtio_ism_detach,
	.kick = virtio_ism_kick,
};

int virtio_ism_ops_init(struct virtio_ism *ism)
{
	struct virtio_ism_irq_ctx *ctx;
	int vector_n, i, n;

	vector_n = ism->vector_num;

	ism->irq_ctx = kcalloc(vector_n, sizeof(*ism->irq_ctx), GFP_KERNEL);
	if (!ism->irq_ctx)
		return -ENOMEM;

	n = ism->region_num / ism->vector_num + 1;
	if (ism->region_num % ism->vector_num)
		n += 1;

	ism->irq_ctx_heads = kcalloc(n, sizeof(*ism->irq_ctx_heads), GFP_KERNEL);
	ism->irq_ctx_heads_n = n;
	ism->irq_ctx_min_index = 0;

	for (i = 0; i < n; ++i)
		INIT_LIST_HEAD(ism->irq_ctx_heads + i);

	for (i = 0; i < vector_n; ++i) {
		ctx = ism->irq_ctx + i;

		INIT_LIST_HEAD(&ctx->regions);
		spin_lock_init(&ctx->lock);
		list_add_tail(&ctx->node, ism->irq_ctx_heads);
	}

	return 0;
}

void virtio_ism_ops_exit(struct virtio_ism *ism)
{
	struct virtio_ism_irq_ctx *ctx;
	int irq, i, vector;

	for (i = 0; i < ism->vector_num; ++i) {
		ctx = ism->irq_ctx + i;

		if (ctx->has_irq) {
			vector = ctx - ism->irq_ctx + ism->vector_start;
			irq = virtio_vector_to_irq(ism->vdev,  vector);
			irq_set_affinity_hint(irq, NULL);
			free_irq(irq, ctx);
		}
	}

	kfree(ism->irq_ctx);
	kfree(ism->irq_ctx_heads);
}

MODULE_AUTHOR("Xuan Zhuo <xuanzhuo@linux.alibaba.com>");
MODULE_DESCRIPTION("Virtio-ISM driver ops");
MODULE_LICENSE("GPL");
