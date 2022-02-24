// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "btree_cache.h"
#include "btree_io.h"
#include "btree_repair_missing_root.h"
#include "btree_update_interior.h"
#include "buckets.h"
#include "error.h"
#include "io.h"
#include "journal_io.h"
#include "recovery.h"

#include <linux/kthread.h>
#include <linux/sort.h>

struct find_btree_nodes_worker {
	struct closure		*cl;
	struct find_btree_nodes	*f;
	struct bch_dev		*ca;
	u64			bucket_start;
	u64			bucket_end;
};

static void found_btree_node_to_text(struct printbuf *out, const struct found_btree_node *n)
{
	pr_buf(out, "l=%u seq=%u cookie=%llx ", n->level, n->seq, n->cookie);
	bch2_bpos_to_text(out, n->min_key);
	pr_buf(out, "-");
	bch2_bpos_to_text(out, n->max_key);

	if (n->range_updated)
		pr_buf(out, " range updated");
	if (n->overwritten)
		pr_buf(out, " overwritten");
}

static int found_btree_node_cmp_cookie(const void *_l, const void *_r)
{
	const struct found_btree_node *l = _l;
	const struct found_btree_node *r = _r;

	return  cmp_int(l->btree_id,	r->btree_id) ?:
		cmp_int(l->level,	r->level) ?:
		cmp_int(l->cookie,	r->cookie);
}

static int found_btree_node_cmp_pos(const void *_l, const void *_r)
{
	const struct found_btree_node *l = _l;
	const struct found_btree_node *r = _r;

	return  cmp_int(l->btree_id,	r->btree_id) ?:
	       -cmp_int(l->level,	r->level) ?:
		bpos_cmp(l->min_key,	r->min_key) ?:
	       -cmp_int(l->seq,		r->seq);
}

static void try_read_btree_node(struct find_btree_nodes *f, struct bch_dev *ca,
				struct bio *bio, struct btree_node *bn, u64 offset)
{
	struct bch_fs *c = container_of(f, struct bch_fs, found_btree_nodes);

	bio_reset(bio);
	bio->bi_opf		= REQ_OP_READ;
	bio->bi_iter.bi_sector	= offset;
	bch2_bio_map(bio, bn, PAGE_SIZE);
	bio_set_dev(bio, ca->disk_sb.bdev);

	submit_bio_wait(bio);
	if (bch2_dev_io_err_on(bio->bi_status, ca,
			       "IO error in try_read_btree_node() at %llu: %s",
			       offset, bch2_blk_status_to_str(bio->bi_status)))
		return;

	if (le64_to_cpu(bn->magic) != bset_magic(c))
		return;

	if (!((1U << BTREE_NODE_ID(bn)) & f->btree_ids))
		return;

	mutex_lock(&f->lock);

	if (BSET_BIG_ENDIAN(&bn->keys) != CPU_BIG_ENDIAN) {
		bch_err(c, "try_read_btree_node() can't handle endian conversion");
		f->ret = -EINVAL;
		goto out;
	}

	if (f->nr == f->size) {
		size_t new_size = max_t(size_t, f->size * 2, 8);
		struct found_btree_node *d =
			krealloc(f->d, new_size * sizeof(*d), GFP_KERNEL);

		if (!d) {
			bch_err(c, "memory allocation failure in try_read_btree_node()");
			f->ret = -ENOMEM;
			goto out;
		}

		f->size	= new_size;
		f->d	= d;
	}

	rcu_read_lock();
	f->d[f->nr++] = (struct found_btree_node) {
		.btree_id	= BTREE_NODE_ID(bn),
		.level		= BTREE_NODE_LEVEL(bn),
		.seq		= BTREE_NODE_SEQ(bn),
		.cookie		= le64_to_cpu(bn->keys.seq),
		.min_key	= bn->min_key,
		.max_key	= bn->max_key,
		.nr_ptrs	= 1,
		.ptrs		= { (struct bch_extent_ptr) {
			.type	= 1 << BCH_EXTENT_ENTRY_ptr,
			.offset	= offset,
			.dev	= ca->dev_idx,
			.gen	= *bucket_gen(ca, sector_to_bucket(ca, offset)),
		},
		},
	};
	rcu_read_unlock();
out:
	mutex_unlock(&f->lock);
}

static int read_btree_nodes_worker(void *p)
{
	struct find_btree_nodes_worker *w = p;
	struct bch_fs *c = container_of(w->f, struct bch_fs, found_btree_nodes);
	struct bch_dev *ca = w->ca;
	void *buf = (void *) __get_free_page(GFP_KERNEL);
	struct bio *bio = bio_alloc(GFP_KERNEL, 1);
	u64 bucket;
	unsigned bucket_offset;

	if (!buf || !bio) {
		bch_err(c, "read_btree_nodes_worker: error allocating bio/buf");
		w->f->ret = -ENOMEM;
		goto err;
	}

	for (bucket = w->bucket_start; bucket < w->bucket_end; bucket++)
		for (bucket_offset = 0;
		     bucket_offset + btree_sectors(c) <= ca->mi.bucket_size;
		     bucket_offset += btree_sectors(c))
			try_read_btree_node(w->f, ca, bio, buf,
					    bucket * ca->mi.bucket_size + bucket_offset);
err:
	bio_put(bio);
	free_page((unsigned long) buf);
	percpu_ref_get(&ca->io_ref);
	closure_put(w->cl);
	kfree(w);
	return 0;
}

static int read_btree_nodes(struct find_btree_nodes *f)
{
	struct bch_fs *c = container_of(f, struct bch_fs, found_btree_nodes);
	struct bch_dev *ca;
	struct closure cl;
	unsigned i;
	int ret = 0;

	closure_init_stack(&cl);

	for_each_online_member(ca, c, i) {
		struct find_btree_nodes_worker *w = kmalloc(sizeof(*w), GFP_KERNEL);
		struct task_struct *t;

		if (!w) {
			percpu_ref_put(&ca->io_ref);
			ret = -ENOMEM;
			goto err;
		}

		percpu_ref_get(&ca->io_ref);
		closure_get(&cl);
		w->cl		= &cl;
		w->f		= f;
		w->ca		= ca;

		w->bucket_start	= ca->mi.first_bucket;
		w->bucket_end	= ca->mi.nbuckets;
		t = kthread_run(read_btree_nodes_worker, w, "read_btree_nodes/%s", ca->name);
		ret = IS_ERR_OR_NULL(t);
		if (ret) {
			percpu_ref_put(&ca->io_ref);
			closure_put(&cl);
			f->ret = ret;
			bch_err(c, "error starting kthread: %i", ret);
			break;
		}
	}
err:
	closure_sync(&cl);
	return f->ret ?: ret;
}

static void bubble_up(struct found_btree_node *n, struct found_btree_node *end)
{
	while (n + 1 < end &&
	       found_btree_node_cmp_pos(n, n + 1) > 0) {
		swap(n[0], n[1]);
		n++;
	}
}

static int handle_overwrites(struct bch_fs *c,
			     struct found_btree_node *start,
			     struct found_btree_node *end)
{
	struct found_btree_node *n;
again:
	for (n = start + 1;
	     n < end &&
	     n->btree_id	== start->btree_id &&
	     n->level		== start->level &&
	     bpos_cmp(start->max_key, n->min_key) > 0;
	     n++)  {
		if (start->seq > n->seq) {
			n->range_updated = true;

			if (bpos_cmp(start->max_key, n->max_key) >= 0)
				n->overwritten = true;
			else {
				n->min_key = bpos_successor(start->max_key);
				bubble_up(n, end);
				goto again;
			}
		} else if (start->seq < n->seq) {
			BUG_ON(bpos_cmp(n->min_key, start->min_key) <= 0);

			start->range_updated = true;
			start->max_key = bpos_predecessor(n->min_key);
		} else {
			char buf[200];

			bch_err(c, "overlapping btree nodes with same seq! halting");
			found_btree_node_to_text(&PBUF(buf), start);
			bch_err(c, "%s", buf);
			found_btree_node_to_text(&PBUF(buf), n);
			bch_err(c, "%s", buf);
			return -1;
		}
	}

	return 0;
}

static int bch2_scan_devices_for_btree_nodes(struct bch_fs *c)
{
	struct find_btree_nodes *f = &c->found_btree_nodes;
	struct found_btree_node *d = NULL, *i;
	size_t src, dst;
	char buf[200];
	int ret = 0;

	if (f->d)
		return 0;

	mutex_init(&f->lock);
	f->btree_ids = ~0;

	bch_info(c, "scanning devices for btree nodes");
	ret = read_btree_nodes(f);
	if (ret)
		return ret;

	bch_info(c, "done scanning devices for btree nodes");

	if (!f->nr) {
		bch_err(c, "no btree nodes found");
		ret = -EINVAL;
		goto err;
	}

	sort(f->d, f->nr, sizeof(f->d[0]), found_btree_node_cmp_cookie, NULL);

	d = kmalloc(sizeof(*d) * f->nr, GFP_KERNEL);
	if (!d) {
		bch_err(c, "memory allocation failure in bch2_scan_devices_for_btree_nodes()");
		ret = -ENOMEM;
		goto err;
	}

	for (src = 0, dst = 0;
	     src < f->nr; src++) {
		if (dst &&
		    d[dst - 1].cookie == f->d[src].cookie) {
			d[dst - 1].ptrs[d[dst - 1].nr_ptrs++] = f->d[src].ptrs[0];
		} else {
			d[dst++] = f->d[src];
		}
	}

	swap(f->d, d);
	f->nr = dst;

	sort(f->d, f->nr, sizeof(f->d[0]), found_btree_node_cmp_pos, NULL);

	bch_verbose(c, "Nodes found before overwrites:");
	for (i = f->d; i < f->d + f->nr; i++) {
		found_btree_node_to_text(&PBUF(buf), i);
		bch_verbose(c, "%s", buf);
	}

	for (src = 0, dst = 0;
	     src < f->nr; src++) {
		if (f->d[src].overwritten)
			continue;

		ret = handle_overwrites(c, f->d + src, f->d + f->nr);
		if (ret)
			goto err;

		BUG_ON(f->d[src].overwritten);
		d[dst++] = f->d[src];
	}

	swap(f->d, d);
	f->nr = dst;

	bch_verbose(c, "Nodes found after overwrites:");
	for (i = f->d; i < f->d + f->nr; i++) {
		found_btree_node_to_text(&PBUF(buf), i);
		bch_verbose(c, "%s", buf);
	}
err:
	kfree(d);
	return ret;
}

int bch2_repair_missing_btree_root(struct bch_fs *c, enum btree_id btree_id)
{
	struct find_btree_nodes *f = &c->found_btree_nodes;
	struct found_btree_node *start, *i;
	unsigned new_root_level;
	int ret;

	ret = bch2_scan_devices_for_btree_nodes(c);
	if (ret)
		return ret;

	for (start = f->d; start < f->d + f->nr; start++)
		if (start->btree_id >= btree_id)
			break;

	if (start->btree_id > btree_id) {
		bch_info(c, "no nodes found in btree %s", bch2_btree_ids[btree_id]);
		return 0;
	}

	bch2_btree_root_alloc(c, btree_id);

	c->btree_roots[btree_id].b->c.level = new_root_level = start->level + 1;

	for (i = start;
	     i < f->d + f->nr &&
	     i->btree_id	== start->btree_id &&
	     i->level		== start->level;
	     i++) {
		struct bkey_i_btree_ptr_v2 *bp;

		__BKEY_PADDED(k, BKEY_BTREE_PTR_VAL_U64s_MAX) tmp;

		bp = bkey_btree_ptr_v2_init(&tmp.k);
		set_bkey_val_u64s(&bp->k,
			sizeof(struct bch_btree_ptr_v2) / sizeof(u64) + i->nr_ptrs);
		bp->k.p			= i->max_key;
		bp->v.seq		= cpu_to_le64(i->cookie);
		bp->v.sectors_written	= 0;
		bp->v.flags		= 0;
		bp->v.min_key		= i->min_key;
		SET_BTREE_PTR_RANGE_UPDATED(&bp->v, i->range_updated);
		memcpy(bp->v.start, i->ptrs, sizeof(struct bch_extent_ptr) * i->nr_ptrs);

		ret = bch2_journal_key_insert(c, btree_id, new_root_level, &bp->k_i);
		if (ret)
			return ret;
	}

	return 0;
}

void bch2_find_btree_nodes_exit(struct find_btree_nodes *f)
{
	kfree(f->d);
	f->d = NULL;
}
