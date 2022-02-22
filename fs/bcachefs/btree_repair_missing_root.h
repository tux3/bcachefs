/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BTREE_REPAIR_MISING_ROOT_H
#define _BCACHEFS_BTREE_REPAIR_MISING_ROOT_H

int bch2_repair_missing_btree_root(struct bch_fs *, enum btree_id);
void bch2_find_btree_nodes_exit(struct find_btree_nodes *);

#endif /* _BCACHEFS_BTREE_REPAIR_MISING_ROOT_H */
