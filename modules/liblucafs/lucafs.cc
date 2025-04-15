extern "C" {
#define USE_C_INTERFACE 1
#include <osv/device.h>
#include <osv/prex.h>
#include <osv/vnode.h>
#include <osv/mount.h>
#include <osv/debug.h>
#include <osv/file.h>
#include <osv/vnode_attr.h>

void* alloc_contiguous_aligned(size_t size, size_t align);
void free_contiguous_aligned(void* p);
}

#include "lucafs.hh"
#include "tree.h"
#include <ext4_errno.h>
#include <ext4_dir.h>
#include <ext4_inode.h>
#include <ext4_fs.h>
#include <ext4_dir_idx.h>
#include <ext4_trans.h>

#include <cstdlib>
#include <time.h>
#include <cstddef>

#include <algorithm>
#include <stdio.h>



static int luca_bcache_lba_compare(struct luca_buf *a, struct luca_buf *b)
{
	 if (a->lba > b->lba)
		 return 1;
	 else if (a->lba < b->lba)
		 return -1;
	 return 0;
}

static int luca_bcache_lru_compare(struct luca_buf *a, struct luca_buf *b)
{
	if (a->lru_id > b->lru_id)
		return 1;
	else if (a->lru_id < b->lru_id)
		return -1;
	return 0;
}


RB_GENERATE_INTERNAL(luca_buf_lba, luca_buf, lba_node,
		     luca_bcache_lba_compare, static inline)
RB_GENERATE_INTERNAL(luca_buf_lru, luca_buf, lru_node,
		     luca_bcache_lru_compare, static inline)


/*superblock相关*/
int luca_sb_write(luca_blockdev_t *bdev, luca_sblock_t *s)
{
    if(s->features_compatible & LUCA_FRO_COM_METADATA_CSUM)
    {
        s->checksum = ext4_crc32c(EXT4_CRC32_INIT, s, offsetof(luca_sblock_t, checksum));
    }

	printf("写入超级块\n");
    return luca_block_writebytes(bdev, LUCA_SUPERBLOCK_OFFSET, s, LUCA_SUPERBLOCK_SIZE);
}









/*blockdev相关*/
int luca_block_writebytes(luca_blockdev_t *bdev, uint64_t off,
			  const void *buf, uint32_t len)
{
	uint64_t block_idx;
	uint32_t blen;
	uint32_t unalg;
	int r = EOK;
	//printf("写入数据\n");

	uint8_t *p = (uint8_t *)buf;

	ext4_assert(bdev && buf);

	if (!bdev->bdif->ph_refctr)
		return EIO;

	if (off + len > bdev->part_size)
		return EINVAL; /*Ups. Out of range operation*/

	block_idx = ((off + bdev->part_offset) / bdev->bdif->ph_bsize);
	//printf("写入数据2\n");

	/*OK lets deal with the first possible unaligned block*/
	unalg = (off & (bdev->bdif->ph_bsize - 1));
	if (unalg) {
		//printf("写入数据2.1\n");

		uint32_t wlen = (bdev->bdif->ph_bsize - unalg) > len
				    ? len
				    : (bdev->bdif->ph_bsize - unalg);
		

		// r = ext4_bdif_bread(bdev, bdev->bdif->ph_bbuf, block_idx, 1);
        // blockdev_bwrite(bdev, bdev->bdif->ph_bbuf, block_idx, 1);
		//printf("写入数据3\n");
		r = bdev->bdif->bread(bdev, bdev->bdif->ph_bbuf, block_idx, 1);
        bdev->bdif->bread_ctr++;
		if (r != EOK)
			return r;

		memcpy(bdev->bdif->ph_bbuf + unalg, p, wlen);
		//r = ext4_bdif_bwrite(bdev, bdev->bdif->ph_bbuf, block_idx, 1);
        // blockdev_bwrite(bdev, bdev->bdif->ph_bbuf, block_idx, 1);
		r = bdev->bdif->bwrite(bdev, bdev->bdif->ph_bbuf, block_idx, 1);
        bdev->bdif->bwrite_ctr++;
		if (r != EOK)
			return r;

		p += wlen;
		len -= wlen;
		block_idx++;
	}

	/*Aligned data*/
	blen = len / bdev->bdif->ph_bsize;
	if (blen != 0) {
		//printf("写入数据4\n");
		//r = ext4_bdif_bwrite(bdev, p, block_idx, blen);
        // blockdev_bwrite(bdev, p, block_idx, blen);
		r = bdev->bdif->bwrite(bdev, p, block_idx, blen);
        bdev->bdif->bwrite_ctr++;
		if (r != EOK)
			return r;


		p += bdev->bdif->ph_bsize * blen;
		len -= bdev->bdif->ph_bsize * blen;

		block_idx += blen;
	}

	/*Rest of the data*/
	if (len) {
		kprintf("剩余len:%d\n", len);
		//r = ext4_bdif_bread(bdev, bdev->bdif->ph_bbuf, block_idx, 1);
        // r = blockdev_bread(bdev, (void *)bdev->bdif->ph_bbuf, block_idx, 1);
        r = bdev->bdif->bread(bdev, bdev->bdif->ph_bbuf, block_idx, 1);
		bdev->bdif->bread_ctr++;
		if (r != EOK)
			return r;

		memcpy(bdev->bdif->ph_bbuf, p, len);
		//r = ext4_bdif_bwrite(bdev, bdev->bdif->ph_bbuf, block_idx, 1);
        // r = blockdev_bwrite(bdev, bdev->bdif->ph_bbuf, block_idx, 1);
        r = bdev->bdif->bwrite(bdev, bdev->bdif->ph_bbuf, block_idx, 1);
		bdev->bdif->bwrite_ctr++;
		if (r != EOK)
			return r;
	}

	return r;
}



int luca_block_readbytes(luca_blockdev_t *bdev, uint64_t off, void *buf,
			 uint32_t len)
{
	kprintf("[luca_block_readbytes] off:%ld, len:%d\n", off, len);
	uint64_t block_idx;
	uint32_t blen;
	uint32_t unalg;
	int r = EOK;
	cache_queue_t *data_cache_queue = bdev->data_cache_queue;

	uint8_t *p = (uint8_t *)buf;

	ext4_assert(bdev && buf);

	if (!bdev->bdif->ph_refctr)
		return EIO;

	if (off + len > bdev->part_size)
		return EINVAL; /*Ups. Out of range operation*/

	block_idx = ((off + bdev->part_offset) / bdev->bdif->ph_bsize);

	/*OK lets deal with the first possible unaligned block*/
	unalg = (off & (bdev->bdif->ph_bsize - 1));
	if (unalg) {

		uint32_t rlen = (bdev->bdif->ph_bsize - unalg) > len
				    ? len
				    : (bdev->bdif->ph_bsize - unalg);

		// r = ext4_bdif_bread(bdev, bdev->bdif->ph_bbuf, block_idx, 1);
        //r = blockdev_bread(bdev, bdev->bdif->ph_bbuf, block_idx, 1);


		// cache_node *node = cache_find(block_idx, data_cache_queue);
		// if(node)
		// 	memcpy(p, node->cache.data + unalg, rlen);
		// else
		// {
		// 	r = bdev->bdif->bread(bdev, bdev->bdif->ph_bbuf, block_idx, 1);
        // 	bdev->bdif->bread_ctr++;
		// 	if (r != EOK)
		// 		return r;

		// 	memcpy(p, bdev->bdif->ph_bbuf + unalg, rlen);
		// 	cache_node *new_node = (cache_node *)ext4_malloc(sizeof(cache_node));
		// 	new_node->cache.blk_id = block_idx;
		// 	memcpy(new_node->cache.data, bdev->bdif->ph_bbuf, bdev->bdif->ph_bsize);
		// 	cache_insert(data_cache_queue, new_node);

		// }
		r = bdev->bdif->bread(bdev, bdev->bdif->ph_bbuf, block_idx, 1);
        bdev->bdif->bread_ctr++;
		if (r != EOK)
			return r;

		memcpy(p, bdev->bdif->ph_bbuf + unalg, rlen);

		p += rlen;
		len -= rlen;
		block_idx++;
	}

	/*Aligned data*/
	blen = len / bdev->bdif->ph_bsize;

	if (blen != 0) {
		//printf("blen:%d\n", blen);
		//r = ext4_bdif_bread(bdev, p, block_idx, blen);
        // r = blockdev_bread(bdev, p, block_idx, blen);

		// for(int i = 0; i < blen; i++)
		// {
		// 	cache_node *node = cache_find(block_idx + i, data_cache_queue);
		// 	if(node)
		// 		memcpy(p + i*bdev->bdif->ph_bsize , node->cache.data, bdev->bdif->ph_bsize);
		// 	else
		// 	{
		// 		node = cache_num_sectors(bdev, block_idx + i, 2*blen);
		// 		memcpy(p + i*bdev->bdif->ph_bsize , node->cache.data, bdev->bdif->ph_bsize);
		// 	}
		// }


		r = bdev->bdif->bread(bdev, p, block_idx, blen);
        bdev->bdif->bread_ctr++;
		if (r != EOK)
			return r;

		p += bdev->bdif->ph_bsize * blen;
		len -= bdev->bdif->ph_bsize * blen;

		block_idx += blen;
	}

	/*Rest of the data*/
	if (len) {
		kprintf("剩余len:%d\n", len);
		//r = ext4_bdif_bread(bdev, bdev->bdif->ph_bbuf, block_idx, 1);
        // r = blockdev_bread(bdev, (void *)bdev->bdif->ph_bbuf, block_idx, 1);
		//printf("cache最大块数是%d\n",data_cache_queue->max_size);


		// cache_node *node = cache_find(block_idx, data_cache_queue);
		// if(node)
		// 	memcpy(p, node->cache.data, len);
		// else
		// {
		// 	r = bdev->bdif->bread(bdev, bdev->bdif->ph_bbuf, block_idx, 1);
		// 	bdev->bdif->bread_ctr++;
		// 	if (r != EOK)
		// 		return r;

		// 	memcpy(p, bdev->bdif->ph_bbuf, len);
		// 	//printf("从设备中捞到1\n");
		// 	cache_node *new_node = (cache_node *)ext4_malloc(sizeof(cache_node));
		// 	new_node->cache.blk_id = block_idx;
		// 	//printf("从设备中捞到2\n");
		// 	memcpy(new_node->cache.data, bdev->bdif->ph_bbuf, bdev->bdif->ph_bsize);
		// 	//printf("从设备中捞到3\n");
		// 	cache_insert(data_cache_queue, new_node);
		// }
        r = bdev->bdif->bread(bdev, bdev->bdif->ph_bbuf, block_idx, 1);
		bdev->bdif->bread_ctr++;
		if (r != EOK)
			return r;

		memcpy(p, bdev->bdif->ph_bbuf, len);
	}

	return r;
}

int luca_block_get(luca_blockdev_t *bdev, struct luca_block *b,
		   uint64_t lba)
{
	//kprintf("[luca_block_get] lba:%ld\n", lba);
	bdev->fs->bcache_lock();
	int r = luca_block_get_noread(bdev, b, lba);
	if (r != EOK) {
		bdev->fs->bcache_unlock();
		return r;
	}

	if (ext4_bcache_test_flag(b->buf, BC_UPTODATE)) {
		/* Data in the cache is up-to-date.
		 * Reading from physical device is not required */
		bdev->fs->bcache_unlock();
		return EOK;
	}

	r = luca_blocks_get_direct(bdev, b->data, lba, 1);
	if (r != EOK) {
		luca_bcache_free(bdev->bc, b);
		bdev->fs->bcache_unlock();
		b->lb_id = 0;
		return r;
	}

	/* Mark buffer up-to-date, since
	 * fresh data is read from physical device just now. */
	ext4_bcache_set_flag(b->buf, BC_UPTODATE);
	bdev->fs->bcache_unlock();
	return EOK;
}



int luca_block_set(luca_blockdev_t *bdev, struct luca_block *b)
{
	ext4_assert(bdev && b);
	ext4_assert(b->buf);

	if (!bdev->bdif->ph_refctr)
		return EIO;

	bdev->fs->bcache_lock();
	int rc = luca_bcache_free(bdev->bc, b);
	bdev->fs->bcache_unlock();
	return rc;
}

/*直接读整个块*/
int luca_blocks_get_direct(luca_blockdev_t *bdev, void *buf, uint64_t lba,
			   uint32_t cnt)
{
	uint64_t pba;
	uint32_t pb_cnt;

	ext4_assert(bdev && buf);

	pba = (lba * bdev->lg_bsize + bdev->part_offset) / bdev->bdif->ph_bsize;
	pb_cnt = bdev->lg_bsize / bdev->bdif->ph_bsize;
	int final_cnt = pb_cnt * cnt;

	int r = bdev->bdif->bread(bdev, buf, pba, pb_cnt * cnt);
    bdev->bdif->bread_ctr++;
    return EOK;
	// return ext4_bdif_bread(bdev, buf, pba, pb_cnt * cnt);
}


/*直接写整个块*/
int luca_blocks_set_direct(luca_blockdev_t *bdev, const void *buf,
			   uint64_t lba, uint32_t cnt)
{
	uint64_t pba;
	uint32_t pb_cnt;

	ext4_assert(bdev && buf);

	pba = (lba * bdev->lg_bsize + bdev->part_offset) / bdev->bdif->ph_bsize;
	pb_cnt = bdev->lg_bsize / bdev->bdif->ph_bsize;

    // int r = blockdev_bwrite(bdev, buf, pba, pb_cnt * cnt);
	int r = bdev->bdif->bwrite(bdev, buf, pba, pb_cnt * cnt);
    bdev->bdif->bwrite_ctr++;
    return r;
	//return ext4_bdif_bwrite(bdev, buf, pba, pb_cnt * cnt);
}


int luca_block_fini(luca_blockdev_t *bdev)
{
	ext4_assert(bdev);

	if (!bdev->bdif->ph_refctr)
		return EOK;

	bdev->bdif->ph_refctr--;
	if (bdev->bdif->ph_refctr)
		return EOK;

	/*Low level block fini*/
	return bdev->bdif->close(bdev);
}

int luca_block_cache_shake(luca_blockdev_t *bdev)
{
	int r = EOK;
	struct luca_buf *buf;
	if (bdev->bc->dont_shake)
		return EOK;

	bdev->bc->dont_shake = true;

	while (!RB_EMPTY(&bdev->bc->lru_root) &&
		/*ext4_bcache_is_full(bdev->bc)*/(bdev->bc->cnt <= bdev->bc->ref_blocks)) {

		//buf = ext4_buf_lowest_lru(bdev->bc);
		buf = RB_MIN(luca_buf_lru, &bdev->bc->lru_root);
		ext4_assert(buf);
		if (luca_bcache_test_flag(buf, BC_DIRTY)) {
			r = luca_block_flush_buf(bdev, buf);
			if (r != EOK)
				break;

		}

		luca_bcache_drop_buf(bdev->bc, buf);
	}
	bdev->bc->dont_shake = false;
	return r;
}

int luca_trans_block_get_noread(luca_blockdev_t *bdev,
			  struct luca_block *b,
			  uint64_t lba)
{
	bdev->fs->bcache_lock();
	int r = luca_block_get_noread(bdev, b, lba);
	bdev->fs->bcache_unlock();
	return r;
}

int luca_block_get_noread(luca_blockdev_t *bdev, struct luca_block *b,
			  uint64_t lba)
{
	bool is_new;
	int r;

	ext4_assert(bdev && b);

	if (!bdev->bdif->ph_refctr)
		return EIO;

	if (!(lba < bdev->lg_bcnt))
		return ENXIO;

	b->lb_id = lba;

	/*If cache is full we have to (flush and) drop it anyway :(*/
	r = luca_block_cache_shake(bdev);
	if (r != EOK)
		return r;

	r = luca_bcache_alloc(bdev->bc, b, &is_new);
	if (r != EOK)
		return r;

	if (!b->data)
		return ENOMEM;

	return EOK;
}

int luca_block_cache_flush(luca_blockdev_t *bdev)
{
	while (!SLIST_EMPTY(&bdev->bc->dirty_list)) {
		int r;
		struct luca_buf *buf = SLIST_FIRST(&bdev->bc->dirty_list);
		ext4_assert(buf);
		r = luca_block_flush_buf(bdev, buf);
		if (r != EOK)
			return r;

	}
	return EOK;
}

int luca_block_cache_write_back(luca_blockdev_t *bdev, uint8_t on_off)
{
	if (on_off)
		bdev->cache_write_back++;

	if (!on_off && bdev->cache_write_back)
		bdev->cache_write_back--;

	if (bdev->cache_write_back)
		return EOK;

	/*Flush data in all delayed cache blocks*/
	return luca_block_cache_flush(bdev);
}










/*block cache相关*/
// static int luca_bcache_lba_compare(struct luca_buf *a, struct luca_buf *b)
// {
// 	 if (a->lba > b->lba)
// 		 return 1;
// 	 else if (a->lba < b->lba)
// 		 return -1;
// 	 return 0;
// }

// static int luca_bcache_lru_compare(struct luca_buf *a, struct luca_buf *b)
// {
// 	if (a->lru_id > b->lru_id)
// 		return 1;
// 	else if (a->lru_id < b->lru_id)
// 		return -1;
// 	return 0;
// }


// RB_GENERATE_INTERNAL(luca_buf_lba, luca_buf, lba_node,
// 		     luca_bcache_lba_compare, static inline)
// RB_GENERATE_INTERNAL(luca_buf_lru, luca_buf, lru_node,
// 		     luca_bcache_lru_compare, static inline)

int luca_bcache_init_dynamic(luca_bcache_t *bc, uint32_t cnt,
			     uint32_t itemsize)
{
	ext4_assert(bc && cnt && itemsize);

	memset(bc, 0, sizeof(luca_bcache_t));

	bc->cnt = cnt;
	bc->itemsize = itemsize;
	bc->ref_blocks = 0;
	bc->max_ref_blocks = 0;

	return EOK;
}

void luca_bcache_cleanup(luca_bcache_t *bc)
{
	struct luca_buf *buf, *tmp;
	RB_FOREACH_SAFE(buf, luca_buf_lba, (luca_buf_lba *)&bc->lba_root, tmp) {
		luca_block_flush_buf(bc->bdev, buf);
		luca_bcache_drop_buf(bc, buf);
	}
}

int luca_bcache_fini_dynamic(luca_bcache_t *bc)
{
	memset(bc, 0, sizeof(struct ext4_bcache));
	return EOK;
}

int luca_block_bind_bcache(luca_blockdev_t *bdev, luca_bcache_t *bc)
{
	ext4_assert(bdev && bc);
	bdev->bc = bc;
	bc->bdev = bdev;
	return EOK;
}

void luca_bcache_drop_buf(luca_bcache_t *bc, luca_buf *buf)
{
	/* Warn on dropping any referenced buffers.*/
	if (buf->refctr) {
		kprintf("Buffer is still referenced. "
				"lba: %" PRIu64 ", refctr: %" PRIu32 "\n",
				buf->lba, buf->refctr);
	} else
		RB_REMOVE(luca_buf_lru, (luca_buf_lru *)&bc->lru_root, buf);

	RB_REMOVE(luca_buf_lba, (luca_buf_lba *)&bc->lba_root, buf);

	/*Forcibly drop dirty buffer.*/
	if (luca_bcache_test_flag(buf, BC_DIRTY))
		luca_bcache_remove_dirty_node(bc, buf);

	luca_buf_free(buf);
	bc->ref_blocks--;
}


int luca_block_flush_buf(luca_blockdev_t*bdev, struct luca_buf *buf)
{
	int r;
	luca_bcache_t *bc = bdev->bc;

	if (luca_bcache_test_flag(buf, BC_DIRTY) &&
	    luca_bcache_test_flag(buf, BC_UPTODATE)) {
		r = luca_blocks_set_direct(bdev, buf->data, buf->lba, 1);
		if (r) {
			if (buf->end_write) {
				bc->dont_shake = true;
				buf->end_write(bc, buf, r, buf->end_write_arg);
				bc->dont_shake = false;
			}

			return r;
		}

		luca_bcache_remove_dirty_node(bc, buf);
		luca_bcache_clear_flag(buf, BC_DIRTY);
		if (buf->end_write) {
			bc->dont_shake = true;
			buf->end_write(bc, buf, r, buf->end_write_arg);
			bc->dont_shake = false;
		}
	}
	return EOK;
}

static struct luca_buf *
luca_buf_alloc(struct luca_bcache *bc, uint64_t lba)
{
	void *data;
	struct luca_buf *buf;
	data = ext4_malloc(bc->itemsize);
	if (!data)
		return NULL;

	buf = (struct luca_buf *)ext4_calloc(1, sizeof(struct luca_buf));
	if (!buf) {
		ext4_free(data);
		return NULL;
	}

	buf->lba = lba;
	buf->data = (uint8_t *)data;
	buf->bc = bc;
	return buf;
}

static void luca_buf_free(struct luca_buf *buf)
{
	ext4_free(buf->data);
	ext4_free(buf);
}

struct luca_buf *
luca_bcache_find_get(struct luca_bcache *bc, struct luca_block *b,
		     uint64_t lba)
{
	//struct luca_buf *buf = ext4_buf_lookup(bc, lba);
	struct luca_buf tmp ;
	tmp.lba = lba;
	struct luca_buf *buf = RB_FIND(luca_buf_lba, (luca_buf_lba*)&bc->lba_root, &tmp);
	if (buf) {
		/* If buffer is not referenced. */
		if (!buf->refctr) {
			/* Assign new value to LRU id and increment LRU counter
			 * by 1*/
			buf->lru_id = ++bc->lru_ctr;
			RB_REMOVE(luca_buf_lru, (luca_buf_lru*)&bc->lru_root, buf);
			if (luca_bcache_test_flag(buf, BC_DIRTY))
				luca_bcache_remove_dirty_node(bc, buf);

		}

		ext4_bcache_inc_ref(buf);

		b->lb_id = lba;
		b->buf = buf;
		b->data = buf->data;
	}
	return buf;
}


int luca_bcache_alloc(struct luca_bcache *bc, struct luca_block *b,
		      bool *is_new)
{
	/* Try to search the buffer with exaxt LBA. */
	struct luca_buf *buf = luca_bcache_find_get(bc, b, b->lb_id);
	if (buf) {
		*is_new = false;
		return EOK;
	}

	/* We need to allocate one buffer.*/
	buf = luca_buf_alloc(bc, b->lb_id);
	if (!buf)
		return ENOMEM;

	RB_INSERT(luca_buf_lba, (luca_buf_lba *)&bc->lba_root, buf);
	/* One more buffer in bcache now. :-) */
	bc->ref_blocks++;

	/*Calc ref blocks max depth*/
	if (bc->max_ref_blocks < bc->ref_blocks)
		bc->max_ref_blocks = bc->ref_blocks;


	ext4_bcache_inc_ref(buf);
	/* Assign new value to LRU id and increment LRU counter
	 * by 1*/
	buf->lru_id = ++bc->lru_ctr;

	b->buf = buf;
	b->data = buf->data;

	*is_new = true;
	return EOK;
}

// Called by 3 functions - ext4_block_flush_lba(), ext4_block_get() and ext4_block_set()
// Protected there
int luca_bcache_free(luca_bcache_t *bc, struct luca_block *b)
{
	struct luca_buf *buf = b->buf;

	ext4_assert(bc && b);

	/*Check if valid.*/
	ext4_assert(b->lb_id);

	/*Block should have a valid pointer to ext4_buf.*/
	ext4_assert(buf);

	/*Check if someone don't try free unreferenced block cache.*/
	ext4_assert(buf->refctr);

	/*Just decrease reference counter*/
	ext4_bcache_dec_ref(buf);

	luca_blockdev_t *bdev = bc->bdev;

	/* We are the last one touching this buffer, do the cleanups. */
	if (!buf->refctr) {
		RB_INSERT(luca_buf_lru, (luca_buf_lru *)&bc->lru_root, buf);
		/* This buffer is ready to be flushed. */
		if (luca_bcache_test_flag(buf, BC_DIRTY) &&
		    luca_bcache_test_flag(buf, BC_UPTODATE)) {
			if (bdev->cache_write_back &&
			    !luca_bcache_test_flag(buf, BC_FLUSH) &&
			    !luca_bcache_test_flag(buf, BC_TMP))
				luca_bcache_insert_dirty_node(bc, buf);
			else {
				luca_block_flush_buf(bdev, buf);
				luca_bcache_clear_flag(buf, BC_FLUSH);
			}
		}

		/* The buffer is invalidated...drop it. */
		if (!luca_bcache_test_flag(buf, BC_UPTODATE) ||
		    luca_bcache_test_flag(buf, BC_TMP))
			luca_bcache_drop_buf(bc, buf);

	}

	b->lb_id = 0;
	b->data = 0;

	return EOK;
}

static
void ext4_bcache_invalidate_buf(luca_bcache_t *bc,
				struct luca_buf *buf)
{
	buf->end_write = NULL;
	buf->end_write_arg = NULL;

	/* Clear both dirty and up-to-date flags. */
	if (ext4_bcache_test_flag(buf, BC_DIRTY))
	{
		luca_bcache_remove_dirty_node(bc, buf);
	}

	luca_bcache_clear_dirty(buf);
}

void luca_bcache_invalidate_lba(luca_bcache_t *bc,
				uint64_t from,
				uint32_t cnt)
{
	uint64_t end = from + cnt - 1;
	//struct ext4_buf *tmp = ext4_buf_lookup(bc, from), *buf;
	struct luca_buf tmp;
	tmp.lba = from;
	struct luca_buf *temp = RB_FIND(luca_buf_lba, (luca_buf_lba *)&bc->lba_root, &tmp);
	struct luca_buf *buf;

	RB_FOREACH_FROM(buf, luca_buf_lba, temp) {
		if (buf->lba > end)
			break;

		ext4_bcache_invalidate_buf(bc, buf);
	}
}








/*blcok group相关*/
int luca_fs_get_block_group_ref(luca_fs_t *fs, uint32_t bgid,
				luca_block_group_ref_t *ref)
{
	/* Compute number of descriptors, that fits in one data block */
	//uint32_t block_size = ext4_sb_get_block_size(&fs->sb);
	uint32_t block_size = 1024 << fs->sb.log_block_size;
	uint32_t dsc_cnt = block_size / ext4_sb_get_desc_size(&fs->sb);

	/* Block group descriptor table starts at the next block after
	 * superblock */
	uint64_t block_id = luca_fs_get_descriptor_block(&fs->sb, bgid, dsc_cnt);

	uint32_t offset = (bgid % dsc_cnt) * ext4_sb_get_desc_size(&fs->sb);

	//int rc = ext4_trans_block_get(fs->bdev, &ref->block, block_id);
	int rc = luca_block_get(fs->bdev, &ref->block, block_id);
	if (rc != EOK)
		return rc;

	ref->block_group = (ext4_bgroup *)(ref->block.data + offset);
	ref->fs = fs;
	ref->index = bgid;
	ref->dirty = false;
	struct ext4_bgroup *bg = ref->block_group;

	if (!luca_fs_verify_bg_csum(&fs->sb, bgid, bg)) {
		ext4_dbg(DEBUG_FS,
			 DBG_WARN "Block group descriptor checksum failed."
			 "Block group index: %" PRIu32"\n",
			 bgid);
	}

	if (ext4_bg_has_flag(bg, EXT4_BLOCK_GROUP_BLOCK_UNINIT)) {
		rc = luca_fs_init_block_bitmap(ref);
		if (rc != EOK) {
			luca_block_set(fs->bdev, &ref->block);
			return rc;
		}
		ext4_bg_clear_flag(bg, EXT4_BLOCK_GROUP_BLOCK_UNINIT);
		ref->dirty = true;
	}

	if (ext4_bg_has_flag(bg, EXT4_BLOCK_GROUP_INODE_UNINIT)) {
		rc = luca_fs_init_inode_bitmap(ref);
		if (rc != EOK) {
			luca_block_set(ref->fs->bdev, &ref->block);
			return rc;
		}

		ext4_bg_clear_flag(bg, EXT4_BLOCK_GROUP_INODE_UNINIT);

		if (!ext4_bg_has_flag(bg, EXT4_BLOCK_GROUP_ITABLE_ZEROED)) {
			rc = luca_fs_init_inode_table(ref);
			if (rc != EOK) {
				luca_block_set(fs->bdev, &ref->block);
				return rc;
			}

			ext4_bg_set_flag(bg, EXT4_BLOCK_GROUP_ITABLE_ZEROED);
		}

		ref->dirty = true;
	}

	return EOK;
}




/*inode相关*/
void luca_inode_clear_flag(struct luca_inode *inode, uint32_t f)
{
	uint32_t flags = to_le32(inode->flags);
	flags = flags & (~f);
	inode->flags = to_le32(flags);
}

void luca_inode_set_size(struct luca_inode *inode, uint64_t size)
{
	inode->size_lo = to_le32((size << 32) >> 32);
	inode->size_hi = to_le32(size >> 32);
}

static uint32_t luca_inode_block_bits_count(uint32_t block_size)
{
	uint32_t bits = 8;
	uint32_t size = block_size;

	do {
		bits++;
		size = size >> 1;
	} while (size > 256);

	return bits;
}

uint32_t luca_inode_type(luca_sblock_t*sb, struct luca_inode *inode)
{
	return (to_le16(inode->mode) & EXT4_INODE_MODE_TYPE_MASK);
}


void luca_inode_set_flag(struct luca_inode *inode, uint32_t f)
{
	uint32_t flags = to_le32(inode->flags);
	flags = flags | f;
	// ext4_inode_set_flags(inode, flags);
	inode->flags = to_le32(flags);
}


uint64_t luca_inode_get_size(luca_sblock_t *sb, struct luca_inode *inode)
{
	uint64_t v = to_le32(inode->size_lo);

	bool is_file = (to_le16(inode->mode) & EXT4_INODE_MODE_TYPE_MASK) == EXT4_INODE_MODE_FILE; 

	if ((ext4_get32(sb, rev_level) > 0) &&
	    is_file)
		v |= ((uint64_t)to_le32(inode->size_hi)) << 32;

	return v;
}

uint32_t luca_inode_get_csum(luca_sblock_t *sb, struct luca_inode *inode)
{
	uint16_t inode_size = ext4_get16(sb, inode_size);
	uint32_t v = to_le16(inode->checksum_lo);

	if (inode_size > EXT4_GOOD_OLD_INODE_SIZE)
		v |= ((uint32_t)to_le16(inode->checksum_hi)) << 16;

	return v;
}

void luca_inode_set_csum(luca_sblock_t *sb, struct luca_inode *inode,
			uint32_t checksum)
{
	uint16_t inode_size = ext4_get16(sb, inode_size);
	inode->checksum_lo =
		to_le16((checksum << 16) >> 16);

	if (inode_size > EXT4_GOOD_OLD_INODE_SIZE)
		inode->checksum_hi = to_le16(checksum >> 16);

}

uint64_t luca_inode_get_file_acl(struct luca_inode *inode,
				 luca_sblock_t *sb)
{
	uint64_t v = to_le32(inode->file_acl_lo);
	v |= (uint32_t)to_le16(inode->file_acl_high) << 16;

	// if (ext4_get32(sb, creator_os) == EXT4_SUPERBLOCK_OS_LINUX)
	// 	v |= (uint32_t)to_le16(inode->osd2.linux2.file_acl_high) << 16;

	return v;
}

void luca_inode_set_file_acl(struct luca_inode *inode, luca_sblock_t *sb,
			     uint64_t acl)
{
	inode->file_acl_lo = to_le32((acl << 32) >> 32);
	inode->file_acl_high = to_le16((uint16_t)(acl >> 32));

	// if (ext4_get32(sb, creator_os) == EXT4_SUPERBLOCK_OS_LINUX)
	// 	inode->osd2.linux2.file_acl_high = to_le16((uint16_t)(acl >> 32));
}

bool luca_inode_can_truncate(luca_sblock_t *sb, struct luca_inode *inode)
{
	if ((to_le32(inode->flags) & EXT4_INODE_FLAG_APPEND) ||
	    (to_le32(inode->flags) & EXT4_INODE_FLAG_IMMUTABLE))
		return false;

	if (((to_le16(inode->mode) & EXT4_INODE_MODE_TYPE_MASK) == EXT4_INODE_MODE_FILE) ||
	    ((to_le16(inode->mode) & EXT4_INODE_MODE_TYPE_MASK) == EXT4_INODE_MODE_DIRECTORY) ||
	    ((to_le16(inode->mode) & EXT4_INODE_MODE_TYPE_MASK) == EXT4_INODE_MODE_SOFTLINK))
		return true;

	return false;
}

static int __luca_fs_get_inode_ref(luca_fs_t *fs, uint32_t index,
			luca_inode_ref_t *ref, bool initialized)
{
	/* Compute number of i-nodes, that fits in one data block */
	//uint32_t inodes_per_group = ext4_get32(&fs->sb, inodes_per_group);
	uint32_t inodes_per_group = fs->sb.inodes_per_group;
	/*
	 * Inode numbers are 1-based, but it is simpler to work with 0-based
	 * when computing indices
	 */
	index -= 1;
	uint32_t block_group = index / inodes_per_group;
	uint32_t offset_in_group = index % inodes_per_group;

	/* Load block group, where i-node is located */
	luca_block_group_ref_t bg_ref;
	//kprintf("测试1block_group: %d\n", block_group);

	int rc = luca_fs_get_block_group_ref(fs, block_group, &bg_ref);
	if (rc != EOK) {
		return rc;
	}

	/* Load block address, where i-node table is located */
	uint64_t inode_table_start =
	    ext4_bg_get_inode_table_first_block(bg_ref.block_group, &fs->sb);

	/* Put back block group reference (not needed more) */
	rc = luca_fs_put_block_group_ref(&bg_ref);
	if (rc != EOK) {
		return rc;
	}

	//kprintf("测试2\n");

	/* Compute position of i-node in the block group */
	uint16_t inode_size = ext4_get16(&fs->sb, inode_size);
	uint32_t block_size = luca_sb_get_block_size(&fs->sb);
	uint32_t byte_offset_in_group = offset_in_group * inode_size;

	/* Compute block address */
	uint64_t block_id =
	    inode_table_start + (byte_offset_in_group / block_size);

	//rc = ext4_trans_block_get(fs->bdev, &ref->block, block_id);
	rc = luca_block_get(fs->bdev, &ref->block, block_id);
	if (rc != EOK) {
		return rc;
	}

	/* Compute position of i-node in the data block */
	uint32_t offset_in_block = byte_offset_in_group % block_size;
	ref->inode = (struct luca_inode *)(ref->block.data + offset_in_block);

	/* We need to store the original value of index in the reference */
	ref->index = index + 1;
	ref->fs = fs;
	ref->dirty = false;

	if (initialized && !luca_fs_verify_inode_csum(ref)) {
		ext4_dbg(DEBUG_FS,
			DBG_WARN "Inode checksum failed."
			"Inode: %" PRIu32"\n",
			ref->index);
	}

	return EOK;
}

int luca_fs_get_inode_ref(luca_fs_t *fs, uint32_t index,
			  luca_inode_ref_t *ref)
{
	return __luca_fs_get_inode_ref(fs, index, ref, true);
}

int luca_fs_put_inode_ref(luca_inode_ref_t *ref)
{
	/* Check if reference modified */
	if (ref->dirty) {
		/* Mark block dirty for writing changes to physical device */
		luca_fs_set_inode_checksum(ref);
		//ext4_trans_set_block_dirty(ref->block.buf);
		luca_bcache_set_dirty(ref->block.buf);
	}

	/* Put back block, that contains i-node */
	return luca_block_set(ref->fs->bdev, &ref->block);
}




uint64_t luca_inode_get_blocks_count(luca_sblock_t *sb,
				     struct luca_inode *inode)
{
	uint64_t cnt = to_le32(inode->blocks_count_lo);

	if (ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_HUGE_FILE)) {

		/* 48-bit field */
		cnt |= (uint64_t)to_le16(inode->blocks_high) << 32;

		if (/*ext4_inode_has_flag(inode, EXT4_INODE_FLAG_HUGE_FILE)*/
		    to_le32(inode->flags) & EXT4_INODE_FLAG_HUGE_FILE) {

			uint32_t block_count = ext4_sb_get_block_size(sb);
			uint32_t b = luca_inode_block_bits_count(block_count);
			return cnt << (b - 9);
		}
	}

	return cnt;
}

int luca_inode_set_blocks_count(luca_sblock_t *sb,
				struct luca_inode *inode, uint64_t count)
{
	/* 32-bit maximum */
	uint64_t max = 0;
	max = ~max >> 32;

	if (count <= max) {
		inode->blocks_count_lo = to_le32((uint32_t)count);
		inode->blocks_high = 0;
		luca_inode_clear_flag(inode, EXT4_INODE_FLAG_HUGE_FILE);

		return EOK;
	}

	/* Check if there can be used huge files (many blocks) */
	if (!ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_HUGE_FILE))
		return EINVAL;

	/* 48-bit maximum */
	max = 0;
	max = ~max >> 16;

	if (count <= max) {
		inode->blocks_count_lo = to_le32((uint32_t)count);
		inode->blocks_high = to_le16((uint16_t)(count >> 32));
		luca_inode_clear_flag(inode, EXT4_INODE_FLAG_HUGE_FILE);
	} else {
		uint32_t block_count = ext4_sb_get_block_size(sb);
		uint32_t block_bits = luca_inode_block_bits_count(block_count);

		luca_inode_set_flag(inode, EXT4_INODE_FLAG_HUGE_FILE);
		//inode->flags = to_le32(EXT4_INODE_FLAG_HUGE_FILE);
		count = count >> (block_bits - 9);
		inode->blocks_count_lo = to_le32((uint32_t)count);
		inode->blocks_high = to_le16((uint16_t)(count >> 32));
	}

	return EOK;
}







/*balloc相关*/
#if CONFIG_META_CSUM_ENABLE
static uint32_t luca_balloc_bitmap_csum(luca_sblock_t *sb,
					void *bitmap)
{
	uint32_t checksum = 0;
	if (ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM)) {
		uint32_t blocks_per_group = ext4_get32(sb, blocks_per_group);

		/* First calculate crc32 checksum against fs uuid */
		checksum = ext4_crc32c(EXT4_CRC32_INIT, sb->uuid,
				sizeof(sb->uuid));
		/* Then calculate crc32 checksum against block_group_desc */
		checksum = ext4_crc32c(checksum, bitmap, blocks_per_group / 8);
	}
	return checksum;
}
#else
#define ext4_balloc_bitmap_csum(...) 0
#endif

#if CONFIG_META_CSUM_ENABLE
static bool
luca_balloc_verify_bitmap_csum(luca_sblock_t *sb,
			       struct ext4_bgroup *bg,
			       void *bitmap __unused)
{
	int desc_size = ext4_sb_get_desc_size(sb);
	uint32_t checksum = luca_balloc_bitmap_csum(sb, bitmap);
	uint16_t lo_checksum = to_le16(checksum & 0xFFFF),
		 hi_checksum = to_le16(checksum >> 16);

	if (!ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM))
		return true;

	if (bg->block_bitmap_csum_lo != lo_checksum)
		return false;

	if (desc_size == EXT4_MAX_BLOCK_GROUP_DESCRIPTOR_SIZE)
		if (bg->block_bitmap_csum_hi != hi_checksum)
			return false;

	return true;
}
#else
#define ext4_balloc_verify_bitmap_csum(...) true
#endif

int
luca_balloc_alloc_block(luca_inode_ref_t *inode_ref,
			    uint64_t goal,
			    uint64_t *fblock)
{
	uint64_t alloc = 0;
	uint64_t bmp_blk_adr;
	uint32_t rel_blk_idx = 0;
	uint64_t free_blocks;
	uint32_t blk_in_bg;
	uint32_t end_idx;
	uint32_t block_group_count;
	uint32_t bgid;
	uint32_t count;
	int r;
	struct ext4_sblock *sb = &inode_ref->fs->sb;

	/* Load block group number for goal and relative index */
	uint32_t bg_id = ext4_balloc_get_bgid_of_block(sb, goal);
	uint32_t idx_in_bg = ext4_fs_addr_to_idx_bg(sb, goal);

	struct luca_block b;
	struct luca_block_group_ref bg_ref;

	/* Load block group reference */
	r = luca_fs_get_block_group_ref(inode_ref->fs, bg_id, &bg_ref);
	if (r != EOK)
		return r;

	struct ext4_bgroup *bg = bg_ref.block_group;

	free_blocks = ext4_bg_get_free_blocks_count(bg_ref.block_group, sb);
	if (free_blocks == 0) {
		/* This group has no free blocks */
		goto goal_failed;
	}

	/* Compute indexes */
	uint64_t first_in_bg;
	first_in_bg = ext4_balloc_get_block_of_bgid(sb, bg_ref.index);

	uint32_t first_in_bg_index;
	first_in_bg_index = ext4_fs_addr_to_idx_bg(sb, first_in_bg);

	if (idx_in_bg < first_in_bg_index)
		idx_in_bg = first_in_bg_index;

	/* Load block with bitmap */
	bmp_blk_adr = ext4_bg_get_block_bitmap(bg_ref.block_group, sb);

	r = luca_block_get(inode_ref->fs->bdev, &b, bmp_blk_adr);
	if (r != EOK) {
		luca_fs_put_block_group_ref(&bg_ref);
		return r;
	}

	if (!luca_balloc_verify_bitmap_csum(sb, bg, b.data)) {
		ext4_dbg(DEBUG_BALLOC,
			DBG_WARN "Bitmap checksum failed."
			"Group: %" PRIu32"\n",
			bg_ref.index);
	}

	/* Check if goal is free */
	if (ext4_bmap_is_bit_clr(b.data, idx_in_bg)) {
		ext4_bmap_bit_set(b.data, idx_in_bg);
		ext4_balloc_set_bitmap_csum(sb, bg_ref.block_group,
					    b.data);
		//ext4_trans_set_block_dirty(b.buf);
		luca_bcache_set_dirty(b.buf);
		r = luca_block_set(inode_ref->fs->bdev, &b);
		if (r != EOK) {
			luca_fs_put_block_group_ref(&bg_ref);
			return r;
		}

		alloc = ext4_fs_bg_idx_to_addr(sb, idx_in_bg, bg_id);
		goto success;
	}

	blk_in_bg = ext4_blocks_in_group_cnt(sb, bg_id);

	end_idx = (idx_in_bg + 63) & ~63;
	if (end_idx > blk_in_bg)
		end_idx = blk_in_bg;

	/* Try to find free block near to goal */
	uint32_t tmp_idx;
	for (tmp_idx = idx_in_bg + 1; tmp_idx < end_idx; ++tmp_idx) {
		if (ext4_bmap_is_bit_clr(b.data, tmp_idx)) {
			ext4_bmap_bit_set(b.data, tmp_idx);

			ext4_balloc_set_bitmap_csum(sb, bg, b.data);
			luca_bcache_set_dirty(b.buf);
			r = luca_block_set(inode_ref->fs->bdev, &b);
			if (r != EOK) {
				luca_fs_put_block_group_ref(&bg_ref);
				return r;
			}

			alloc = ext4_fs_bg_idx_to_addr(sb, tmp_idx, bg_id);
			goto success;
		}
	}

	/* Find free bit in bitmap */
	r = ext4_bmap_bit_find_clr(b.data, idx_in_bg, blk_in_bg, &rel_blk_idx);
	if (r == EOK) {
		ext4_bmap_bit_set(b.data, rel_blk_idx);
		ext4_balloc_set_bitmap_csum(sb, bg_ref.block_group, b.data);
		luca_bcache_set_dirty(b.buf);
		r = luca_block_set(inode_ref->fs->bdev, &b);
		if (r != EOK) {
			luca_fs_put_block_group_ref(&bg_ref);
			return r;
		}

		alloc = ext4_fs_bg_idx_to_addr(sb, rel_blk_idx, bg_id);
		goto success;
	}

	/* No free block found yet */
	r = luca_block_set(inode_ref->fs->bdev, &b);
	if (r != EOK) {
		luca_fs_put_block_group_ref(&bg_ref);
		return r;
	}

goal_failed:

	r = luca_fs_put_block_group_ref(&bg_ref);
	if (r != EOK)
		return r;

	/* Try other block groups */
	block_group_count = ext4_block_group_cnt(sb);
	bgid = (bg_id + 1) % block_group_count;
	count = block_group_count;

	while (count > 0) {
		r = luca_fs_get_block_group_ref(inode_ref->fs, bgid, &bg_ref);
		if (r != EOK)
			return r;

		struct ext4_bgroup *bg = bg_ref.block_group;
		free_blocks = ext4_bg_get_free_blocks_count(bg, sb);
		if (free_blocks == 0) {
			/* This group has no free blocks */
			goto next_group;
		}

		/* Load block with bitmap */
		bmp_blk_adr = ext4_bg_get_block_bitmap(bg, sb);
		r = luca_block_get(inode_ref->fs->bdev, &b, bmp_blk_adr);
		if (r != EOK) {
			luca_fs_put_block_group_ref(&bg_ref);
			return r;
		}

		if (!luca_balloc_verify_bitmap_csum(sb, bg, b.data)) {
			ext4_dbg(DEBUG_BALLOC,
				DBG_WARN "Bitmap checksum failed."
				"Group: %" PRIu32"\n",
				bg_ref.index);
		}

		/* Compute indexes */
		first_in_bg = ext4_balloc_get_block_of_bgid(sb, bgid);
		idx_in_bg = ext4_fs_addr_to_idx_bg(sb, first_in_bg);
		blk_in_bg = ext4_blocks_in_group_cnt(sb, bgid);
		first_in_bg_index = ext4_fs_addr_to_idx_bg(sb, first_in_bg);

		if (idx_in_bg < first_in_bg_index)
			idx_in_bg = first_in_bg_index;

		r = ext4_bmap_bit_find_clr(b.data, idx_in_bg, blk_in_bg,
				&rel_blk_idx);
		if (r == EOK) {
			ext4_bmap_bit_set(b.data, rel_blk_idx);
			ext4_balloc_set_bitmap_csum(sb, bg, b.data);
			luca_bcache_set_dirty(b.buf);
			r = luca_block_set(inode_ref->fs->bdev, &b);
			if (r != EOK) {
				luca_fs_put_block_group_ref(&bg_ref);
				return r;
			}

			alloc = ext4_fs_bg_idx_to_addr(sb, rel_blk_idx, bgid);
			goto success;
		}

		r = luca_block_set(inode_ref->fs->bdev, &b);
		if (r != EOK) {
			luca_fs_put_block_group_ref(&bg_ref);
			return r;
		}

	next_group:
		r = luca_fs_put_block_group_ref(&bg_ref);
		if (r != EOK) {
			return r;
		}

		/* Goto next group */
		bgid = (bgid + 1) % block_group_count;
		count--;
	}

	return ENOSPC;

success:
    /* Empty command - because of syntax */
    ;

	uint32_t block_size = ext4_sb_get_block_size(sb);

	/* Update superblock free blocks count */
	uint64_t sb_free_blocks = ext4_sb_get_free_blocks_cnt(sb);
	sb_free_blocks--;
	ext4_sb_set_free_blocks_cnt(sb, sb_free_blocks);

	/* Update inode blocks (different block size!) count */
	uint64_t ino_blocks = luca_inode_get_blocks_count(sb, inode_ref->inode);
	ino_blocks += block_size / EXT4_INODE_BLOCK_SIZE;
	luca_inode_set_blocks_count(sb, inode_ref->inode, ino_blocks);
	inode_ref->dirty = true;

	/* Update block group free blocks count */

	uint32_t fb_cnt = ext4_bg_get_free_blocks_count(bg_ref.block_group, sb);
	fb_cnt--;
	ext4_bg_set_free_blocks_count(bg_ref.block_group, sb, fb_cnt);

	bg_ref.dirty = true;
	r = luca_fs_put_block_group_ref(&bg_ref);

	*fblock = alloc;
	return r;
}

int
luca_balloc_free_block(luca_inode_ref_t *inode_ref, ext4_fsblk_t baddr)
{
	luca_fs_t *fs = inode_ref->fs;
	luca_sblock_t *sb = &fs->sb;

	uint32_t bg_id = ext4_balloc_get_bgid_of_block(sb, baddr);
	uint32_t index_in_group = ext4_fs_addr_to_idx_bg(sb, baddr);

	/* Load block group reference */
	luca_block_group_ref_t bg_ref;
	int rc = luca_fs_get_block_group_ref(fs, bg_id, &bg_ref);
	if (rc != EOK)
		return rc;

	struct ext4_bgroup *bg = bg_ref.block_group;

	/* Load block with bitmap */
	ext4_fsblk_t bitmap_block_addr =
	    ext4_bg_get_block_bitmap(bg, sb);

	struct luca_block bitmap_block;

	rc = luca_block_get(fs->bdev, &bitmap_block, bitmap_block_addr);
	if (rc != EOK) {
		luca_fs_put_block_group_ref(&bg_ref);
		return rc;
	}

	if (!luca_balloc_verify_bitmap_csum(sb, bg, bitmap_block.data)) {
		ext4_dbg(DEBUG_BALLOC,
			DBG_WARN "Bitmap checksum failed."
			"Group: %" PRIu32"\n",
			bg_ref.index);
	}

	/* Modify bitmap */
	ext4_bmap_bit_clr(bitmap_block.data, index_in_group);
	ext4_balloc_set_bitmap_csum(sb, bg, bitmap_block.data);
	//ext4_trans_set_block_dirty(bitmap_block.buf);
	luca_bcache_set_dirty(bitmap_block.buf);

	/* Release block with bitmap */
	rc = luca_block_set(fs->bdev, &bitmap_block);
	if (rc != EOK) {
		/* Error in saving bitmap */
		luca_fs_put_block_group_ref(&bg_ref);
		return rc;
	}

	uint32_t block_size = ext4_sb_get_block_size(sb);

	/* Update superblock free blocks count */
	uint64_t sb_free_blocks = ext4_sb_get_free_blocks_cnt(sb);
	sb_free_blocks++;
	ext4_sb_set_free_blocks_cnt(sb, sb_free_blocks);

	/* Update inode blocks count */
	uint64_t ino_blocks = luca_inode_get_blocks_count(sb, inode_ref->inode);
	ino_blocks -= block_size / EXT4_INODE_BLOCK_SIZE;
	luca_inode_set_blocks_count(sb, inode_ref->inode, ino_blocks);
	inode_ref->dirty = true;

	/* Update block group free blocks count */
	uint32_t free_blocks = ext4_bg_get_free_blocks_count(bg, sb);
	free_blocks++;
	ext4_bg_set_free_blocks_count(bg, sb, free_blocks);

	bg_ref.dirty = true;

	// rc = ext4_trans_try_revoke_block(fs->bdev, baddr);
	// if (rc != EOK) {
	// 	bg_ref.dirty = false;
	// 	ext4_fs_put_block_group_ref(&bg_ref);
	// 	return rc;
	// }
	fs->bcache_lock();
	luca_bcache_invalidate_lba(fs->bdev->bc, baddr, 1);
	fs->bcache_unlock();
	/* Release block group reference */
	rc = luca_fs_put_block_group_ref(&bg_ref);

	return rc;
}

int
luca_balloc_free_blocks(luca_inode_ref_t *inode_ref,
			    uint64_t first, uint32_t count)
{
	int rc = EOK;
	uint32_t blk_cnt = count;
	uint64_t start_block = first;
	luca_fs_t *fs = inode_ref->fs;
	luca_sblock_t *sb = &fs->sb;

	/* Compute indexes */
	uint32_t bg_first = ext4_balloc_get_bgid_of_block(sb, first);

	/* Compute indexes */
	uint32_t bg_last = ext4_balloc_get_bgid_of_block(sb, first + count - 1);

	if (!ext4_sb_feature_incom(sb, EXT4_FINCOM_FLEX_BG)) {
		/*It is not possible without flex_bg that blocks are continuous
		 * and and last block belongs to other bg.*/
		if (bg_last != bg_first) {
			ext4_dbg(DEBUG_BALLOC, DBG_WARN "FLEX_BG: disabled & "
				"bg_last: %"PRIu32" bg_first: %"PRIu32"\n",
				bg_last, bg_first);
		}
	}

	/* Load block group reference */
	luca_block_group_ref_t bg_ref;
	while (bg_first <= bg_last) {

		rc = luca_fs_get_block_group_ref(fs, bg_first, &bg_ref);
		if (rc != EOK)
			return rc;

		struct ext4_bgroup *bg = bg_ref.block_group;

		uint32_t idx_in_bg_first;
		idx_in_bg_first = ext4_fs_addr_to_idx_bg(sb, first);

		/* Load block with bitmap */
		uint64_t bitmap_blk = ext4_bg_get_block_bitmap(bg, sb);

		struct luca_block blk;
		rc = luca_block_get(fs->bdev, &blk, bitmap_blk);
		if (rc != EOK) {
			luca_fs_put_block_group_ref(&bg_ref);
			return rc;
		}

		if (!luca_balloc_verify_bitmap_csum(sb, bg, blk.data)) {
			ext4_dbg(DEBUG_BALLOC,
				DBG_WARN "Bitmap checksum failed."
				"Group: %" PRIu32"\n",
				bg_ref.index);
		}
		uint32_t free_cnt;
		free_cnt = ext4_sb_get_block_size(sb) * 8 - idx_in_bg_first;

		/*If last block, free only count blocks*/
		free_cnt = count > free_cnt ? free_cnt : count;

		/* Modify bitmap */
		ext4_bmap_bits_free(blk.data, idx_in_bg_first, free_cnt);
		ext4_balloc_set_bitmap_csum(sb, bg, blk.data);
		//ext4_trans_set_block_dirty(blk.buf);
		luca_bcache_set_dirty(blk.buf);

		count -= free_cnt;
		first += free_cnt;

		/* Release block with bitmap */
		rc = luca_block_set(fs->bdev, &blk);
		if (rc != EOK) {
			luca_fs_put_block_group_ref(&bg_ref);
			return rc;
		}

		uint32_t block_size = ext4_sb_get_block_size(sb);

		/* Update superblock free blocks count */
		uint64_t sb_free_blocks = ext4_sb_get_free_blocks_cnt(sb);
		sb_free_blocks += free_cnt;
		ext4_sb_set_free_blocks_cnt(sb, sb_free_blocks);

		/* Update inode blocks count */
		uint64_t ino_blocks;
		ino_blocks = luca_inode_get_blocks_count(sb, inode_ref->inode);
		ino_blocks -= free_cnt * (block_size / EXT4_INODE_BLOCK_SIZE);
		luca_inode_set_blocks_count(sb, inode_ref->inode, ino_blocks);
		inode_ref->dirty = true;

		/* Update block group free blocks count */
		uint32_t free_blocks;
		free_blocks = ext4_bg_get_free_blocks_count(bg, sb);
		free_blocks += free_cnt;
		ext4_bg_set_free_blocks_count(bg, sb, free_blocks);
		bg_ref.dirty = true;

		/* Release block group reference */
		rc = luca_fs_put_block_group_ref(&bg_ref);
		if (rc != EOK)
			break;

		bg_first++;
	}

	// uint32_t i;
	// for (i = 0;i < blk_cnt;i++) {
	// 	rc = ext4_trans_try_revoke_block(fs->bdev, start_block + i);
	// 	if (rc != EOK)
	// 		return rc;

	// }

	fs->bcache_lock();
	luca_bcache_invalidate_lba(fs->bdev->bc, start_block, blk_cnt);
	fs->bcache_unlock();
	/*All blocks should be released*/
	ext4_assert(count == 0);

	return rc;
}









/*dir_idx相关*/
static inline uint16_t
ext4_dir_dx_climit_get_limit(struct ext4_dir_idx_climit *climit)
{
	return to_le16(climit->limit);
}

static inline void
ext4_dir_dx_climit_set_limit(struct ext4_dir_idx_climit *climit, uint16_t limit)
{
	climit->limit = to_le16(limit);
}

/**@brief Get current number of index node entries.
 * @param climit Pointer to counlimit structure
 * @return Number of entries in node
 */
static inline uint16_t
ext4_dir_dx_climit_get_count(struct ext4_dir_idx_climit *climit)
{
	return to_le16(climit->count);
}

/**@brief Set current number of index node entries.
 * @param climit Pointer to counlimit structure
 * @param count Number of entries in node
 */
static inline void
ext4_dir_dx_climit_set_count(struct ext4_dir_idx_climit *climit, uint16_t count)
{
	climit->count = to_le16(count);
}

/**@brief Get hash value of index entry.
 * @param entry Pointer to index entry
 * @return Hash value
 */
static inline uint32_t
ext4_dir_dx_entry_get_hash(struct ext4_dir_idx_entry *entry)
{
	return to_le32(entry->hash);
}

/**@brief Set hash value of index entry.
 * @param entry Pointer to index entry
 * @param hash  Hash value
 */
static inline void
ext4_dir_dx_entry_set_hash(struct ext4_dir_idx_entry *entry, uint32_t hash)
{
	entry->hash = to_le32(hash);
}

/**@brief Get block address where child node is located.
 * @param entry Pointer to index entry
 * @return Block address of child node
 */
static inline uint32_t
ext4_dir_dx_entry_get_block(struct ext4_dir_idx_entry *entry)
{
	return to_le32(entry->block);
}

/**@brief Set block address where child node is located.
 * @param entry Pointer to index entry
 * @param block Block address of child node
 */
static inline void
ext4_dir_dx_entry_set_block(struct ext4_dir_idx_entry *entry, uint32_t block)
{
	entry->block = to_le32(block);
}

struct ext4_dx_sort_entry {
	uint32_t hash;
	uint32_t rec_len;
	void *dentry;
};

#if CONFIG_META_CSUM_ENABLE
static uint32_t luca_dir_dx_checksum(luca_inode_ref_t *inode_ref, void *de,
				     int count_offset, int count,
				     struct ext4_dir_idx_tail *t)
{
	uint32_t orig_cum, csum = 0;
	luca_sblock_t *sb = &inode_ref->fs->sb;
	int sz;

	/* Compute the checksum only if the filesystem supports it */
	if (ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM)) {
		uint32_t ino_index = to_le32(inode_ref->index);
		uint32_t ino_gen;
		ino_gen = to_le32(inode_ref->inode->generation);

		sz = count_offset + (count * sizeof(struct ext4_dir_idx_tail));
		orig_cum = t->checksum;
		t->checksum = 0;
		/* First calculate crc32 checksum against fs uuid */
		csum = ext4_crc32c(EXT4_CRC32_INIT, sb->uuid, sizeof(sb->uuid));
		/* Then calculate crc32 checksum against inode number
		 * and inode generation */
		csum = ext4_crc32c(csum, &ino_index, sizeof(ino_index));
		csum = ext4_crc32c(csum, &ino_gen, sizeof(ino_gen));
		/* After that calculate crc32 checksum against all the dx_entry */
		csum = ext4_crc32c(csum, de, sz);
		/* Finally calculate crc32 checksum for dx_tail */
		csum = ext4_crc32c(csum, t, sizeof(struct ext4_dir_idx_tail));
		t->checksum = orig_cum;
	}
	return csum;
}

static struct ext4_dir_idx_climit *
luca_dir_dx_get_climit(luca_inode_ref_t *inode_ref,
			   struct ext4_dir_en *dirent, int *offset)
{
	struct ext4_dir_en *dp;
	struct ext4_dir_idx_root *root;
	luca_sblock_t *sb = &inode_ref->fs->sb;
	uint32_t block_size = ext4_sb_get_block_size(sb);
	uint16_t entry_len = ext4_dir_en_get_entry_len(dirent);
	int count_offset;


	if (entry_len == 12) {
		root = (struct ext4_dir_idx_root *)dirent;
		dp = (struct ext4_dir_en *)&root->dots[1];
		if (ext4_dir_en_get_entry_len(dp) != (block_size - 12))
			return NULL;
		if (root->info.reserved_zero)
			return NULL;
		if (root->info.info_length != sizeof(struct ext4_dir_idx_rinfo))
			return NULL;
		count_offset = 32;
	} else if (entry_len == block_size) {
		count_offset = 8;
	} else {
		return NULL;
	}

	if (offset)
		*offset = count_offset;
	return (struct ext4_dir_idx_climit *)(((char *)dirent) + count_offset);
}

/*
 * BIG FAT NOTES:
 *       Currently we do not verify the checksum of HTree node.
 */
static bool luca_dir_dx_csum_verify(luca_inode_ref_t *inode_ref,
				    struct ext4_dir_en *de)
{
	luca_sblock_t *sb = &inode_ref->fs->sb;
	uint32_t block_size = ext4_sb_get_block_size(sb);
	int coff, limit, cnt;

	if (ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM)) {
		struct ext4_dir_idx_climit *climit;
		climit = luca_dir_dx_get_climit(inode_ref, de, &coff);
		if (!climit) {
			/* Directory seems corrupted. */
			return true;
		}
		struct ext4_dir_idx_tail *t;
		// limit = ext4_dir_dx_climit_get_limit(climit);
		limit = to_le16(climit->limit);
		// cnt = ext4_dir_dx_climit_get_count(climit);
		cnt = to_le16(climit->count);
		if (coff + (limit * sizeof(struct ext4_dir_idx_entry)) >
		    (block_size - sizeof(struct ext4_dir_idx_tail))) {
			/* There is no space to hold the checksum */
			return true;
		}
		t = (ext4_dir_idx_tail *)(((struct ext4_dir_idx_entry *)climit) + limit);

		uint32_t c;
		c = to_le32(luca_dir_dx_checksum(inode_ref, de, coff, cnt, t));
		if (t->checksum != c)
			return false;
	}
	return true;
}


static void luca_dir_set_dx_csum(luca_inode_ref_t *inode_ref,
				 struct ext4_dir_en *dirent)
{
	int coff, limit, count;
	struct ext4_sblock *sb = &inode_ref->fs->sb;
	uint32_t block_size = ext4_sb_get_block_size(sb);

	if (ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM)) {
		struct ext4_dir_idx_climit *climit;
		climit = luca_dir_dx_get_climit(inode_ref, dirent, &coff);
		if (!climit) {
			/* Directory seems corrupted. */
			return;
		}
		struct ext4_dir_idx_tail *t;
		// limit = ext4_dir_dx_climit_get_limit(climit);
		limit = to_le16(climit->limit);
		// count = ext4_dir_dx_climit_get_count(climit);
		count = to_le16(climit->count);
		if (coff + (limit * sizeof(struct ext4_dir_idx_entry)) >
		   (block_size - sizeof(struct ext4_dir_idx_tail))) {
			/* There is no space to hold the checksum */
			return;
		}

		t = (ext4_dir_idx_tail *)(((struct ext4_dir_idx_entry *)climit) + limit);
		t->checksum = to_le32(luca_dir_dx_checksum(inode_ref, dirent,
					coff, count, t));
	}
}
#else
#define ext4_dir_dx_csum_verify(...) true
#define ext4_dir_set_dx_csum(...)
#endif

int luca_dir_dx_init(luca_inode_ref_t *dir, luca_inode_ref_t *parent)
{
	/* Load block 0, where will be index root located */
	ext4_fsblk_t fblock;
	uint32_t iblock = 0;
	bool need_append =
		(luca_inode_get_size(&dir->fs->sb, dir->inode)
			< EXT4_DIR_DX_INIT_BCNT)
		? true : false;
	struct ext4_sblock *sb = &dir->fs->sb;
	uint32_t block_size = ext4_sb_get_block_size(&dir->fs->sb);
	struct luca_block block;

	int rc;

	if (!need_append)
		rc = luca_fs_get_inode_dblk_idx_internal(dir, iblock, &fblock, true, true);
		//rc = ext4_fs_init_inode_dblk_idx(dir, iblock, &fblock);
	else
		rc = luca_fs_append_inode_dblk(dir, &fblock, &iblock);

	if (rc != EOK)
		return rc;

	rc = luca_trans_block_get_noread(dir->fs->bdev, &block, fblock);
	if (rc != EOK)
		return rc;

	/* Initialize pointers to data structures */
	struct ext4_dir_idx_root *root = (ext4_dir_idx_root *)block.data;
	struct ext4_dir_idx_rinfo *info = &(root->info);

	memset(root, 0, sizeof(struct ext4_dir_idx_root));
	struct ext4_dir_en *de;

	/* Initialize dot entries */
	de = (struct ext4_dir_en *)root->dots;
	luca_dir_write_entry(sb, de, 12, dir, ".", strlen("."));

	de = (struct ext4_dir_en *)(root->dots + 1);
	uint16_t elen = block_size - 12;
	luca_dir_write_entry(sb, de, elen, parent, "..", strlen(".."));

	/* Initialize root info structure */
	uint8_t hash_version = ext4_get8(&dir->fs->sb, default_hash_version);

	// ext4_dir_dx_rinfo_set_hash_version(info, hash_version);
	// ext4_dir_dx_rinfo_set_indirect_levels(info, 0);
	// ext4_dir_dx_root_info_set_info_length(info, 8);
	info->hash_version = hash_version;
	info->indirect_levels = 0;
	info->info_length = 8;

	/* Set limit and current number of entries */
	struct ext4_dir_idx_climit *climit;
	climit = (struct ext4_dir_idx_climit *)&root->en;

	ext4_dir_dx_climit_set_count(climit, 1);

	uint32_t entry_space;
	entry_space = block_size - 2 * sizeof(struct ext4_dir_idx_dot_en) -
			sizeof(struct ext4_dir_idx_rinfo);

	if (ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM))
		entry_space -= sizeof(struct ext4_dir_idx_tail);

	uint16_t root_limit = entry_space / sizeof(struct ext4_dir_idx_entry);
	printf("root_limit: %d\n", root_limit);
	ext4_dir_dx_climit_set_limit(climit, root_limit);

	/* Append new block, where will be new entries inserted in the future */
	iblock++;
	if (!need_append)
		rc = luca_fs_get_inode_dblk_idx_internal(dir, iblock, &fblock, true, true);
		// rc = ext4_fs_init_inode_dblk_idx(dir, iblock, &fblock);
	else
		rc = luca_fs_append_inode_dblk(dir, &fblock, &iblock);

	if (rc != EOK) {
		luca_block_set(dir->fs->bdev, &block);
		return rc;
	}

	struct luca_block new_block;
	rc = luca_trans_block_get_noread(dir->fs->bdev, &new_block, fblock);
	if (rc != EOK) {
		luca_block_set(dir->fs->bdev, &block);
		return rc;
	}

	/* Fill the whole block with empty entry */
	struct ext4_dir_en *be = (ext4_dir_en *)new_block.data;

	ext4_dir_en_set_inode(be, 0);

	if (ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM)) {
		uint16_t len = block_size - sizeof(struct ext4_dir_entry_tail);
		ext4_dir_en_set_entry_len(be, len);
		ext4_dir_en_set_name_len(sb, be, 0);
		ext4_dir_en_set_inode_type(sb, be, EXT4_DE_UNKNOWN);
		ext4_dir_init_entry_tail(EXT4_DIRENT_TAIL(be, block_size));
		luca_dir_set_csum(dir, be);
	} else {
		ext4_dir_en_set_entry_len(be, block_size);
	}

	//ext4_trans_set_block_dirty(new_block.buf);
	luca_bcache_set_dirty(new_block.buf);
	rc = luca_block_set(dir->fs->bdev, &new_block);
	if (rc != EOK) {
		luca_block_set(dir->fs->bdev, &block);
		return rc;
	}

	/* Connect new block to the only entry in index */
	struct ext4_dir_idx_entry *entry = root->en;
	ext4_dir_dx_entry_set_block(entry, iblock);

	luca_dir_set_dx_csum(dir, (struct ext4_dir_en *)block.data);
	//ext4_trans_set_block_dirty(block.buf);
	luca_bcache_set_dirty(block.buf);

	return luca_block_set(dir->fs->bdev, &block);
}

static int luca_dir_hinfo_init(struct ext4_hash_info *hinfo,
			       struct luca_block *root_block,
			       luca_sblock_t *sb, size_t name_len,
			       const char *name)
{
	struct ext4_dir_idx_root *root;

	root = (struct ext4_dir_idx_root *)root_block->data;
	if ((root->info.hash_version != EXT2_HTREE_LEGACY) &&
	    (root->info.hash_version != EXT2_HTREE_HALF_MD4) &&
	    (root->info.hash_version != EXT2_HTREE_TEA))
		return EXT4_ERR_BAD_DX_DIR;

	/* Check unused flags */
	if (root->info.unused_flags != 0)
		return EXT4_ERR_BAD_DX_DIR;

	/* Check indirect levels */
	if (root->info.indirect_levels > 1)
		return EXT4_ERR_BAD_DX_DIR;

	/* Check if node limit is correct */
	uint32_t block_size = ext4_sb_get_block_size(sb);
	uint32_t entry_space = block_size;
	entry_space -= 2 * sizeof(struct ext4_dir_idx_dot_en);
	entry_space -= sizeof(struct ext4_dir_idx_rinfo);
	if (ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM))
		entry_space -= sizeof(struct ext4_dir_idx_tail);
	entry_space = entry_space / sizeof(struct ext4_dir_idx_entry);

	struct ext4_dir_idx_climit *climit = (ext4_dir_idx_climit *)&root->en;
	// uint16_t limit = ext4_dir_dx_climit_get_limit(climit);
	uint16_t limit = to_le16(climit->limit);
	
	if (limit != entry_space)
		return EXT4_ERR_BAD_DX_DIR;

	/* Check hash version and modify if necessary */
	hinfo->hash_version = root->info.hash_version;
	//ext4_dir_dx_rinfo_get_hash_version(&root->info);
	if ((hinfo->hash_version <= EXT2_HTREE_TEA) &&
	    (ext4_sb_check_flag(sb, EXT4_SUPERBLOCK_FLAGS_UNSIGNED_HASH))) {
		/* Use unsigned hash */
		hinfo->hash_version += 3;
	}

	/* Load hash seed from superblock */
	hinfo->seed = ext4_get8(sb, hash_seed);

	/* Compute hash value of name */
	if (name)
		return ext2_htree_hash(name, name_len, hinfo->seed, hinfo->hash_version,
			       &hinfo->hash, &hinfo->minor_hash);
		//return ext4_dir_dx_hash_string(hinfo, name_len, name);

	return EOK;
}

static int luca_dir_dx_get_leaf(struct ext4_hash_info *hinfo,
				luca_inode_ref_t *inode_ref,
				struct luca_block *root_block,
				struct luca_dir_idx_block **dx_block,
				struct luca_dir_idx_block *dx_blocks)
{
	struct ext4_dir_idx_root *root;
	struct ext4_dir_idx_entry *entries;
	struct ext4_dir_idx_entry *p;
	struct ext4_dir_idx_entry *q;
	struct ext4_dir_idx_entry *m;
	struct ext4_dir_idx_entry *at;
	ext4_fsblk_t fblk;
	uint32_t block_size;
	uint16_t limit;
	uint16_t entry_space;
	uint8_t ind_level;
	int r;

	struct luca_dir_idx_block *tmp_dx_blk = dx_blocks;
	struct luca_block *tmp_blk = root_block;
	luca_sblock_t *sb = &inode_ref->fs->sb;

	block_size = ext4_sb_get_block_size(sb);
	root = (struct ext4_dir_idx_root *)root_block->data;

	//struct ext4_dir_idx_climit *entries;
	entries = (ext4_dir_idx_entry *)&root->en;

	limit = ext4_dir_dx_climit_get_limit((ext4_dir_idx_climit *)entries);
	//limit = to_le16((ext4_dir_idx_climit *)entries->limit);
	//ind_level = ext4_dir_dx_rinfo_get_indirect_levels(&root->info);
	ind_level = root->info.indirect_levels;

	/* Walk through the index tree */
	while (true) {
		uint16_t cnt = ext4_dir_dx_climit_get_count((ext4_dir_idx_climit *)entries);
		
		if ((cnt == 0) || (cnt > limit))
		{
			printf("cnt: %d limit: %d\n", cnt, limit);
			return EXT4_ERR_BAD_DX_DIR;
		}
		/* Do binary search in every node */
		p = entries + 1;
		q = entries + cnt - 1;

		while (p <= q) {
			m = p + (q - p) / 2;
			if (ext4_dir_dx_entry_get_hash(m) > hinfo->hash)
				q = m - 1;
			else
				p = m + 1;
		}

		at = p - 1;

		/* Write results */
		memcpy(&tmp_dx_blk->b, tmp_blk, sizeof(struct ext4_block));
		tmp_dx_blk->entries = entries;
		tmp_dx_blk->position = at;

		/* Is algorithm in the leaf? */
		if (ind_level == 0) {
			*dx_block = tmp_dx_blk;
			return EOK;
		}

		/* Goto child node */
		uint32_t n_blk = ext4_dir_dx_entry_get_block(at);

		ind_level--;

		//r = ext4_fs_get_inode_dblk_idx(inode_ref, n_blk, &fblk, false);
		r = luca_fs_get_inode_dblk_idx_internal(inode_ref, n_blk, &fblk, false, false);
		if (r != EOK)
			return r;

		r = luca_block_get(inode_ref->fs->bdev, tmp_blk, fblk);
		if (r != EOK)
			return r;

		entries = ((struct ext4_dir_idx_node *)tmp_blk->data)->entries;
		limit = ext4_dir_dx_climit_get_limit((ext4_dir_idx_climit *)entries);

		entry_space = block_size - sizeof(struct ext4_fake_dir_entry);
		if (ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM))
			entry_space -= sizeof(struct ext4_dir_idx_tail);

		entry_space = entry_space / sizeof(struct ext4_dir_idx_entry);

		if (limit != entry_space) {
			luca_block_set(inode_ref->fs->bdev, tmp_blk);
			printf("limit: %d entry_space: %d\n", limit, entry_space);
			return EXT4_ERR_BAD_DX_DIR;
		}

		if (!luca_dir_dx_csum_verify(inode_ref, (ext4_dir_en *)tmp_blk->data)) {
			ext4_dbg(DEBUG_DIR_IDX,
					DBG_WARN "HTree checksum failed."
					"Inode: %" PRIu32", "
					"Block: %" PRIu32"\n",
					inode_ref->index,
					n_blk);
		}

		++tmp_dx_blk;
	}

	/* Unreachable */
	return EOK;
}

static int luca_dir_dx_next_block(luca_inode_ref_t *inode_ref,
				  uint32_t hash,
				  struct luca_dir_idx_block *dx_block,
				  struct luca_dir_idx_block *dx_blocks)
{
	int r;
	uint32_t num_handles = 0;
	ext4_fsblk_t blk_adr;
	struct luca_dir_idx_block *p = dx_block;

	/* Try to find data block with next bunch of entries */
	while (true) {
		uint16_t cnt = ext4_dir_dx_climit_get_count((ext4_dir_idx_climit *)p->entries);

		p->position++;
		if (p->position < p->entries + cnt)
			break;

		if (p == dx_blocks)
			return EOK;

		num_handles++;
		p--;
	}

	/* Check hash collision (if not occurred - no next block cannot be
	 * used)*/
	uint32_t current_hash = ext4_dir_dx_entry_get_hash(p->position);
	if ((hash & 1) == 0) {
		if ((current_hash & ~1) != hash)
			return 0;
	}

	/* Fill new path */
	while (num_handles--) {
		uint32_t blk = ext4_dir_dx_entry_get_block(p->position);
		// r = ext4_fs_get_inode_dblk_idx(inode_ref, blk, &blk_adr, false);
		r = luca_fs_get_inode_dblk_idx_internal(inode_ref, blk, &blk_adr, false, false);
		if (r != EOK)
			return r;

		struct luca_block b;
		r = luca_block_get(inode_ref->fs->bdev, &b, blk_adr);
		if (r != EOK)
			return r;

		if (!luca_dir_dx_csum_verify(inode_ref, (ext4_dir_en *)b.data)) {
			ext4_dbg(DEBUG_DIR_IDX,
					DBG_WARN "HTree checksum failed."
					"Inode: %" PRIu32", "
					"Block: %" PRIu32"\n",
					inode_ref->index,
					blk);
		}

		p++;

		/* Don't forget to put old block (prevent memory leak) */
		r = luca_block_set(inode_ref->fs->bdev, &p->b);
		if (r != EOK)
			return r;

		memcpy(&p->b, &b, sizeof(b));
		p->entries = ((struct ext4_dir_idx_node *)b.data)->entries;
		p->position = p->entries;
	}

	return ENOENT;
}

int luca_dir_dx_find_entry(luca_dir_search_result *result,
			   luca_inode_ref_t *inode_ref, size_t name_len,
			   const char *name)
{
	/* Load direct block 0 (index root) */
	ext4_fsblk_t root_block_addr;
	int rc2;
	int rc;
	//rc = ext4_fs_get_inode_dblk_idx(inode_ref,  0, &root_block_addr, false);
	rc = luca_fs_get_inode_dblk_idx_internal(inode_ref, 0, &root_block_addr, false, false);
	if (rc != EOK)
	{
		printf("luca_fs_get_inode_dblk_idx_internal failed\n");
		return rc;
	}
	luca_fs_t *fs = inode_ref->fs;

	struct luca_block root_block;
	rc = luca_block_get(fs->bdev, &root_block, root_block_addr);
	if (rc != EOK)
		return rc;

	if (!luca_dir_dx_csum_verify(inode_ref, (ext4_dir_en *)root_block.data)) {
		ext4_dbg(DEBUG_DIR_IDX,
			 DBG_WARN "HTree root checksum failed."
			 "Inode: %" PRIu32", "
			 "Block: %" PRIu32"\n",
			 inode_ref->index,
			 (uint32_t)0);
	}

	/* Initialize hash info (compute hash value) */
	struct ext4_hash_info hinfo;
	rc = luca_dir_hinfo_init(&hinfo, &root_block, &fs->sb, name_len, name);
	if (rc != EOK) {
		luca_block_set(fs->bdev, &root_block);
		printf("luca_dir_hinfo_init failed\n");
		return EXT4_ERR_BAD_DX_DIR;
	}

	/*
	 * Hardcoded number 2 means maximum height of index tree,
	 * specified in the Linux driver.
	 */
	struct luca_dir_idx_block dx_blocks[2];
	struct luca_dir_idx_block *dx_block;
	struct luca_dir_idx_block *tmp;

	// printf("luca_dir_dx_find_entry: hash: %x\n", hinfo.hash);
	rc = luca_dir_dx_get_leaf(&hinfo, inode_ref, &root_block, &dx_block,
				  dx_blocks);
	if (rc != EOK) {
		luca_block_set(fs->bdev, &root_block);
		printf("luca_dir_dx_get_leaf failed\n");
		return EXT4_ERR_BAD_DX_DIR;
	}

	do {
		/* Load leaf block */
		uint32_t leaf_blk_idx;
		ext4_fsblk_t leaf_block_addr;
		struct luca_block b;

		leaf_blk_idx = ext4_dir_dx_entry_get_block(dx_block->position);
		// rc = ext4_fs_get_inode_dblk_idx(inode_ref, leaf_blk_idx,
		// 				&leaf_block_addr, false);
		rc = luca_fs_get_inode_dblk_idx_internal(inode_ref, leaf_blk_idx,
						&leaf_block_addr, false, false);
		if (rc != EOK)
			goto cleanup;

		rc = luca_block_get(fs->bdev, &b, leaf_block_addr);
		if (rc != EOK)
			goto cleanup;

		if (!luca_dir_csum_verify(inode_ref, (ext4_dir_en *)b.data)) {
			ext4_dbg(DEBUG_DIR_IDX,
				 DBG_WARN "HTree leaf block checksum failed."
				 "Inode: %" PRIu32", "
				 "Block: %" PRIu32"\n",
				 inode_ref->index,
				 leaf_blk_idx);
		}

		/* Linear search inside block */
		struct ext4_dir_en *de;
		rc = luca_dir_find_in_block(&b, &fs->sb, name_len, name, &de);

		/* Found => return it */
		if (rc == EOK) {
			result->block = b;
			result->dentry = de;
			goto cleanup;
		}

		/* Not found, leave untouched */
		rc2 = luca_block_set(fs->bdev, &b);
		if (rc2 != EOK)
			goto cleanup;

		if (rc != ENOENT)
			goto cleanup;

		/* check if the next block could be checked */
		rc = luca_dir_dx_next_block(inode_ref, hinfo.hash, dx_block,
					    &dx_blocks[0]);
		if (rc < 0)
			goto cleanup;
	} while (rc == ENOENT);

	/* Entry not found */
	rc = ENOENT;

cleanup:
	/* The whole path must be released (preventing memory leak) */
	tmp = dx_blocks;

	while (tmp <= dx_block) {
		rc2 = luca_block_set(fs->bdev, &tmp->b);
		if (rc == EOK && rc2 != EOK)
			rc = rc2;
		++tmp;
	}

	return rc;
}

static int luca_dir_dx_entry_comparator(const void *arg1, const void *arg2)
{
	struct ext4_dx_sort_entry *entry1 = (ext4_dx_sort_entry *)arg1;
	struct ext4_dx_sort_entry *entry2 = (ext4_dx_sort_entry *)arg2;

	if (entry1->hash == entry2->hash)
		return 0;

	if (entry1->hash < entry2->hash)
		return -1;
	else
		return 1;
}

static void
luca_dir_dx_insert_entry(luca_inode_ref_t *inode_ref __unused,
			 struct luca_dir_idx_block *index_block,
			 uint32_t hash, uint32_t iblock)
{
	struct ext4_dir_idx_entry *old_index_entry = index_block->position;
	struct ext4_dir_idx_entry *new_index_entry = old_index_entry + 1;
	struct ext4_dir_idx_climit *climit = (ext4_dir_idx_climit *)index_block->entries;
	struct ext4_dir_idx_entry *start_index = index_block->entries;
	uint32_t count = ext4_dir_dx_climit_get_count(climit);

	size_t bytes;
	bytes = (uint8_t *)(start_index + count) - (uint8_t *)(new_index_entry);

	memmove(new_index_entry + 1, new_index_entry, bytes);

	ext4_dir_dx_entry_set_block(new_index_entry, iblock);
	ext4_dir_dx_entry_set_hash(new_index_entry, hash);
	ext4_dir_dx_climit_set_count(climit, count + 1);
	luca_dir_set_dx_csum(inode_ref, (ext4_dir_en *)index_block->b.data);
	//ext4_trans_set_block_dirty(index_block->b.buf);
	luca_bcache_set_dirty(index_block->b.buf);
}

/**@brief Split directory entries to two parts preventing node overflow.
 * @param inode_ref      Directory i-node
 * @param hinfo          Hash info
 * @param old_data_block Block with data to be split
 * @param index_block    Block where index entries are located
 * @param new_data_block Output value for newly allocated data block
 */
static int luca_dir_dx_split_data(luca_inode_ref_t *inode_ref,
				  struct ext4_hash_info *hinfo,
				  struct luca_block *old_data_block,
				  struct luca_dir_idx_block *index_block,
				  struct luca_block *new_data_block)
{
	int rc = EOK;
	struct ext4_sblock *sb = &inode_ref->fs->sb;
	uint32_t block_size = ext4_sb_get_block_size(&inode_ref->fs->sb);

	/* Allocate buffer for directory entries */
	uint8_t *entry_buffer = (uint8_t *)ext4_malloc(block_size);
	if (entry_buffer == NULL)
		return ENOMEM;

	/* dot entry has the smallest size available */
	uint32_t max_ecnt = block_size / sizeof(struct ext4_dir_idx_dot_en);

	/* Allocate sort entry */
	struct ext4_dx_sort_entry *sort;

	sort = (ext4_dx_sort_entry *)ext4_malloc(max_ecnt * sizeof(ext4_dx_sort_entry));
	if (sort == NULL) {
		ext4_free(entry_buffer);
		return ENOMEM;
	}

	uint32_t idx = 0;
	uint32_t real_size = 0;

	/* Initialize hinfo */
	struct ext4_hash_info hinfo_tmp;
	memcpy(&hinfo_tmp, hinfo, sizeof(struct ext4_hash_info));

	/* Load all valid entries to the buffer */
	struct ext4_dir_en *de = (ext4_dir_en *)old_data_block->data;
	uint8_t *entry_buffer_ptr = entry_buffer;
	while ((void *)de < (void *)(old_data_block->data + block_size)) {
		/* Read only valid entries */
		if (ext4_dir_en_get_inode(de) && de->name_len) {
			uint16_t len = ext4_dir_en_get_name_len(sb, de);
			// rc = ext4_dir_dx_hash_string(&hinfo_tmp, len,
			// 			     (char *)de->name);
			rc = ext2_htree_hash((char *)de->name, len, hinfo_tmp.seed, hinfo_tmp.hash_version,
			                    &hinfo_tmp.hash, &hinfo_tmp.minor_hash); 
			if (rc != EOK) {
				ext4_free(sort);
				ext4_free(entry_buffer);
				return rc;
			}

			uint32_t rec_len = 8 + len;
			if ((rec_len % 4) != 0)
				rec_len += 4 - (rec_len % 4);

			memcpy(entry_buffer_ptr, de, rec_len);

			sort[idx].dentry = entry_buffer_ptr;
			sort[idx].rec_len = rec_len;
			sort[idx].hash = hinfo_tmp.hash;

			entry_buffer_ptr += rec_len;
			real_size += rec_len;
			idx++;
		}

		size_t elen = ext4_dir_en_get_entry_len(de);
		de = (ext4_dir_en *)((uint8_t *)de + elen);
	}

	qsort(sort, idx, sizeof(struct ext4_dx_sort_entry),
	      luca_dir_dx_entry_comparator);

	/* Allocate new block for store the second part of entries */
	ext4_fsblk_t new_fblock;
	uint32_t new_iblock;
	rc = luca_fs_append_inode_dblk(inode_ref, &new_fblock, &new_iblock);
	if (rc != EOK) {
		ext4_free(sort);
		ext4_free(entry_buffer);
		return rc;
	}

	/* Load new block */
	struct luca_block new_data_block_tmp;
	rc = luca_trans_block_get_noread(inode_ref->fs->bdev, &new_data_block_tmp,
				   new_fblock);
	if (rc != EOK) {
		ext4_free(sort);
		ext4_free(entry_buffer);
		return rc;
	}

	/*
	 * Distribute entries to two blocks (by size)
	 * - compute the half
	 */
	uint32_t new_hash = 0;
	uint32_t current_size = 0;
	uint32_t mid = 0;
	uint32_t i;
	for (i = 0; i < idx; ++i) {
		if ((current_size + sort[i].rec_len) > (block_size / 2)) {
			new_hash = sort[i].hash;
			mid = i;
			break;
		}

		current_size += sort[i].rec_len;
	}

	/* Check hash collision */
	uint32_t continued = 0;
	if (new_hash == sort[mid - 1].hash)
		continued = 1;

	uint32_t off = 0;
	void *ptr;
	if (ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM))
		block_size -= sizeof(struct ext4_dir_entry_tail);

	/* First part - to the old block */
	for (i = 0; i < mid; ++i) {
		ptr = old_data_block->data + off;
		memcpy(ptr, sort[i].dentry, sort[i].rec_len);

		struct ext4_dir_en *t = (ext4_dir_en *)ptr;
		if (i < (mid - 1))
			ext4_dir_en_set_entry_len(t, sort[i].rec_len);
		else
			ext4_dir_en_set_entry_len(t, block_size - off);

		off += sort[i].rec_len;
	}

	/* Second part - to the new block */
	off = 0;
	for (i = mid; i < idx; ++i) {
		ptr = new_data_block_tmp.data + off;
		memcpy(ptr, sort[i].dentry, sort[i].rec_len);

		struct ext4_dir_en *t = (ext4_dir_en *)ptr;
		if (i < (idx - 1))
			ext4_dir_en_set_entry_len(t, sort[i].rec_len);
		else
			ext4_dir_en_set_entry_len(t, block_size - off);

		off += sort[i].rec_len;
	}

	block_size = ext4_sb_get_block_size(&inode_ref->fs->sb);

	/* Do some steps to finish operation */
	sb = &inode_ref->fs->sb;
	if (ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM)) {
		struct ext4_dir_entry_tail *t;

		t = EXT4_DIRENT_TAIL(old_data_block->data, block_size);
		ext4_dir_init_entry_tail(t);
		t = EXT4_DIRENT_TAIL(new_data_block_tmp.data, block_size);
		ext4_dir_init_entry_tail(t);
	}
	luca_dir_set_csum(inode_ref, (ext4_dir_en *)old_data_block->data);
	luca_dir_set_csum(inode_ref, (ext4_dir_en *)new_data_block_tmp.data);
	// ext4_trans_set_block_dirty(old_data_block->buf);
	luca_bcache_set_dirty(old_data_block->buf);
	// ext4_trans_set_block_dirty(new_data_block_tmp.buf);
	luca_bcache_set_dirty(new_data_block_tmp.buf);

	ext4_free(sort);
	ext4_free(entry_buffer);

	luca_dir_dx_insert_entry(inode_ref, index_block, new_hash + continued,
				new_iblock);

	*new_data_block = new_data_block_tmp;
	return EOK;
}

/**@brief  Split index node and maybe some parent nodes in the tree hierarchy.
 * @param ino_ref Directory i-node
 * @param dx_blks Array with path from root to leaf node
 * @param dxb  Leaf block to be split if needed
 * @return Error code
 */
static int
luca_dir_dx_split_index(luca_inode_ref_t *ino_ref,
			struct luca_dir_idx_block *dx_blks,
			struct luca_dir_idx_block *dxb,
			struct luca_dir_idx_block **new_dx_block)
{
	luca_sblock_t *sb = &ino_ref->fs->sb;
	struct ext4_dir_idx_entry *e;
	int r;

	uint32_t block_size = ext4_sb_get_block_size(&ino_ref->fs->sb);
	uint32_t entry_space = block_size - sizeof(struct ext4_fake_dir_entry);
	uint32_t node_limit =  entry_space / sizeof(struct ext4_dir_idx_entry);

	bool meta_csum = ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM);

	if (dxb == dx_blks)
		e = ((struct ext4_dir_idx_root *)dxb->b.data)->en;
	else
		e = ((struct ext4_dir_idx_node *)dxb->b.data)->entries;

	struct ext4_dir_idx_climit *climit = (struct ext4_dir_idx_climit *)e;

	uint16_t leaf_limit = ext4_dir_dx_climit_get_limit(climit);
	uint16_t leaf_count = ext4_dir_dx_climit_get_count(climit);

	/* Check if is necessary to split index block */
	if (leaf_limit == leaf_count) {
		struct ext4_dir_idx_entry *ren;
		ptrdiff_t levels = dxb - dx_blks;

		ren = ((struct ext4_dir_idx_root *)dx_blks[0].b.data)->en;
		struct ext4_dir_idx_climit *rclimit = (ext4_dir_idx_climit *)ren;
		uint16_t root_limit = ext4_dir_dx_climit_get_limit(rclimit);
		uint16_t root_count = ext4_dir_dx_climit_get_count(rclimit);


		/* Linux limitation */
		if ((levels > 0) && (root_limit == root_count))
			return ENOSPC;

		/* Add new block to directory */
		ext4_fsblk_t new_fblk;
		uint32_t new_iblk;
		r = luca_fs_append_inode_dblk(ino_ref, &new_fblk, &new_iblk);
		if (r != EOK)
			return r;

		/* load new block */
		struct luca_block b;
		r = luca_trans_block_get_noread(ino_ref->fs->bdev, &b, new_fblk);
		if (r != EOK)
			return r;

		struct ext4_dir_idx_node *new_node = (ext4_dir_idx_node *)b.data;
		struct ext4_dir_idx_entry *new_en = new_node->entries;

		memset(&new_node->fake, 0, sizeof(struct ext4_fake_dir_entry));
		new_node->fake.entry_length = block_size;

		/* Split leaf node */
		if (levels > 0) {
			uint32_t count_left = leaf_count / 2;
			uint32_t count_right = leaf_count - count_left;
			uint32_t hash_right;
			size_t sz;

			struct ext4_dir_idx_climit *left_climit;
			struct ext4_dir_idx_climit *right_climit;

			hash_right = ext4_dir_dx_entry_get_hash(e + count_left);
			/* Copy data to new node */
			sz = count_right * sizeof(struct ext4_dir_idx_entry);
			memcpy(new_en, e + count_left, sz);

			/* Initialize new node */
			left_climit = (struct ext4_dir_idx_climit *)e;
			right_climit = (struct ext4_dir_idx_climit *)new_en;

			ext4_dir_dx_climit_set_count(left_climit, count_left);
			ext4_dir_dx_climit_set_count(right_climit, count_right);

			if (meta_csum)
			{
				entry_space -= sizeof(struct ext4_dir_idx_tail);
				node_limit = entry_space / sizeof(struct ext4_dir_idx_entry);
			}

			ext4_dir_dx_climit_set_limit(right_climit, node_limit);

			/* Which index block is target for new entry */
			uint32_t position_index =
			    (dxb->position - dxb->entries);
			if (position_index >= count_left) {
				luca_dir_set_dx_csum(
						ino_ref,
						(struct ext4_dir_en *)
						dxb->b.data);
				//ext4_trans_set_block_dirty(dxb->b.buf);
				luca_bcache_set_dirty(dxb->b.buf);

				struct luca_block block_tmp = dxb->b;

				dxb->b = b;

				dxb->position =
				    new_en + position_index - count_left;
				dxb->entries = new_en;

				b = block_tmp;
			}

			/* Finally insert new entry */
			luca_dir_dx_insert_entry(ino_ref, dx_blks, hash_right,
						 new_iblk);
			luca_dir_set_dx_csum(ino_ref, (ext4_dir_en *)dx_blks[0].b.data);
			luca_dir_set_dx_csum(ino_ref, (ext4_dir_en *)dx_blks[1].b.data);
			// ext4_trans_set_block_dirty(dx_blks[0].b.buf);
			// ext4_trans_set_block_dirty(dx_blks[1].b.buf);
			luca_bcache_set_dirty(dx_blks[0].b.buf);
			luca_bcache_set_dirty(dx_blks[1].b.buf);

			luca_dir_set_dx_csum(ino_ref, (ext4_dir_en *)b.data);
			// ext4_trans_set_block_dirty(b.buf);
			luca_bcache_set_dirty(b.buf);
			return luca_block_set(ino_ref->fs->bdev, &b);
		} else {
			size_t sz;
			/* Copy data from root to child block */
			sz = leaf_count * sizeof(struct ext4_dir_idx_entry);
			memcpy(new_en, e, sz);

			struct ext4_dir_idx_climit *new_climit = (ext4_dir_idx_climit *)new_en;
			if (meta_csum)
			{
				entry_space -= sizeof(struct ext4_dir_idx_tail);
				node_limit = entry_space / sizeof(struct ext4_dir_idx_entry);
			}

			ext4_dir_dx_climit_set_limit(new_climit, node_limit);

			/* Set values in root node */
			struct ext4_dir_idx_climit *new_root_climit = (ext4_dir_idx_climit *)e;

			ext4_dir_dx_climit_set_count(new_root_climit, 1);
			ext4_dir_dx_entry_set_block(e, new_iblk);

			struct ext4_dir_idx_root *r = (ext4_dir_idx_root *)dx_blks[0].b.data;
			r->info.indirect_levels = 1;

			/* Add new entry to the path */
			dxb = dx_blks + 1;
			dxb->position = dx_blks->position - e + new_en;
			dxb->entries = new_en;
			dxb->b = b;
			*new_dx_block = dxb;

			luca_dir_set_dx_csum(ino_ref, (ext4_dir_en *)dx_blks[0].b.data);
			luca_dir_set_dx_csum(ino_ref, (ext4_dir_en *)dx_blks[1].b.data);
			// ext4_trans_set_block_dirty(dx_blks[0].b.buf);
			// ext4_trans_set_block_dirty(dx_blks[1].b.buf);
			luca_bcache_set_dirty(dx_blks[0].b.buf);
			luca_bcache_set_dirty(dx_blks[1].b.buf);
		}
	}

	return EOK;
}

int luca_dir_dx_add_entry(luca_inode_ref_t *parent,
			  luca_inode_ref_t *child, const char *name, uint32_t name_len)
{
	int rc2 = EOK;
	int r;

	uint32_t leaf_block_idx;
	uint32_t blk_hash;
	/* Get direct block 0 (index root) */
	ext4_fsblk_t rblock_addr;
	// r =  ext4_fs_get_inode_dblk_idx(parent, 0, &rblock_addr, false);
	r = luca_fs_get_inode_dblk_idx_internal(parent, 0, &rblock_addr, false, false);
	if (r != EOK)
		return r;

	luca_fs_t *fs = parent->fs;
	struct luca_block root_blk;

	r = luca_block_get(fs->bdev, &root_blk, rblock_addr);
	if (r != EOK)
		return r;

	if (!luca_dir_dx_csum_verify(parent, (ext4_dir_en *)root_blk.data)) {
		ext4_dbg(DEBUG_DIR_IDX,
			 DBG_WARN "HTree root checksum failed."
			 "Inode: %" PRIu32", "
			 "Block: %" PRIu32"\n",
			 parent->index,
			 (uint32_t)0);
	}

	/* Initialize hinfo structure (mainly compute hash) */
	struct ext4_hash_info hinfo;
	r = luca_dir_hinfo_init(&hinfo, &root_blk, &fs->sb, name_len, name);
	if (r != EOK) {
		luca_block_set(fs->bdev, &root_blk);
		return EXT4_ERR_BAD_DX_DIR;
	}

	/*
	 * Hardcoded number 2 means maximum height of index
	 * tree defined in Linux.
	 */
	struct luca_dir_idx_block dx_blks[2];
	struct luca_dir_idx_block *dx_blk;
	struct luca_dir_idx_block *dx_it;

	r = luca_dir_dx_get_leaf(&hinfo, parent, &root_blk, &dx_blk, dx_blks);
	if (r != EOK) {
		r = EXT4_ERR_BAD_DX_DIR;
		goto release_index;
	}

	/* Try to insert to existing data block */
	leaf_block_idx = ext4_dir_dx_entry_get_block(dx_blk->position);
	ext4_fsblk_t leaf_block_addr;
	// r = ext4_fs_get_inode_dblk_idx(parent, leaf_block_idx,
	// 					&leaf_block_addr, false);
	r = luca_fs_get_inode_dblk_idx_internal(parent, leaf_block_idx,
						&leaf_block_addr, false, false);
	if (r != EOK)
		goto release_index;

	/*
	 * Check if there is needed to split index node
	 * (and recursively also parent nodes)
	 */
	r = luca_dir_dx_split_index(parent, dx_blks, dx_blk, &dx_blk);
	if (r != EOK)
		goto release_target_index;

	struct luca_block target_block;
	r = luca_block_get(fs->bdev, &target_block, leaf_block_addr);
	if (r != EOK)
		goto release_index;

	if (!luca_dir_csum_verify(parent,(ext4_dir_en *)target_block.data)) {
		ext4_dbg(DEBUG_DIR_IDX,
				DBG_WARN "HTree leaf block checksum failed."
				"Inode: %" PRIu32", "
				"Block: %" PRIu32"\n",
				parent->index,
				leaf_block_idx);
	}

	/* Check if insert operation passed */
	r = luca_dir_try_insert_entry(&fs->sb, parent, &target_block, child,
					name, name_len);
	if (r == EOK)
		goto release_target_index;

	/* Split entries to two blocks (includes sorting by hash value) */
	struct luca_block new_block;
	r = luca_dir_dx_split_data(parent, &hinfo, &target_block, dx_blk,
				    &new_block);
	if (r != EOK) {
		rc2 = r;
		goto release_target_index;
	}

	/* Where to save new entry */
	blk_hash = ext4_dir_dx_entry_get_hash(dx_blk->position + 1);
	if (hinfo.hash >= blk_hash)
		r = luca_dir_try_insert_entry(&fs->sb, parent, &new_block,
						child, name, name_len);
	else
		r = luca_dir_try_insert_entry(&fs->sb, parent, &target_block,
						child, name, name_len);

	/* Cleanup */
	r = luca_block_set(fs->bdev, &new_block);
	if (r != EOK)
		return r;

/* Cleanup operations */

release_target_index:
	rc2 = r;

	r = luca_block_set(fs->bdev, &target_block);
	if (r != EOK)
		return r;

release_index:
	if (r != EOK)
		rc2 = r;

	dx_it = dx_blks;

	while (dx_it <= dx_blk) {
		r = luca_block_set(fs->bdev, &dx_it->b);
		if (r != EOK)
			return r;

		dx_it++;
	}

	return rc2;
}

int luca_dir_dx_reset_parent_inode(luca_inode_ref_t *dir,
                                   uint32_t parent_inode)
{
	/* Load block 0, where will be index root located */
	ext4_fsblk_t fblock;
	// int rc = ext4_fs_get_inode_dblk_idx(dir, 0, &fblock, false);
	int rc = luca_fs_get_inode_dblk_idx_internal(dir, 0, &fblock, false, false);
	if (rc != EOK)
		return rc;

	struct luca_block block;
	rc = luca_block_get(dir->fs->bdev, &block, fblock);
	if (rc != EOK)
		return rc;

	if (!luca_dir_dx_csum_verify(dir, (ext4_dir_en *)block.data)) {
		ext4_dbg(DEBUG_DIR_IDX,
			 DBG_WARN "HTree root checksum failed."
			 "Inode: %" PRIu32", "
			 "Block: %" PRIu32"\n",
			 dir->index,
			 (uint32_t)0);
	}

	/* Initialize pointers to data structures */
	struct ext4_dir_idx_root *root = (ext4_dir_idx_root *)block.data;

	/* Fill the inode field with a new parent ino. */
	ext4_dx_dot_en_set_inode(&root->dots[1], parent_inode);

	luca_dir_set_dx_csum(dir, (ext4_dir_en *)block.data);
	//ext4_trans_set_block_dirty(block.buf);
	luca_bcache_set_dirty(block.buf);

	return luca_block_set(dir->fs->bdev, &block);
}










/*dir相关*/

static struct ext4_dir_entry_tail *
luca_dir_get_tail(luca_inode_ref_t *inode_ref,
		struct ext4_dir_en *de)
{
	struct ext4_dir_entry_tail *t;
	luca_sblock_t *sb = &inode_ref->fs->sb;

	t = EXT4_DIRENT_TAIL(de, ext4_sb_get_block_size(sb));

	if (t->reserved_zero1 || t->reserved_zero2)
		return NULL;
	if (to_le16(t->rec_len) != sizeof(struct ext4_dir_entry_tail))
		return NULL;
	if (t->reserved_ft != EXT4_DIRENTRY_DIR_CSUM)
		return NULL;

	return t;
}

#if CONFIG_META_CSUM_ENABLE
static uint32_t luca_dir_csum(luca_inode_ref_t *inode_ref,
			      struct ext4_dir_en *dirent, int size)
{
	uint32_t csum;
	struct ext4_sblock *sb = &inode_ref->fs->sb;
	uint32_t ino_index = to_le32(inode_ref->index);
	uint32_t ino_gen = to_le32(inode_ref->inode->generation);

	/* First calculate crc32 checksum against fs uuid */
	csum = ext4_crc32c(EXT4_CRC32_INIT, sb->uuid, sizeof(sb->uuid));
	/* Then calculate crc32 checksum against inode number
	 * and inode generation */
	csum = ext4_crc32c(csum, &ino_index, sizeof(ino_index));
	csum = ext4_crc32c(csum, &ino_gen, sizeof(ino_gen));
	/* Finally calculate crc32 checksum against directory entries */
	csum = ext4_crc32c(csum, dirent, size);
	return csum;
}
#else
#define ext4_dir_csum(...) 0
#endif

bool luca_dir_csum_verify(luca_inode_ref_t *inode_ref,
			      struct ext4_dir_en *dirent)
{
#ifdef CONFIG_META_CSUM_ENABLE
	struct ext4_dir_entry_tail *t;
	luca_sblock_t *sb = &inode_ref->fs->sb;

	/* Compute the checksum only if the filesystem supports it */
	if (ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM)) {
		t = luca_dir_get_tail(inode_ref, dirent);
		if (!t) {
			/* There is no space to hold the checksum */
			return false;
		}

		ptrdiff_t __unused diff = (char *)t - (char *)dirent;
		uint32_t csum = luca_dir_csum(inode_ref, dirent, diff);
		if (t->checksum != to_le32(csum))
			return false;

	}
#endif
	return true;
}

void luca_dir_init_entry_tail(struct ext4_dir_entry_tail *t)
{
	memset(t, 0, sizeof(struct ext4_dir_entry_tail));
	t->rec_len = to_le16(sizeof(struct ext4_dir_entry_tail));
	t->reserved_ft = EXT4_DIRENTRY_DIR_CSUM;
}

void luca_dir_set_csum(luca_inode_ref_t *inode_ref,
			   struct ext4_dir_en *dirent)
{
	struct ext4_dir_entry_tail *t;
	luca_sblock_t *sb = &inode_ref->fs->sb;

	/* Compute the checksum only if the filesystem supports it */
	if (ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM)) {
		t = luca_dir_get_tail(inode_ref, dirent);
		if (!t) {
			/* There is no space to hold the checksum */
			return;
		}

		ptrdiff_t __unused diff = (char *)t - (char *)dirent;
		uint32_t csum = luca_dir_csum(inode_ref, dirent, diff);
		t->checksum = to_le32(csum);
	}
}

static int luca_dir_iterator_set(struct luca_dir_iter *it,
				 uint32_t block_size)
{
	uint32_t off_in_block = it->curr_off % block_size;
	luca_sblock_t *sb = &it->inode_ref->fs->sb;

	it->curr = NULL;

	/* Ensure proper alignment */
	if ((off_in_block % 4) != 0)
		return EIO;

	/* Ensure that the core of the entry does not overflow the block */
	if (off_in_block > block_size - 8)
		return EIO;

	struct ext4_dir_en *en;
	en = (ext4_dir_en *)(it->curr_blk.data + off_in_block);

	/* Ensure that the whole entry does not overflow the block */
	uint16_t length = ext4_dir_en_get_entry_len(en);
	if (off_in_block + length > block_size)
		return EIO;

	/* Ensure the name length is not too large */
	if (ext4_dir_en_get_name_len(sb, en) > length - 8)
		return EIO;

	/* Everything OK - "publish" the entry */
	it->curr = en;
	return EOK;
}

static int luca_dir_iterator_seek(struct luca_dir_iter *it, uint64_t pos)
{
	luca_sblock_t *sb = &it->inode_ref->fs->sb;
	struct luca_inode *inode = it->inode_ref->inode;
	luca_blockdev_t *bdev = it->inode_ref->fs->bdev;
	uint64_t size = luca_inode_get_size(sb, inode);
	int r;

	/* The iterator is not valid until we seek to the desired position */
	it->curr = NULL;

	/* Are we at the end? */
	if (pos >= size) {
		if (it->curr_blk.lb_id) {

			r = luca_block_set(bdev, &it->curr_blk);
			it->curr_blk.lb_id = 0;
			if (r != EOK)
				return r;
		}

		it->curr_off = pos;
		return EOK;
	}

	/* Compute next block address */
	uint32_t block_size = ext4_sb_get_block_size(sb);
	uint64_t current_blk_idx = it->curr_off / block_size;
	uint32_t next_blk_idx = (uint32_t)(pos / block_size);

	/*
	 * If we don't have a block or are moving across block boundary,
	 * we need to get another block
	 */
	if ((it->curr_blk.lb_id == 0) ||
	    (current_blk_idx != next_blk_idx)) {
		if (it->curr_blk.lb_id) {
			r = luca_block_set(bdev, &it->curr_blk);
			it->curr_blk.lb_id = 0;

			if (r != EOK)
				return r;
		}

		ext4_fsblk_t next_blk;
		// r = ext4_fs_get_inode_dblk_idx(it->inode_ref, next_blk_idx,
		// 			       &next_blk, false);
		r = luca_fs_get_inode_dblk_idx_internal(it->inode_ref, next_blk_idx,
					       &next_blk, false, false);
		if (r != EOK)
			return r;

		r = luca_block_get(bdev, &it->curr_blk, next_blk);
		if (r != EOK) {
			it->curr_blk.lb_id = 0;
			return r;
		}
	}

	it->curr_off = pos;
	return luca_dir_iterator_set(it, block_size);
}

/*
9800x3d
4070tis 
*/

int luca_dir_iterator_init(struct luca_dir_iter *it,
			   luca_inode_ref_t *inode_ref, uint64_t pos)
{
	it->inode_ref = inode_ref;
	it->curr = 0;
	it->curr_off = 0;
	it->curr_blk.lb_id = 0;

	return luca_dir_iterator_seek(it, pos);
}

int luca_dir_iterator_next(luca_dir_iter *it)
{
	int r = EOK;
	uint16_t skip;

	while (r == EOK) {
		skip = ext4_dir_en_get_entry_len(it->curr);
		r = luca_dir_iterator_seek(it, it->curr_off + skip);

		if (!it->curr)
			break;
		/*Skip NULL referenced entry*/
		if (ext4_dir_en_get_inode(it->curr) != 0)
			break;
	}

	return r;
}

int luca_dir_iterator_fini(struct luca_dir_iter *it)
{
	it->curr = 0;

	if (it->curr_blk.lb_id)
		return luca_block_set(it->inode_ref->fs->bdev, &it->curr_blk);

	return EOK;
}

void luca_dir_write_entry(luca_sblock_t*sb, struct ext4_dir_en *en,
			  uint16_t entry_len, luca_inode_ref_t *child,
			  const char *name, size_t name_len)
{
	/* Check maximum entry length */
	ext4_assert(entry_len <= ext4_sb_get_block_size(sb));

	/* Set type of entry */
	switch (/*ext4_inode_type(sb, child->inode)*/
	 to_le16(child->inode->mode) & EXT4_INODE_MODE_TYPE_MASK) {
	case EXT4_INODE_MODE_DIRECTORY:
		ext4_dir_en_set_inode_type(sb, en, EXT4_DE_DIR);
		break;
	case EXT4_INODE_MODE_FILE:
		ext4_dir_en_set_inode_type(sb, en, EXT4_DE_REG_FILE);
		break;
	case EXT4_INODE_MODE_SOFTLINK:
		ext4_dir_en_set_inode_type(sb, en, EXT4_DE_SYMLINK);
		break;
	case EXT4_INODE_MODE_CHARDEV:
		ext4_dir_en_set_inode_type(sb, en, EXT4_DE_CHRDEV);
		break;
	case EXT4_INODE_MODE_BLOCKDEV:
		ext4_dir_en_set_inode_type(sb, en, EXT4_DE_BLKDEV);
		break;
	case EXT4_INODE_MODE_FIFO:
		ext4_dir_en_set_inode_type(sb, en, EXT4_DE_FIFO);
		break;
	case EXT4_INODE_MODE_SOCKET:
		ext4_dir_en_set_inode_type(sb, en, EXT4_DE_SOCK);
		break;
	default:
		/* FIXME: unsupported filetype */
		ext4_dir_en_set_inode_type(sb, en, EXT4_DE_UNKNOWN);
	}

	/* Set basic attributes */
	ext4_dir_en_set_inode(en, child->index);
	ext4_dir_en_set_entry_len(en, entry_len);
	ext4_dir_en_set_name_len(sb, en, (uint16_t)name_len);

	/* Write name */
	// printf("luca_dir_write_entry name_len:%d %s\n", name_len, name);
	memcpy(en->name, name, name_len);
}

int luca_dir_add_entry(luca_inode_ref_t *parent, const char *name,
		       uint32_t name_len, luca_inode_ref_t *child)
{
	int r;
	luca_fs_t *fs = parent->fs;
	struct ext4_sblock *sb = &parent->fs->sb;

#if CONFIG_DIR_INDEX_ENABLE
	/* Index adding (if allowed) */
	if ((ext4_sb_feature_com(sb, EXT4_FCOM_DIR_INDEX)) &&
		(to_le32(parent->inode->flags) & EXT4_INODE_FLAG_INDEX)) {
		r = luca_dir_dx_add_entry(parent, child, name, name_len);

		/* Check if index is not corrupted */
		if (r != EXT4_ERR_BAD_DX_DIR) {
			if (r != EOK)
				return r;

			return EOK;
		}

		/* Needed to clear dir index flag if corrupted */
		luca_inode_clear_flag(parent->inode, EXT4_INODE_FLAG_INDEX);
		parent->dirty = true;
	}
#endif

	// printf("luca_dir_add_entry: %s\n", name);
	/* Linear algorithm */
	uint32_t iblock = 0;
	ext4_fsblk_t fblock = 0;
	uint32_t block_size = ext4_sb_get_block_size(sb);
	uint64_t inode_size = luca_inode_get_size(sb, parent->inode);
	uint32_t total_blocks = (uint32_t)(inode_size / block_size);

	/* Find block, where is space for new entry and try to add */
	bool success = false;
	for (iblock = 0; iblock < total_blocks; ++iblock) {
		r = luca_fs_get_inode_dblk_idx_internal(parent, iblock, &fblock, false, false);
		// r = ext4_fs_get_inode_dblk_idx(parent, iblock, &fblock, false);
		if (r != EOK)
			return r;

		struct luca_block block;
		r = luca_block_get(fs->bdev, &block, fblock);
		if (r != EOK)
			return r;

		if (!luca_dir_csum_verify(parent, (ext4_dir_en *)block.data)) {
			ext4_dbg(DEBUG_DIR,
				 DBG_WARN "Leaf block checksum failed."
				 "Inode: %" PRIu32", "
				 "Block: %" PRIu32"\n",
				 parent->index,
				 iblock);
		}

		/* If adding is successful, function can finish */
		r = luca_dir_try_insert_entry(sb, parent, &block, child,
						name, name_len);
		if (r == EOK)
			success = true;

		r = luca_block_set(fs->bdev, &block);
		if (r != EOK)
			return r;

		if (success)
			return EOK;
	}

	/* No free block found - needed to allocate next data block */

	iblock = 0;
	fblock = 0;
	r = luca_fs_append_inode_dblk(parent, &fblock, &iblock);
	if (r != EOK)
		return r;

	/* Load new block */
	struct luca_block b;

	r = luca_trans_block_get_noread(fs->bdev, &b, fblock);
	if (r != EOK)
		return r;
 
	/* Fill block with zeroes */
	memset(b.data, 0, block_size);
	struct ext4_dir_en *blk_en = (ext4_dir_en *)b.data;

	/* Save new block */
	if (ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM)) {
		uint16_t el = block_size - sizeof(struct ext4_dir_entry_tail);
		luca_dir_write_entry(sb, blk_en, el, child, name, name_len);
		ext4_dir_init_entry_tail(EXT4_DIRENT_TAIL(b.data, block_size));
	} else {
		luca_dir_write_entry(sb, blk_en, block_size, child, name,
				name_len);
	}

	printf("luca_dir_add_entry name:%s\n", blk_en->name);

	luca_dir_set_csum(parent, (ext4_dir_en *)b.data);
	//ext4_trans_set_block_dirty(b.buf);
	luca_bcache_set_dirty(b.buf);
	r = luca_block_set(fs->bdev, &b);

	return r;
}

int luca_dir_find_entry(struct luca_dir_search_result *result,
			luca_inode_ref_t *parent, const char *name,
			uint32_t name_len)
{
	int r;
	struct ext4_sblock *sb = &parent->fs->sb;

	/* Entry clear */
	result->block.lb_id = 0;
	result->dentry = NULL;

#if CONFIG_DIR_INDEX_ENABLE
	/* Index search */
	// printf("ext4_sb_feature_com(sb, EXT4_FCOM_DIR_INDEX) :%d", 
	//  	ext4_sb_feature_com(sb, EXT4_FCOM_DIR_INDEX));
	// printf("ext4_inode_has_flag(parent->inode, EXT4_INODE_FLAG_INDEX):%d\n",
	// 	(to_le32(parent->inode->flags) & EXT4_INODE_FLAG_INDEX));

	if ((ext4_sb_feature_com(sb, EXT4_FCOM_DIR_INDEX)) &&
	    /*(ext4_inode_has_flag(parent->inode, EXT4_INODE_FLAG_INDEX)) &&*/
		 (to_le32(parent->inode->flags) & EXT4_INODE_FLAG_INDEX)) {
		// printf("luca_dir_index: %s\n", name);
		r = luca_dir_dx_find_entry(result, parent, name_len, name);
		/* Check if index is not corrupted */
		if (r != EXT4_ERR_BAD_DX_DIR) {
			// printf("不是坏的索引\n");
			if (r != EOK)
				return r;

			return EOK;
		}

		/* Needed to clear dir index flag if corrupted */
		luca_inode_clear_flag(parent->inode, EXT4_INODE_FLAG_INDEX);
		parent->dirty = true;
	}
#endif

	/* Linear algorithm */
	// printf("luca_dir_find_entry: %s\n", name);
	uint32_t iblock;
	ext4_fsblk_t fblock;
	uint32_t block_size = ext4_sb_get_block_size(sb);
	uint64_t inode_size = luca_inode_get_size(sb, parent->inode);
	uint32_t total_blocks = (uint32_t)(inode_size / block_size);

	/* Walk through all data blocks */
	for (iblock = 0; iblock < total_blocks; ++iblock) {
		/* Load block address */
		// r = ext4_fs_get_inode_dblk_idx(parent, iblock, &fblock, false);
		r = luca_fs_get_inode_dblk_idx_internal(parent, iblock, &fblock, false, false);
		if (r != EOK)
			return r;

		/* Load data block */
		struct luca_block b;
		r = luca_block_get(parent->fs->bdev, &b, fblock);
		if (r != EOK)
			return r;

		if (!luca_dir_csum_verify(parent, (ext4_dir_en *)b.data)) {
			ext4_dbg(DEBUG_DIR,
				 DBG_WARN "Leaf block checksum failed."
				 "Inode: %" PRIu32", "
				 "Block: %" PRIu32"\n",
				 parent->index,
				 iblock);
		}

		/* Try to find entry in block */
		struct ext4_dir_en *res_entry;
		r = luca_dir_find_in_block(&b, sb, name_len, name, &res_entry);
		if (r == EOK) {
			result->block = b;
			result->dentry = res_entry;
			return EOK;
		}

		/* Entry not found - put block and continue to the next block */

		r = luca_block_set(parent->fs->bdev, &b);
		if (r != EOK)
			return r;
	}

	return ENOENT;
}

int luca_dir_remove_entry(luca_inode_ref_t *parent, const char *name,
			  uint32_t name_len)
{
	luca_sblock_t *sb = &parent->fs->sb;
	/* Check if removing from directory */
	// if (!ext4_inode_is_type(sb, parent->inode, EXT4_INODE_MODE_DIRECTORY))
	// 	return ENOTDIR;

	if((to_le16(parent->inode->mode) & EXT4_INODE_MODE_TYPE_MASK) != EXT4_INODE_MODE_DIRECTORY)
		return ENOTDIR;

	/* Try to find entry */
	struct luca_dir_search_result result;
	int rc = luca_dir_find_entry(&result, parent, name, name_len);
	if (rc != EOK)
		return rc;

	/* Invalidate entry */
	ext4_dir_en_set_inode(result.dentry, 0);

	/* Store entry position in block */
	uint32_t pos = (uint8_t *)result.dentry - result.block.data;

	/*
	 * If entry is not the first in block, it must be merged
	 * with previous entry
	 */
	if (pos != 0) {
		uint32_t offset = 0;

		/* Start from the first entry in block */
		struct ext4_dir_en *tmp_de =(ext4_dir_en *)result.block.data;
		uint16_t de_len = ext4_dir_en_get_entry_len(tmp_de);

		/* Find direct predecessor of removed entry */
		while ((offset + de_len) < pos) {
			offset += ext4_dir_en_get_entry_len(tmp_de);
			tmp_de = (ext4_dir_en *)(result.block.data + offset);
			de_len = ext4_dir_en_get_entry_len(tmp_de);
		}

		ext4_assert(de_len + offset == pos);

		/* Add to removed entry length to predecessor's length */
		uint16_t del_len;
		del_len = ext4_dir_en_get_entry_len(result.dentry);
		ext4_dir_en_set_entry_len(tmp_de, de_len + del_len);
	}

	luca_dir_set_csum(parent,
			(struct ext4_dir_en *)result.block.data);
	// ext4_trans_set_block_dirty(result.block.buf);
	luca_bcache_set_dirty(result.block.buf);

	return luca_dir_destroy_result(parent, &result);
}

int luca_dir_try_insert_entry(luca_sblock_t *sb,
			      luca_inode_ref_t *inode_ref,
			      struct luca_block *dst_blk,
			      luca_inode_ref_t *child, const char *name,
			      uint32_t name_len)
{
	// printf("luca_dir_try_insert_entry: %s\n", name);
	/* Compute required length entry and align it to 4 bytes */
	uint32_t block_size = ext4_sb_get_block_size(sb);
	uint16_t required_len = sizeof(struct ext4_fake_dir_entry) + name_len;

	if ((required_len % 4) != 0)
		required_len += 4 - (required_len % 4);

	/* Initialize pointers, stop means to upper bound */
	struct ext4_dir_en *start = (ext4_dir_en *)dst_blk->data;
	struct ext4_dir_en *stop = (ext4_dir_en *)(dst_blk->data + block_size);

	/*
	 * Walk through the block and check for invalid entries
	 * or entries with free space for new entry
	 */
	while (start < stop) {
		uint32_t inode = ext4_dir_en_get_inode(start);
		uint16_t rec_len = ext4_dir_en_get_entry_len(start);
		uint8_t itype = ext4_dir_en_get_inode_type(sb, start);

		/* If invalid and large enough entry, use it */
		if ((inode == 0) && (itype != EXT4_DIRENTRY_DIR_CSUM) &&
		    (rec_len >= required_len)) {
			// printf("luca_dir_try_insert_entry name1:%s\n", name);
			luca_dir_write_entry(sb, start, rec_len, child, name,
					     name_len);
			luca_dir_set_csum(inode_ref, (ext4_dir_en *)dst_blk->data);
			// ext4_trans_set_block_dirty(dst_blk->buf);
			luca_bcache_set_dirty(dst_blk->buf);

			return EOK;
		}

		/* Valid entry, try to split it */
		if (inode != 0) {
			uint16_t used_len;
			used_len = ext4_dir_en_get_name_len(sb, start);

			uint16_t sz;
			sz = sizeof(struct ext4_fake_dir_entry) + used_len;

			if ((used_len % 4) != 0)
				sz += 4 - (used_len % 4);

			uint16_t free_space = rec_len - sz;

			/* There is free space for new entry */
			if (free_space >= required_len) {
				/* Cut tail of current entry */
				// printf("luca_dir_try_insert_entry name2:%s\n", name);
				struct ext4_dir_en * new_entry;
				new_entry = (ext4_dir_en *)((uint8_t *)start + sz);
				ext4_dir_en_set_entry_len(start, sz);
				luca_dir_write_entry(sb, new_entry, free_space,
						     child, name, name_len);
				// printf("new_entry name:%s\n", new_entry->name);
				luca_dir_set_csum(inode_ref,
						  (ext4_dir_en *)dst_blk->data);
				// ext4_trans_set_block_dirty(dst_blk->buf);
				luca_bcache_set_dirty(dst_blk->buf);
				return EOK;
			}
		}

		/* Jump to the next entry */
		start = (ext4_dir_en *)((uint8_t *)start + rec_len);
	}

	/* No free space found for new entry */
	return ENOSPC;
}


int luca_dir_find_in_block(struct luca_block *block, luca_sblock_t *sb,
			   size_t name_len, const char *name,
			   struct ext4_dir_en **res_entry)
{
	/* Start from the first entry in block */
	struct ext4_dir_en *de = (struct ext4_dir_en *)block->data;

	/* Set upper bound for cycling */
	uint8_t *addr_limit = block->data + ext4_sb_get_block_size(sb);

	/* Walk through the block and check entries */
	while ((uint8_t *)de < addr_limit) {
		/* Termination condition */
		if ((uint8_t *)de + name_len > addr_limit)
			break;

		/* Valid entry - check it */
		if (ext4_dir_en_get_inode(de) != 0) {
			/* For more efficient compare only lengths firstly*/
			uint16_t el = ext4_dir_en_get_name_len(sb, de);
			if (el == name_len) {
				/* Compare names */
				if (memcmp(name, de->name, name_len) == 0) {
					*res_entry = de;
					return EOK;
				}
			}
		}

		uint16_t de_len = ext4_dir_en_get_entry_len(de);

		/* Corrupted entry */
		if (de_len == 0)
			return EINVAL;

		/* Jump to next entry */
		de = (struct ext4_dir_en *)((uint8_t *)de + de_len);
	}

	/* Entry not found */
	return ENOENT;
}

int luca_dir_destroy_result(luca_inode_ref_t *parent,
			    struct luca_dir_search_result *result)
{
	if (result->block.lb_id)
		return luca_block_set(parent->fs->bdev, &result->block);

	return EOK;
}








/*ialloc相关*/
/**@brief  Convert i-node number to relative index in block group.
 * @param sb    Superblock
 * @param inode I-node number to be converted
 * @return Index of the i-node in the block group
 */
static uint32_t luca_ialloc_inode_to_bgidx(luca_sblock_t *sb,
					   uint32_t inode)
{
	uint32_t inodes_per_group = ext4_get32(sb, inodes_per_group);
	return (inode - 1) % inodes_per_group;
}

/**@brief Convert relative index of i-node to absolute i-node number.
 * @param sb    Superblock
 * @param index Index to be converted
 * @return Absolute number of the i-node
 *
 */
static uint32_t luca_ialloc_bgidx_to_inode(luca_sblock_t *sb,
					   uint32_t index, uint32_t bgid)
{
	uint32_t inodes_per_group = ext4_get32(sb, inodes_per_group);
	return bgid * inodes_per_group + (index + 1);
}

/**@brief Compute block group number from the i-node number.
 * @param sb    Superblock
 * @param inode I-node number to be found the block group for
 * @return Block group number computed from i-node number
 */
static uint32_t luca_ialloc_get_bgid_of_inode(luca_sblock_t *sb,
					      uint32_t inode)
{
	uint32_t inodes_per_group = ext4_get32(sb, inodes_per_group);
	return (inode - 1) / inodes_per_group;
}

#if CONFIG_META_CSUM_ENABLE
static uint32_t luca_ialloc_bitmap_csum(luca_sblock_t *sb,	void *bitmap)
{
	uint32_t csum = 0;
	if (ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM)) {
		uint32_t inodes_per_group =
			ext4_get32(sb, inodes_per_group);

		/* First calculate crc32 checksum against fs uuid */
		csum = ext4_crc32c(EXT4_CRC32_INIT, sb->uuid, sizeof(sb->uuid));
		/* Then calculate crc32 checksum against inode bitmap */
		csum = ext4_crc32c(csum, bitmap, (inodes_per_group + 7) / 8);
	}
	return csum;
}
#else
#define luca_ialloc_bitmap_csum(...) 0
#endif

//TODO: Check this one when called by ext4_fs_get_block_group_ref()
void luca_ialloc_set_bitmap_csum(luca_sblock_t *sb, struct ext4_bgroup *bg,
				 void *bitmap __unused)
{
	int desc_size = ext4_sb_get_desc_size(sb);
	uint32_t csum = luca_ialloc_bitmap_csum(sb, bitmap);
	uint16_t lo_csum = to_le16(csum & 0xFFFF),
		 hi_csum = to_le16(csum >> 16);

	if (!ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM))
		return;

	/* See if we need to assign a 32bit checksum */
	bg->inode_bitmap_csum_lo = lo_csum;
	if (desc_size == EXT4_MAX_BLOCK_GROUP_DESCRIPTOR_SIZE)
		bg->inode_bitmap_csum_hi = hi_csum;

}

#if CONFIG_META_CSUM_ENABLE
static bool
luca_ialloc_verify_bitmap_csum(luca_sblock_t *sb, struct ext4_bgroup *bg,
			       void *bitmap __unused)
{

	int desc_size = ext4_sb_get_desc_size(sb);
	uint32_t csum = luca_ialloc_bitmap_csum(sb, bitmap);
	uint16_t lo_csum = to_le16(csum & 0xFFFF),
		 hi_csum = to_le16(csum >> 16);

	if (!ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM))
		return true;

	if (bg->inode_bitmap_csum_lo != lo_csum)
		return false;

	if (desc_size == EXT4_MAX_BLOCK_GROUP_DESCRIPTOR_SIZE)
		if (bg->inode_bitmap_csum_hi != hi_csum)
			return false;

	return true;
}
#else
#define luca_ialloc_verify_bitmap_csum(...) true
#endif

static int
__luca_ialloc_free_inode(luca_fs_t *fs, uint32_t index, bool is_dir)
{
	struct ext4_sblock *sb = &fs->sb;

	/* Compute index of block group and load it */
	uint32_t block_group = luca_ialloc_get_bgid_of_inode(sb, index);

	luca_block_group_ref_t bg_ref;
	int rc = luca_fs_get_block_group_ref(fs, block_group, &bg_ref);
	if (rc != EOK)
		return rc;

	struct ext4_bgroup *bg = bg_ref.block_group;

	/* Load i-node bitmap */
	ext4_fsblk_t bitmap_block_addr =
	    ext4_bg_get_inode_bitmap(bg, sb);

	struct luca_block b;
	rc = luca_block_get(fs->bdev, &b, bitmap_block_addr);
	if (rc != EOK)
		return rc;

	if (!luca_ialloc_verify_bitmap_csum(sb, bg, b.data)) {
		ext4_dbg(DEBUG_IALLOC,
			DBG_WARN "Bitmap checksum failed."
			"Group: %" PRIu32"\n",
			bg_ref.index);
	}

	/* Free i-node in the bitmap */
	uint32_t index_in_group = luca_ialloc_inode_to_bgidx(sb, index);
	ext4_bmap_bit_clr(b.data, index_in_group);
	luca_ialloc_set_bitmap_csum(sb, bg, b.data);
	// ext4_trans_set_block_dirty(b.buf);
	luca_bcache_set_dirty(b.buf);

	/* Put back the block with bitmap */
	rc = luca_block_set(fs->bdev, &b);
	if (rc != EOK) {
		/* Error in saving bitmap */
		luca_fs_put_block_group_ref(&bg_ref);
		return rc;
	}

	/* If released i-node is a directory, decrement used directories count
	 */
	if (is_dir) {
		uint32_t bg_used_dirs = ext4_bg_get_used_dirs_count(bg, sb);
		bg_used_dirs--;
		ext4_bg_set_used_dirs_count(bg, sb, bg_used_dirs);
	}

	/* Update block group free inodes count */
	uint32_t free_inodes = ext4_bg_get_free_inodes_count(bg, sb);
	free_inodes++;
	ext4_bg_set_free_inodes_count(bg, sb, free_inodes);

	bg_ref.dirty = true;

	/* Put back the modified block group */
	rc = luca_fs_put_block_group_ref(&bg_ref);
	if (rc != EOK)
		return rc;

	/* Update superblock free inodes count */
	ext4_set32(sb, free_inodes_count,
		   ext4_get32(sb, free_inodes_count) + 1);

	return EOK;
}

static int
__luca_ialloc_alloc_inode(luca_fs_t *fs, uint32_t *idx, bool is_dir)
{
	luca_sblock_t *sb = &fs->sb;

	uint32_t bgid = fs->last_inode_bg_id;
	uint32_t bg_count = ext4_block_group_cnt(sb);
	uint32_t sb_free_inodes = ext4_get32(sb, free_inodes_count);
	bool rewind = false;

	/* Try to find free i-node in all block groups */
	while (bgid <= bg_count) {

		if (bgid == bg_count) {
			if (rewind)
				break;
			bg_count = fs->last_inode_bg_id;
			bgid = 0;
			rewind = true;
			continue;
		}

		/* Load block group to check */
		luca_block_group_ref_t bg_ref;
		int rc = luca_fs_get_block_group_ref(fs, bgid, &bg_ref);
		if (rc != EOK)
			return rc;

		struct ext4_bgroup *bg = bg_ref.block_group;

		/* Read necessary values for algorithm */
		uint32_t free_inodes = ext4_bg_get_free_inodes_count(bg, sb);
		uint32_t used_dirs = ext4_bg_get_used_dirs_count(bg, sb);

		/* Check if this block group is good candidate for allocation */
		if (free_inodes > 0) {
			/* Load block with bitmap */
			ext4_fsblk_t bmp_blk_add = ext4_bg_get_inode_bitmap(bg, sb);

			struct luca_block b;
			rc = luca_block_get(fs->bdev, &b, bmp_blk_add);
			if (rc != EOK) {
				luca_fs_put_block_group_ref(&bg_ref);
				return rc;
			}

			if (!luca_ialloc_verify_bitmap_csum(sb, bg, b.data)) {
				ext4_dbg(DEBUG_IALLOC,
					DBG_WARN "Bitmap checksum failed."
					"Group: %" PRIu32"\n",
					bg_ref.index);
			}

			/* Try to allocate i-node in the bitmap */
			uint32_t inodes_in_bg;
			uint32_t idx_in_bg;

			inodes_in_bg = ext4_inodes_in_group_cnt(sb, bgid);
			rc = ext4_bmap_bit_find_clr(b.data, 0, inodes_in_bg,
						    &idx_in_bg);
			/* Block group has not any free i-node */
			if (rc == ENOSPC) {
				rc = luca_block_set(fs->bdev, &b);
				if (rc != EOK) {
					luca_fs_put_block_group_ref(&bg_ref);
					return rc;
				}

				rc = luca_fs_put_block_group_ref(&bg_ref);
				if (rc != EOK)
					return rc;

				continue;
			}

			ext4_bmap_bit_set(b.data, idx_in_bg);

			/* Free i-node found, save the bitmap */
			ext4_ialloc_set_bitmap_csum(sb,bg,
						    b.data);
			//ext4_trans_set_block_dirty(b.buf);
			luca_bcache_set_dirty(b.buf);

			luca_block_set(fs->bdev, &b);
			if (rc != EOK) {
				luca_fs_put_block_group_ref(&bg_ref);
				return rc;
			}

			/* Modify filesystem counters */
			free_inodes--;
			ext4_bg_set_free_inodes_count(bg, sb, free_inodes);

			/* Increment used directories counter */
			if (is_dir) {
				used_dirs++;
				ext4_bg_set_used_dirs_count(bg, sb, used_dirs);
			}

			/* Decrease unused inodes count */
			uint32_t unused =
			    ext4_bg_get_itable_unused(bg, sb);

			uint32_t free = inodes_in_bg - unused;

			if (idx_in_bg >= free) {
				unused = inodes_in_bg - (idx_in_bg + 1);
				ext4_bg_set_itable_unused(bg, sb, unused);
			}

			/* Save modified block group */
			bg_ref.dirty = true;

			rc = luca_fs_put_block_group_ref(&bg_ref);
			if (rc != EOK)
				return rc;

			/* Update superblock */
			sb_free_inodes--;
			ext4_set32(sb, free_inodes_count, sb_free_inodes);

			/* Compute the absolute i-nodex number */
			*idx = luca_ialloc_bgidx_to_inode(sb, idx_in_bg, bgid);

			fs->last_inode_bg_id = bgid;

			return EOK;
		}

		/* Block group not modified, put it and jump to the next block
		 * group */
		luca_fs_put_block_group_ref(&bg_ref);
		if (rc != EOK)
			return rc;

		++bgid;
	}

	return ENOSPC;
}





/*lucafs相关*/
static uint64_t luca_fs_get_descriptor_block(luca_sblock_t *s,
					     uint32_t bgid,
					     uint32_t dsc_per_block)
{
	uint32_t first_meta_bg, dsc_id;
	int has_super = 0;
	dsc_id = bgid / dsc_per_block;
	first_meta_bg = ext4_sb_first_meta_bg(s);

	bool meta_bg = ext4_sb_feature_incom(s, EXT4_FINCOM_META_BG);

	if (!meta_bg || dsc_id < first_meta_bg)
		return ext4_get32(s, first_data_block) + dsc_id + 1;

	if (ext4_sb_is_super_in_bg(s, bgid))
		has_super = 1;

	return (has_super + ext4_fs_first_bg_block_no(s, bgid));
}

static void luca_fs_mark_bitmap_end(int start_bit, int end_bit, void *bitmap)
{
	int i;

	if (start_bit >= end_bit)
		return;

	for (i = start_bit; (unsigned)i < ((start_bit + 7) & ~7UL); i++)
		ext4_bmap_bit_set((uint8_t *)bitmap, i);

	if (i < end_bit)
		memset((char *)bitmap + (i >> 3), 0xff, (end_bit - i) >> 3);
}


static int luca_fs_init_block_bitmap(luca_block_group_ref_t *bg_ref)
{
	luca_sblock_t *sb = &bg_ref->fs->sb;
	struct ext4_bgroup *bg = bg_ref->block_group;
	int rc;

	uint32_t bit, bit_max;
	uint32_t group_blocks;
	uint16_t inode_size = ext4_get16(sb, inode_size);
	uint32_t block_size = luca_sb_get_block_size(sb);
	uint32_t inodes_per_group = ext4_get32(sb, inodes_per_group);

	uint64_t i;
	uint64_t bmp_blk = ext4_bg_get_block_bitmap(bg, sb);
	uint64_t bmp_inode = ext4_bg_get_inode_bitmap(bg, sb);
	uint64_t inode_table = ext4_bg_get_inode_table_first_block(bg, sb);
	uint64_t first_bg = ext4_balloc_get_block_of_bgid(sb, bg_ref->index);

	uint32_t dsc_per_block =  block_size / ext4_sb_get_desc_size(sb);

	bool flex_bg = ext4_sb_feature_incom(sb, EXT4_FINCOM_FLEX_BG);
	bool meta_bg = ext4_sb_feature_incom(sb, EXT4_FINCOM_META_BG);

	uint32_t inode_table_bcnt = inodes_per_group * inode_size / block_size;

	struct luca_block block_bitmap;
	rc = luca_trans_block_get_noread(bg_ref->fs->bdev, &block_bitmap, bmp_blk);
	if (rc != EOK)
		return rc;

	memset(block_bitmap.data, 0, block_size);
	bit_max = ext4_sb_is_super_in_bg(sb, bg_ref->index);

	uint32_t count = ext4_sb_first_meta_bg(sb) * dsc_per_block;
	if (!meta_bg || bg_ref->index < count) {
		if (bit_max) {
			bit_max += ext4_bg_num_gdb(sb, bg_ref->index);
			bit_max += ext4_get16(sb, s_reserved_gdt_blocks);
		}
	} else { /* For META_BG_BLOCK_GROUPS */
		bit_max += ext4_bg_num_gdb(sb, bg_ref->index);
	}
	for (bit = 0; bit < bit_max; bit++)
		ext4_bmap_bit_set(block_bitmap.data, bit);

	if (bg_ref->index == ext4_block_group_cnt(sb) - 1) {
		/*
		 * Even though mke2fs always initialize first and last group
		 * if some other tool enabled the EXT4_BG_BLOCK_UNINIT we need
		 * to make sure we calculate the right free blocks
		 */

		group_blocks = (uint32_t)(ext4_sb_get_blocks_cnt(sb) -
					  ext4_get32(sb, first_data_block) -
					  ext4_get32(sb, blocks_per_group) *
					  (ext4_block_group_cnt(sb) - 1));
	} else {
		group_blocks = ext4_get32(sb, blocks_per_group);
	}

	bool in_bg;
	//in_bg = ext4_block_in_group(sb, bmp_blk, bg_ref->index);
	if(ext4_balloc_get_bgid_of_block(sb, bmp_blk) == bg_ref->index)
		in_bg = true;
	else
		in_bg = false;

	if (!flex_bg || in_bg)
		ext4_bmap_bit_set(block_bitmap.data,
				  (uint32_t)(bmp_blk - first_bg));

	//in_bg = ext4_block_in_group(sb, bmp_inode, bg_ref->index);
	if(ext4_balloc_get_bgid_of_block(sb, bmp_inode) == bg_ref->index)
		in_bg = true;
	else
		in_bg = false;

	if (!flex_bg || in_bg)
		ext4_bmap_bit_set(block_bitmap.data,
				  (uint32_t)(bmp_inode - first_bg));

    for (i = inode_table; i < inode_table + inode_table_bcnt; i++) {
		//in_bg = ext4_block_in_group(sb, i, bg_ref->index);
		if(ext4_balloc_get_bgid_of_block(sb, i) == bg_ref->index)
			in_bg = true;
		else
			in_bg = false;
		if (!flex_bg || in_bg)
			ext4_bmap_bit_set(block_bitmap.data,
					  (uint32_t)(i - first_bg));
	}
        /*
         * Also if the number of blocks within the group is
         * less than the blocksize * 8 ( which is the size
         * of bitmap ), set rest of the block bitmap to 1
         */
    luca_fs_mark_bitmap_end(group_blocks, block_size * 8, block_bitmap.data);
	//ext4_trans_set_block_dirty(block_bitmap.buf);
	luca_bcache_set_dirty(block_bitmap.buf);

	ext4_balloc_set_bitmap_csum(sb, bg_ref->block_group, block_bitmap.data);
	bg_ref->dirty = true;

	/* Save bitmap */
	return luca_block_set(bg_ref->fs->bdev, &block_bitmap);
}

static int luca_fs_init_inode_bitmap(luca_block_group_ref_t *bg_ref)
{
	int rc;
	luca_sblock_t *sb = &bg_ref->fs->sb;
	struct ext4_bgroup *bg = bg_ref->block_group;

	/* Load bitmap */
	uint64_t bitmap_block_addr = ext4_bg_get_inode_bitmap(bg, sb);

	struct luca_block b;
	rc = luca_trans_block_get_noread(bg_ref->fs->bdev, &b, bitmap_block_addr);
	if (rc != EOK)
		return rc;

	/* Initialize all bitmap bits to zero */
	uint32_t block_size = luca_sb_get_block_size(sb);
	uint32_t inodes_per_group = ext4_get32(sb, inodes_per_group);

	memset(b.data, 0, (inodes_per_group + 7) / 8);

	uint32_t start_bit = inodes_per_group;
	uint32_t end_bit = block_size * 8;

	uint32_t i;
	for (i = start_bit; i < ((start_bit + 7) & ~7UL); i++)
		ext4_bmap_bit_set(b.data, i);

	if (i < end_bit)
		memset(b.data + (i >> 3), 0xff, (end_bit - i) >> 3);

	//ext4_trans_set_block_dirty(b.buf);
	luca_bcache_set_dirty(b.buf);

	ext4_ialloc_set_bitmap_csum(sb, bg, b.data);
	bg_ref->dirty = true;

	/* Save bitmap */
	return luca_block_set(bg_ref->fs->bdev, &b);
}

static int luca_fs_init_inode_table(luca_block_group_ref_t *bg_ref)
{
	luca_sblock_t *sb = &bg_ref->fs->sb;
	struct ext4_bgroup *bg = bg_ref->block_group;

	uint32_t inode_size = ext4_get16(sb, inode_size);
	uint32_t block_size = luca_sb_get_block_size(sb);
	uint32_t inodes_per_block = block_size / inode_size;
	uint32_t inodes_in_group = ext4_inodes_in_group_cnt(sb, bg_ref->index);
	uint32_t table_blocks = inodes_in_group / inodes_per_block;
	uint64_t fblock;

	if (inodes_in_group % inodes_per_block)
		table_blocks++;

	/* Compute initialization bounds */
	uint64_t first_block = ext4_bg_get_inode_table_first_block(bg, sb);

	uint64_t last_block = first_block + table_blocks - 1;

	/* Initialization of all itable blocks */
	for (fblock = first_block; fblock <= last_block; ++fblock) {
		struct luca_block b;
		int rc = luca_trans_block_get_noread(bg_ref->fs->bdev, &b, fblock);
		if (rc != EOK)
			return rc;

		memset(b.data, 0, block_size);
		//ext4_trans_set_block_dirty(b.buf);
		luca_bcache_set_dirty(b.buf);

		rc = luca_block_set(bg_ref->fs->bdev, &b);
		if (rc != EOK)
			return rc;
	}

	return EOK;
}

int luca_fs_put_block_group_ref(luca_block_group_ref_t *ref)
{
	/* Check if reference modified */
	if (ref->dirty) {
		/* Compute new checksum of block group */
		uint16_t cs;
		cs = luca_fs_bg_checksum(&ref->fs->sb, ref->index,
					 ref->block_group);
		ref->block_group->checksum = to_le16(cs);

		/* Mark block dirty for writing changes to physical device */
		//ext4_trans_set_block_dirty(ref->block.buf);
		luca_bcache_set_dirty(ref->block.buf);
	}

	/* Put back block, that contains block group descriptor */
	return luca_block_set(ref->fs->bdev, &ref->block);
}

static uint16_t luca_fs_bg_checksum(luca_sblock_t *sb, uint32_t bgid,
				    struct ext4_bgroup *bg)
{
	/* If checksum not supported, 0 will be returned */
	uint16_t crc = 0;
#if CONFIG_META_CSUM_ENABLE
	/* Compute the checksum only if the filesystem supports it */
	if (ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM)) {
		/* Use metadata_csum algorithm instead */
		uint32_t le32_bgid = to_le32(bgid);
		uint32_t orig_checksum, checksum;

		/* Preparation: temporarily set bg checksum to 0 */
		orig_checksum = bg->checksum;
		bg->checksum = 0;

		/* First calculate crc32 checksum against fs uuid */
		checksum = ext4_crc32c(EXT4_CRC32_INIT, sb->uuid,
				sizeof(sb->uuid));
		/* Then calculate crc32 checksum against bgid */
		checksum = ext4_crc32c(checksum, &le32_bgid, sizeof(bgid));
		/* Finally calculate crc32 checksum against block_group_desc */
		checksum = ext4_crc32c(checksum, bg, ext4_sb_get_desc_size(sb));
		bg->checksum = orig_checksum;

		crc = checksum & 0xFFFF;
		return crc;
	}
#endif
	if (ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_GDT_CSUM)) {
		uint8_t *base = (uint8_t *)bg;
		uint8_t *checksum = (uint8_t *)&bg->checksum;

		uint32_t offset = (uint32_t)(checksum - base);

		/* Convert block group index to little endian */
		uint32_t group = to_le32(bgid);

		/* Initialization */
		crc = ext4_bg_crc16(~0, sb->uuid, sizeof(sb->uuid));

		/* Include index of block group */
		crc = ext4_bg_crc16(crc, (uint8_t *)&group, sizeof(group));

		/* Compute crc from the first part (stop before checksum field)
		 */
		crc = ext4_bg_crc16(crc, (uint8_t *)bg, offset);

		/* Skip checksum */
		offset += sizeof(bg->checksum);

		/* Checksum of the rest of block group descriptor */
		if ((ext4_sb_feature_incom(sb, EXT4_FINCOM_64BIT)) &&
		    (offset < ext4_sb_get_desc_size(sb))) {

			const uint8_t *start = ((uint8_t *)bg) + offset;
			size_t len = ext4_sb_get_desc_size(sb) - offset;
			crc = ext4_bg_crc16(crc, start, len);
		}
	}
	return crc;
}

#if CONFIG_META_CSUM_ENABLE
static bool luca_fs_verify_bg_csum(luca_sblock_t*sb,
				   uint32_t bgid,
				   struct ext4_bgroup *bg)
{
	if (!ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM))
		return true;

	return luca_fs_bg_checksum(sb, bgid, bg) == to_le16(bg->checksum);
}
#else
#define luca_fs_verify_bg_csum(...) true
#endif

#if CONFIG_META_CSUM_ENABLE
static uint32_t luca_fs_inode_checksum(luca_inode_ref_t *inode_ref)
{
	uint32_t checksum = 0;
	struct ext4_sblock *sb = &inode_ref->fs->sb;
	uint16_t inode_size = ext4_get16(sb, inode_size);

	if (ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM)) {
		uint32_t orig_checksum;

		uint32_t ino_index = to_le32(inode_ref->index);
		uint32_t ino_gen =
			to_le32(inode_ref->inode->generation);

		/* Preparation: temporarily set bg checksum to 0 */
		orig_checksum = luca_inode_get_csum(sb, inode_ref->inode);
		luca_inode_set_csum(sb, inode_ref->inode, 0);

		/* First calculate crc32 checksum against fs uuid */
		checksum = ext4_crc32c(EXT4_CRC32_INIT, sb->uuid,
				       sizeof(sb->uuid));
		/* Then calculate crc32 checksum against inode number
		 * and inode generation */
		checksum = ext4_crc32c(checksum, &ino_index, sizeof(ino_index));
		checksum = ext4_crc32c(checksum, &ino_gen, sizeof(ino_gen));
		/* Finally calculate crc32 checksum against
		 * the entire inode */
		checksum = ext4_crc32c(checksum, inode_ref->inode, inode_size);
		luca_inode_set_csum(sb, inode_ref->inode, orig_checksum);

		/* If inode size is not large enough to hold the
		 * upper 16bit of the checksum */
		if (inode_size == EXT4_GOOD_OLD_INODE_SIZE)
			checksum &= 0xFFFF;

	}
	return checksum;
}
#else
#define luca_fs_inode_checksum(...) 0
#endif

static void luca_fs_set_inode_checksum(luca_inode_ref_t *inode_ref)
{
	luca_sblock_t *sb = &inode_ref->fs->sb;
	if (!ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM))
		return;

	uint32_t csum = luca_fs_inode_checksum(inode_ref);
	luca_inode_set_csum(sb, inode_ref->inode, csum);
}

#if CONFIG_META_CSUM_ENABLE
static bool luca_fs_verify_inode_csum(luca_inode_ref_t *inode_ref)
{
	luca_sblock_t *sb = &inode_ref->fs->sb;
	if (!ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM))
		return true;

	return luca_inode_get_csum(sb, inode_ref->inode) ==
		luca_fs_inode_checksum(inode_ref);
}
#else
#define luca_fs_verify_inode_csum(...) true
#endif

void luca_fs_inode_blocks_init(luca_fs_t *fs,
			       luca_inode_ref_t *inode_ref)
{
	struct luca_inode *inode = inode_ref->inode;

	/* Reset blocks array. For inode which is not directory or file, just
	 * fill in blocks with 0 */
	switch (/*ext4_inode_type(&fs->sb, inode_ref->inode)*/
	 		to_le16(inode->mode) & EXT4_INODE_MODE_TYPE_MASK) {
	case EXT4_INODE_MODE_FILE:
	case EXT4_INODE_MODE_DIRECTORY:
		break;
	default:
		return;
	}

// #if CONFIG_DIR_INDEX_ENABLE
// 	/* Initialize directory index if needed */
// 	if (ext4_sb_feature_incom(&fs->sb, EXT4_FCOM_DIR_INDEX)) {
// 		luca_inode_set_flag(inode, EXT4_INODE_FLAG_INDEX);
// 		// luca_dir_index_init(inode_ref);
// 	}
// #endif

#if CONFIG_EXTENT_ENABLE && CONFIG_EXTENTS_ENABLE
	/* Initialize extents if needed */
	if (ext4_sb_feature_incom(&fs->sb, EXT4_FINCOM_EXTENTS)) {
		luca_inode_set_flag(inode, EXT4_INODE_FLAG_EXTENTS);

		/* Initialize extent root header */
		luca_extent_tree_init(inode_ref);
	}

	inode_ref->dirty = true;
#endif
}

uint32_t luca_fs_correspond_inode_mode(int filetype)
{
	switch (filetype) {
	case EXT4_DE_DIR:
		return EXT4_INODE_MODE_DIRECTORY;
	case EXT4_DE_REG_FILE:
		return EXT4_INODE_MODE_FILE;
	case EXT4_DE_SYMLINK:
		return EXT4_INODE_MODE_SOFTLINK;
	case EXT4_DE_CHRDEV:
		return EXT4_INODE_MODE_CHARDEV;
	case EXT4_DE_BLKDEV:
		return EXT4_INODE_MODE_BLOCKDEV;
	case EXT4_DE_FIFO:
		return EXT4_INODE_MODE_FIFO;
	case EXT4_DE_SOCK:
		return EXT4_INODE_MODE_SOCKET;
	}
	/* FIXME: unsupported filetype */
	return EXT4_INODE_MODE_FILE;
}

int luca_fs_alloc_inode(luca_fs_t *fs, luca_inode_ref_t *inode_ref,
			int filetype)
{
	/* Check if newly allocated i-node will be a directory */
	bool is_dir;
	uint16_t inode_size = ext4_get16(&fs->sb, inode_size);

	is_dir = (filetype == EXT4_DE_DIR);

	/* Allocate inode by allocation algorithm */
	uint32_t index;
	fs->inode_alloc_lock();
	int rc = __luca_ialloc_alloc_inode(fs, &index, is_dir);
	fs->inode_alloc_unlock();

	if (rc != EOK)
		return rc;

	/* Load i-node from on-disk i-node table */
	// rc = luca_fs_get_inode_ref(fs, index, inode_ref, false);
	rc = __luca_fs_get_inode_ref(fs, index, inode_ref, false);
	if (rc != EOK) {
		fs->inode_alloc_lock();
		__luca_ialloc_free_inode(fs, index, is_dir);
		fs->inode_alloc_unlock();
		return rc;
	}

	/* Initialize i-node */
	struct luca_inode *inode = inode_ref->inode;

	memset(inode, 0, inode_size);

	uint32_t mode;
	if (is_dir) {
		/*
		 * Default directory permissions to be compatible with other
		 * systems
		 * 0777 (octal) == rwxrwxrwx
		 */

		mode = 0777;
		mode |= EXT4_INODE_MODE_DIRECTORY;
	} else if (filetype == EXT4_DE_SYMLINK) {
		/*
		 * Default symbolic link permissions to be compatible with other systems
		 * 0777 (octal) == rwxrwxrwx
		 */

		mode = 0777;
		mode |= EXT4_INODE_MODE_SOFTLINK;
	} else {
		/*
		 * Default file permissions to be compatible with other systems
		 * 0666 (octal) == rw-rw-rw-
		 */

		mode = 0666;
		mode |= ext4_fs_correspond_inode_mode(filetype);
	}
	// ext4_inode_set_mode(&fs->sb, inode, mode);

	// ext4_inode_set_links_cnt(inode, 0);
	// ext4_inode_set_uid(inode, 0);
	// ext4_inode_set_gid(inode, 0);
	// ext4_inode_set_size(inode, 0);
	// ext4_inode_set_access_time(inode, 0);
	// ext4_inode_set_change_inode_time(inode, 0);
	// ext4_inode_set_modif_time(inode, 0);
	// ext4_inode_set_del_time(inode, 0);
	// ext4_inode_set_blocks_count(&fs->sb, inode, 0);
	// ext4_inode_set_flags(inode, 0);
	// ext4_inode_set_generation(inode, 0);

	inode->mode = to_le16((mode << 16) >> 16);
	inode->links_count = to_le16(0);
	inode->uid = to_le32(0);
	inode->gid = to_le32(0);

	inode->size_lo = to_le32(0);
	inode->size_hi = to_le32(0);

	inode->access_time = to_le32(0);
	inode->change_inode_time = to_le32(0);
	inode->modification_time = to_le32(0);
	inode->deletion_time = to_le32(0);
	luca_inode_set_blocks_count(&fs->sb, inode, 0);
	inode->flags = to_le32(0);
	inode->generation = to_le32(0);



	if (inode_size > EXT4_GOOD_OLD_INODE_SIZE) {
		uint16_t size = ext4_get16(&fs->sb, want_extra_isize);
		// ext4_inode_set_extra_isize(&fs->sb, inode, size);
		uint16_t temp_zize = ext4_get16(&fs->sb, inode_size);
		if(temp_zize > EXT4_GOOD_OLD_INODE_SIZE)
			inode->extra_isize = to_le16(size);
	}

	memset(inode->blocks, 0, sizeof(inode->blocks));
	inode_ref->dirty = true;

	return EOK;
}

int luca_fs_free_inode(luca_inode_ref_t *inode_ref)
{
	luca_fs_t *fs = inode_ref->fs;
	uint32_t offset;
	uint32_t suboff;
	uint64_t fblock;
	uint32_t block_size;
	uint32_t count;
	int rc;
#if CONFIG_EXTENT_ENABLE && CONFIG_EXTENTS_ENABLE
	/* For extents must be data block destroyed by other way */
	if ((ext4_sb_feature_incom(&fs->sb, EXT4_FINCOM_EXTENTS)) &&
	    /*(ext4_inode_has_flag(inode_ref->inode, EXT4_INODE_FLAG_EXTENTS))*/
		 (to_le32(inode_ref->inode->flags) & EXT4_INODE_FLAG_INDEX)) {
		/* Data structures are released during truncate operation... */
		goto finish;
	}
#endif
	/* Release all indirect (no data) blocks */

	/* 1) Single indirect */
	// ext4_fsblk_t fblock = ext4_inode_get_indirect_block(inode_ref->inode, 0);
	fblock = to_le32(inode_ref->inode->blocks[EXT4_INODE_INDIRECT_BLOCK]);
	if (fblock != 0) {
		inode_ref->fs->block_alloc_lock();
		int rc = luca_balloc_free_block(inode_ref, fblock);
		inode_ref->fs->block_alloc_unlock();
		if (rc != EOK)
			return rc;

		// ext4_inode_set_indirect_block(inode_ref->inode, 0, 0);
		inode_ref->inode->blocks[EXT4_INODE_INDIRECT_BLOCK] = to_le32(0);
	}

	block_size = ext4_sb_get_block_size(&fs->sb);
	count = block_size / sizeof(uint32_t);

	struct luca_block block;

	/* 2) Double indirect */
	// fblock = ext4_inode_get_indirect_block(inode_ref->inode, 1);
	fblock = to_le32(inode_ref->inode->blocks[EXT4_INODE_INDIRECT_BLOCK + 1]);
	if (fblock != 0) {
		int rc = luca_block_get(fs->bdev, &block, fblock);
		if (rc != EOK)
			return rc;

		ext4_fsblk_t ind_block;
		for (offset = 0; offset < count; ++offset) {
			ind_block = to_le32(((uint32_t *)block.data)[offset]);

			if (ind_block == 0)
				continue;

			inode_ref->fs->block_alloc_lock();
			rc = luca_balloc_free_block(inode_ref, ind_block);
			inode_ref->fs->block_alloc_unlock();
			
			if (rc != EOK) {
				luca_block_set(fs->bdev, &block);
				return rc;
			}

		}

		luca_block_set(fs->bdev, &block);
		inode_ref->fs->block_alloc_lock();
		rc = luca_balloc_free_block(inode_ref, fblock);
		inode_ref->fs->block_alloc_unlock();
		if (rc != EOK)
			return rc;

		// ext4_inode_set_indirect_block(inode_ref->inode, 1, 0);
		inode_ref->inode->blocks[EXT4_INODE_INDIRECT_BLOCK + 1] = to_le32(0);
	}

	/* 3) Tripple indirect */
	struct luca_block subblock;
	//fblock = ext4_inode_get_indirect_block(inode_ref->inode, 2);
	fblock = to_le32(inode_ref->inode->blocks[EXT4_INODE_INDIRECT_BLOCK + 2]);

	if (fblock == 0)
		goto finish;
	rc = luca_block_get(fs->bdev, &block, fblock);
	if (rc != EOK)
		return rc;

	ext4_fsblk_t ind_block;
	for (offset = 0; offset < count; ++offset) {
		ind_block = to_le32(((uint32_t *)block.data)[offset]);

		if (ind_block == 0)
			continue;
		rc = luca_block_get(fs->bdev, &subblock,
				ind_block);
		if (rc != EOK) {
			luca_block_set(fs->bdev, &block);
			return rc;
		}

		ext4_fsblk_t ind_subblk;
		for (suboff = 0; suboff < count; ++suboff) {
			ind_subblk = to_le32(((uint32_t *)subblock.data)[suboff]);

			if (ind_subblk == 0)
				continue;

			inode_ref->fs->block_alloc_lock();
			rc = luca_balloc_free_block(inode_ref, ind_subblk);
			inode_ref->fs->block_alloc_unlock();
			if (rc != EOK) {
				luca_block_set(fs->bdev, &subblock);
				luca_block_set(fs->bdev, &block);
				return rc;
			}

		}

		luca_block_set(fs->bdev, &subblock);

		inode_ref->fs->block_alloc_lock();
		rc = luca_balloc_free_block(inode_ref,
				ind_block);
		inode_ref->fs->block_alloc_unlock();
		if (rc != EOK) {
			luca_block_set(fs->bdev, &block);
			return rc;
		}

	}

	luca_block_set(fs->bdev, &block);
	inode_ref->fs->block_alloc_lock();
	rc = luca_balloc_free_block(inode_ref, fblock);
	inode_ref->fs->block_alloc_unlock();
	if (rc != EOK)
		return rc;

	// ext4_inode_set_indirect_block(inode_ref->inode, 2, 0);
	inode_ref->inode->blocks[EXT4_INODE_INDIRECT_BLOCK + 2] = to_le32(0);

finish:
	/* Mark inode dirty for writing to the physical device */
	inode_ref->dirty = true;

	/* Free block with extended attributes if present */
	ext4_fsblk_t xattr_block =
	    luca_inode_get_file_acl(inode_ref->inode, &fs->sb);
	if (xattr_block) {
		inode_ref->fs->block_alloc_lock();
		int rc = luca_balloc_free_block(inode_ref, xattr_block);
		inode_ref->fs->block_alloc_unlock();

		if (rc != EOK)
			return rc;

		luca_inode_set_file_acl(inode_ref->inode, &fs->sb, 0);
	}

	/* Free inode by allocator */
	if (/*ext4_inode_is_type(&fs->sb, inode_ref->inode,
			       EXT4_INODE_MODE_DIRECTORY)*/
		(to_le16(inode_ref->inode->mode) & EXT4_INODE_MODE_TYPE_MASK) == EXT4_INODE_MODE_DIRECTORY)
	{
		fs->inode_alloc_lock();
		rc = __luca_ialloc_free_inode(fs, inode_ref->index, true);
		fs->inode_alloc_unlock();
	}
	else
	{
		fs->inode_alloc_lock();
		rc = __luca_ialloc_free_inode(fs, inode_ref->index, false);
		fs->inode_alloc_unlock();
	}
		// rc = ext4_ialloc_free_inode(fs, inode_ref->index, false);

	return rc;
}


/**@brief Release data block from i-node
 * @param inode_ref I-node to release block from
 * @param iblock    Logical block to be released
 * @return Error code
 */
static int luca_fs_release_inode_block(luca_inode_ref_t *inode_ref,
				ext4_lblk_t iblock)
{
	ext4_fsblk_t fblock;

	luca_fs_t *fs = inode_ref->fs;

	/* Extents are handled otherwise = there is not support in this function
	 */
	ext4_assert(!(
	    ext4_sb_feature_incom(&fs->sb, EXT4_FINCOM_EXTENTS) &&
	    /*(ext4_inode_has_flag(inode_ref->inode, EXT4_INODE_FLAG_EXTENTS)) &&*/
		(to_le32(inode_ref->inode->flags) & EXT4_INODE_FLAG_EXTENTS)));

	struct luca_inode *inode = inode_ref->inode;

	/* Handle simple case when we are dealing with direct reference */
	if (iblock < EXT4_INODE_DIRECT_BLOCK_COUNT) {
		// fblock = ext4_inode_get_direct_block(inode, iblock);
		fblock = to_le32(inode->blocks[iblock]);

		/* Sparse file */
		if (fblock == 0)
			return EOK;

		// ext4_inode_set_direct_block(inode, iblock, 0);
		inode->blocks[iblock] = to_le32(0);

		inode_ref->fs->block_alloc_lock();
		int rc = luca_balloc_free_block(inode_ref, fblock);
		inode_ref->fs->block_alloc_unlock();
		return rc;
	}

	/* Determine the indirection level needed to get the desired block */
	unsigned int level = 0;
	unsigned int i;
	for (i = 1; i < 4; i++) {
		if (iblock < fs->inode_block_limits[i]) {
			level = i;
			break;
		}
	}

	if (level == 0)
		return EIO;

	/* Compute offsets for the topmost level */
	uint32_t block_offset_in_level =
		(uint32_t)(iblock - fs->inode_block_limits[level - 1]);
	ext4_fsblk_t current_block = inode->blocks[level - 1 + EXT4_INODE_INDIRECT_BLOCK];
	    // ext4_inode_get_indirect_block(inode, level - 1);
	uint32_t offset_in_block =
	    (uint32_t)(block_offset_in_level / fs->inode_blocks_per_level[level - 1]);

	/*
	 * Navigate through other levels, until we find the block number
	 * or find null reference meaning we are dealing with sparse file
	 */
	struct luca_block block;

	while (level > 0) {

		/* Sparse check */
		if (current_block == 0)
			return EOK;

		int rc = luca_block_get(fs->bdev, &block, current_block);
		if (rc != EOK)
			return rc;

		current_block =
		    to_le32(((uint32_t *)block.data)[offset_in_block]);

		/* Set zero if physical data block address found */
		if (level == 1) {
			((uint32_t *)block.data)[offset_in_block] = to_le32(0);
			// ext4_trans_set_block_dirty(block.buf);
			luca_bcache_set_dirty(block.buf);
		}

		rc = luca_block_set(fs->bdev, &block);
		if (rc != EOK)
			return rc;

		level--;

		/*
		 * If we are on the last level, break here as
		 * there is no next level to visit
		 */
		if (level == 0)
			break;

		/* Visit the next level */
		block_offset_in_level %= fs->inode_blocks_per_level[level];
		offset_in_block = (uint32_t)(block_offset_in_level /
				  fs->inode_blocks_per_level[level - 1]);
	}

	fblock = current_block;
	if (fblock == 0)
		return EOK;

	/* Physical block is not referenced, it can be released */
	inode_ref->fs->block_alloc_lock();
	int rc = luca_balloc_free_block(inode_ref, fblock);
	inode_ref->fs->block_alloc_unlock();
	return rc;
}

int luca_fs_truncate_inode(luca_inode_ref_t *inode_ref, uint64_t new_size)
{
	luca_sblock_t *sb = &inode_ref->fs->sb;
	uint32_t i;
	int r;
	bool v;

	/* Check flags, if i-node can be truncated */
	if (!luca_inode_can_truncate(sb, inode_ref->inode))
		return EINVAL;

	/* If sizes are equal, nothing has to be done. */
	uint64_t old_size = luca_inode_get_size(sb, inode_ref->inode);
	if (old_size == new_size)
		return EOK;

	/* It's not supported to make the larger file by truncate operation */
	if (old_size < new_size)
		return EINVAL;

	/* For symbolic link which is small enough */
	// v = ext4_inode_is_type(sb, inode_ref->inode, EXT4_INODE_MODE_SOFTLINK);
	v = (to_le16(inode_ref->inode->mode) & EXT4_INODE_MODE_TYPE_MASK) == EXT4_INODE_MODE_SOFTLINK;
	
	if (v && old_size < sizeof(inode_ref->inode->blocks) &&
	    !luca_inode_get_blocks_count(sb, inode_ref->inode)) {
		char *content = (char *)inode_ref->inode->blocks + new_size;
		memset(content, 0,
		       sizeof(inode_ref->inode->blocks) - (uint32_t)new_size);
		// ext4_inode_set_size(inode_ref->inode, new_size);
		inode_ref->inode->size_lo = to_le32((new_size << 32) >> 32);
		inode_ref->inode->size_hi = to_le32(new_size >> 32);
		inode_ref->dirty = true;

		return EOK;
	}

	// i = ext4_inode_type(sb, inode_ref->inode);
	i = to_le16(inode_ref->inode->mode) & EXT4_INODE_MODE_TYPE_MASK;
	if (i == EXT4_INODE_MODE_CHARDEV ||
	    i == EXT4_INODE_MODE_BLOCKDEV ||
	    i == EXT4_INODE_MODE_SOCKET) {
		inode_ref->inode->blocks[0] = 0;
		inode_ref->inode->blocks[1] = 0;

		inode_ref->dirty = true;
		return EOK;
	}

	/* Compute how many blocks will be released */
	uint32_t block_size = ext4_sb_get_block_size(sb);
	uint32_t new_blocks_cnt = (uint32_t)((new_size + block_size - 1) / block_size);
	uint32_t old_blocks_cnt = (uint32_t)((old_size + block_size - 1) / block_size);
	uint32_t diff_blocks_cnt = old_blocks_cnt - new_blocks_cnt;
#if CONFIG_EXTENT_ENABLE && CONFIG_EXTENTS_ENABLE
	if ((ext4_sb_feature_incom(sb, EXT4_FINCOM_EXTENTS)) &&
	    /*(ext4_inode_has_flag(inode_ref->inode, EXT4_INODE_FLAG_EXTENTS)) &&*/
		(to_le32(inode_ref->inode->flags) & EXT4_INODE_FLAG_EXTENTS)) {

		/* Extents require special operation */
		if (diff_blocks_cnt) {
			r = luca_extent_remove_space(inode_ref, new_blocks_cnt,
						     EXT_MAX_BLOCKS);
			if (r != EOK)
				return r;

		}
	} else
#endif
	{
		/* Release data blocks from the end of file */

		/* Starting from 1 because of logical blocks are numbered from 0
		 */
		for (i = 0; i < diff_blocks_cnt; ++i) {
			r = luca_fs_release_inode_block(inode_ref,
							new_blocks_cnt + i);
			if (r != EOK)
				return r;
		}
	}

	/* Update i-node */
	luca_inode_set_size(inode_ref->inode, new_size);
	inode_ref->dirty = true;

	return EOK;
}

uint64_t luca_fs_inode_to_goal_block(luca_inode_ref_t *inode_ref)
{
	uint32_t grp_inodes = ext4_get32(&inode_ref->fs->sb, inodes_per_group);
	return (inode_ref->index - 1) / grp_inodes;
}

int luca_fs_indirect_find_goal(luca_inode_ref_t *inode_ref,
			       ext4_fsblk_t *goal)
{
	int r;
	struct ext4_sblock *sb = &inode_ref->fs->sb;
	*goal = 0;

	uint64_t inode_size = luca_inode_get_size(sb, inode_ref->inode);
	uint32_t block_size = ext4_sb_get_block_size(sb);
	uint32_t iblock_cnt = (uint32_t)(inode_size / block_size);

	if (inode_size % block_size != 0)
		iblock_cnt++;

	/* If inode has some blocks, get last block address + 1 */
	if (iblock_cnt > 0) {
		r = luca_fs_get_inode_dblk_idx_internal(inode_ref, iblock_cnt - 1,
					       goal, false, false);
		if (r != EOK)
			return r;

		if (*goal != 0) {
			(*goal)++;
			return r;
		}

		/* If goal == 0, sparse file -> continue */
	}

	/* Identify block group of inode */

	uint32_t inodes_per_bg = ext4_get32(sb, inodes_per_group);
	uint32_t block_group = (inode_ref->index - 1) / inodes_per_bg;
	block_size = ext4_sb_get_block_size(sb);

	/* Load block group reference */
	struct luca_block_group_ref bg_ref;
	r = luca_fs_get_block_group_ref(inode_ref->fs, block_group, &bg_ref);
	if (r != EOK)
		return r;

	struct ext4_bgroup *bg = bg_ref.block_group;

	/* Compute indexes */
	uint32_t bg_count = ext4_block_group_cnt(sb);
	ext4_fsblk_t itab_first_block = ext4_bg_get_inode_table_first_block(bg, sb);
	uint16_t itab_item_size = ext4_get16(sb, inode_size);
	uint32_t itab_bytes;

	/* Check for last block group */
	if (block_group < bg_count - 1) {
		itab_bytes = inodes_per_bg * itab_item_size;
	} else {
		/* Last block group could be smaller */
		uint32_t inodes_cnt = ext4_get32(sb, inodes_count);

		itab_bytes = (inodes_cnt - ((bg_count - 1) * inodes_per_bg));
		itab_bytes *= itab_item_size;
	}

	ext4_fsblk_t inode_table_blocks = itab_bytes / block_size;

	if (itab_bytes % block_size)
		inode_table_blocks++;

	*goal = itab_first_block + inode_table_blocks;

	return luca_fs_put_block_group_ref(&bg_ref);
}

int luca_fs_get_inode_dblk_idx_internal(luca_inode_ref_t *inode_ref,
				       uint32_t iblock, uint64_t *fblock,
				       bool extent_create,
				       bool support_unwritten __unused)
{
	kprintf("luca_fs_get_inode_dblk_idx_internal调用\n");
	luca_fs_t *fs = inode_ref->fs;

	/* For empty file is situation simple */
	if (luca_inode_get_size(&fs->sb, inode_ref->inode) == 0) {
		*fblock = 0;
		return EOK;
	}

	uint64_t current_block;

	(void)extent_create;
#if CONFIG_EXTENT_ENABLE && CONFIG_EXTENTS_ENABLE
	/* Handle i-node using extents */
	if ((ext4_sb_feature_incom(&fs->sb, EXT4_FINCOM_EXTENTS)) &&
		(to_le32(inode_ref->inode->flags) & EXT4_INODE_FLAG_EXTENTS)) {

		// printf("开启了extent\n");
		uint64_t current_fsblk;
		int rc = luca_extent_get_blocks(inode_ref, iblock, 1,
				&current_fsblk, extent_create, NULL);
		if (rc != EOK)
			return rc;

		current_block = current_fsblk;
		*fblock = current_block;

		ext4_assert(*fblock || support_unwritten);
		return EOK;
	}
#endif

	printf("extent没找到\n");
	struct luca_inode *inode = inode_ref->inode;

	/* Direct block are read directly from array in i-node structure */
	if (iblock < EXT4_INODE_DIRECT_BLOCK_COUNT) {
		current_block = to_le32(inode->blocks[iblock]);
		    //ext4_inode_get_direct_block(inode, (uint32_t)iblock);
		*fblock = current_block;
		return EOK;
	}

	/* Determine indirection level of the target block */
	unsigned int l = 0;
	unsigned int i;
	for (i = 1; i < 4; i++) {
		if (iblock < fs->inode_block_limits[i]) {
			l = i;
			break;
		}
	}

	if (l == 0)
		return EIO;

	/* Compute offsets for the topmost level */
	uint32_t blk_off_in_lvl = (uint32_t)(iblock - fs->inode_block_limits[l - 1]);
	current_block = to_le32(inode->blocks[l - 1 + EXT4_INODE_INDIRECT_BLOCK]);
	//ext4_inode_get_indirect_block(inode, l - 1);
	uint32_t off_in_blk = (uint32_t)(blk_off_in_lvl / fs->inode_blocks_per_level[l - 1]);

	/* Sparse file */
	if (current_block == 0) {
		*fblock = 0;
		return EOK;
	}

	struct luca_block block;

	/*
	 * Navigate through other levels, until we find the block number
	 * or find null reference meaning we are dealing with sparse file
	 */
	while (l > 0) {
		/* Load indirect block */
		int rc = luca_block_get(fs->bdev, &block, current_block);
		if (rc != EOK)
			return rc;

		/* Read block address from indirect block */
		current_block =
		    to_le32(((uint32_t *)block.data)[off_in_blk]);

		/* Put back indirect block untouched */
		rc = luca_block_set(fs->bdev, &block);
		if (rc != EOK)
			return rc;

		/* Check for sparse file */
		if (current_block == 0) {
			*fblock = 0;
			return EOK;
		}

		/* Jump to the next level */
		l--;

		/* Termination condition - we have address of data block loaded
		 */
		if (l == 0)
			break;

		/* Visit the next level */
		blk_off_in_lvl %= fs->inode_blocks_per_level[l];
		off_in_blk = (uint32_t)(blk_off_in_lvl / fs->inode_blocks_per_level[l - 1]);
	}

	*fblock = current_block;

	return EOK;
}

static int luca_fs_set_inode_data_block_index(luca_inode_ref_t *inode_ref,
				       ext4_lblk_t iblock, ext4_fsblk_t fblock)
{
	luca_fs_t *fs = inode_ref->fs;

#if CONFIG_EXTENT_ENABLE && CONFIG_EXTENTS_ENABLE
	/* Handle inode using extents */
	if ((ext4_sb_feature_incom(&fs->sb, EXT4_FINCOM_EXTENTS)) &&
	    (inode_ref->inode->flags & EXT4_INODE_FLAG_EXTENTS)) {
		/* Not reachable */
		return ENOTSUP;
	}
#endif

	/* Handle simple case when we are dealing with direct reference */
	if (iblock < EXT4_INODE_DIRECT_BLOCK_COUNT) {
		// ext4_inode_set_direct_block(inode_ref->inode, (uint32_t)iblock,
		// 			    (uint32_t)fblock);
		inode_ref->inode->blocks[iblock] = to_le32((uint32_t)fblock);
		inode_ref->dirty = true;

		return EOK;
	}

	/* Determine the indirection level needed to get the desired block */
	unsigned int l = 0;
	unsigned int i;
	for (i = 1; i < 4; i++) {
		if (iblock < fs->inode_block_limits[i]) {
			l = i;
			break;
		}
	}

	if (l == 0)
		return EIO;

	uint32_t block_size = ext4_sb_get_block_size(&fs->sb);

	/* Compute offsets for the topmost level */
	uint32_t blk_off_in_lvl = (uint32_t)(iblock - fs->inode_block_limits[l - 1]);
	ext4_fsblk_t current_block = inode_ref->inode->blocks[l - 1 + EXT4_INODE_INDIRECT_BLOCK];
			// ext4_inode_get_indirect_block(inode_ref->inode, l - 1);
	
	uint32_t off_in_blk = (uint32_t)(blk_off_in_lvl / fs->inode_blocks_per_level[l - 1]);

	ext4_fsblk_t new_blk;

	struct luca_block block;
	struct luca_block new_block;

	/* Is needed to allocate indirect block on the i-node level */
	if (current_block == 0) {
		/* Allocate new indirect block */
		ext4_fsblk_t goal;
		int rc = luca_fs_indirect_find_goal(inode_ref, &goal);
		if (rc != EOK)
			return rc;

		//rc = ext4_balloc_alloc_block(inode_ref, goal, &new_blk);
		inode_ref->fs->block_alloc_lock();
		rc = luca_balloc_alloc_block(inode_ref, goal, &new_blk);
		inode_ref->fs->block_alloc_unlock();
		if (rc != EOK)
			return rc;

		/* Update i-node */
		// ext4_inode_set_indirect_block(inode_ref->inode, l - 1,
		// 		(uint32_t)new_blk);
		inode_ref->inode->blocks[l - 1 + EXT4_INODE_INDIRECT_BLOCK] = to_le32((uint32_t)new_blk);

		inode_ref->dirty = true;

		/* Load newly allocated block */
		rc = luca_trans_block_get_noread(fs->bdev, &new_block, new_blk);
		if (rc != EOK) {
			// ext4_balloc_free_block(inode_ref, new_blk);
			inode_ref->fs->block_alloc_lock();
			int rc = luca_balloc_free_block(inode_ref, new_blk);
			inode_ref->fs->block_alloc_unlock();
			return rc;
		}

		/* Initialize new block */
		memset(new_block.data, 0, block_size);
		// ext4_trans_set_block_dirty(new_block.buf);
		luca_bcache_set_dirty(new_block.buf);

		/* Put back the allocated block */
		rc = luca_block_set(fs->bdev, &new_block);
		if (rc != EOK)
			return rc;

		current_block = new_blk;
	}

	/*
	 * Navigate through other levels, until we find the block number
	 * or find null reference meaning we are dealing with sparse file
	 */
	while (l > 0) {
		int rc = luca_block_get(fs->bdev, &block, current_block);
		if (rc != EOK)
			return rc;

		current_block = to_le32(((uint32_t *)block.data)[off_in_blk]);
		if ((l > 1) && (current_block == 0)) {
			ext4_fsblk_t goal;
			rc = luca_fs_indirect_find_goal(inode_ref, &goal);
			if (rc != EOK) {
				luca_block_set(fs->bdev, &block);
				return rc;
			}

			/* Allocate new block */
			// rc =
			//     ext4_balloc_alloc_block(inode_ref, goal, &new_blk);
			inode_ref->fs->block_alloc_lock();
			rc = luca_balloc_alloc_block(inode_ref, goal, &new_blk);
			inode_ref->fs->block_alloc_unlock();
			if (rc != EOK) {
				luca_block_set(fs->bdev, &block);
				return rc;
			}

			/* Load newly allocated block */
			rc = luca_trans_block_get_noread(fs->bdev, &new_block,
					    new_blk);

			if (rc != EOK) {
				luca_block_set(fs->bdev, &block);
				return rc;
			}

			/* Initialize allocated block */
			memset(new_block.data, 0, block_size);
			luca_bcache_set_dirty(new_block.buf);

			rc = luca_block_set(fs->bdev, &new_block);
			if (rc != EOK) {
				luca_block_set(fs->bdev, &block);
				return rc;
			}

			/* Write block address to the parent */
			uint32_t * p = (uint32_t * )block.data;
			p[off_in_blk] = to_le32((uint32_t)new_blk);
			luca_bcache_set_dirty(new_block.buf);
			current_block = new_blk;
		}

		/* Will be finished, write the fblock address */
		if (l == 1) {
			uint32_t * p = (uint32_t * )block.data;
			p[off_in_blk] = to_le32((uint32_t)fblock);
			luca_bcache_set_dirty(new_block.buf);
		}

		rc = luca_block_set(fs->bdev, &block);
		if (rc != EOK)
			return rc;

		l--;

		/*
		 * If we are on the last level, break here as
		 * there is no next level to visit
		 */
		if (l == 0)
			break;

		/* Visit the next level */
		blk_off_in_lvl %= fs->inode_blocks_per_level[l];
		off_in_blk = (uint32_t)(blk_off_in_lvl / fs->inode_blocks_per_level[l - 1]);
	}

	return EOK;
}

int luca_fs_append_inode_dblk(luca_inode_ref_t *inode_ref,
			      ext4_fsblk_t *fblock, ext4_lblk_t *iblock)
{
#if CONFIG_EXTENT_ENABLE && CONFIG_EXTENTS_ENABLE
	/* Handle extents separately */
	if ((ext4_sb_feature_incom(&inode_ref->fs->sb, EXT4_FINCOM_EXTENTS)) &&
		 (inode_ref->inode->flags & EXT4_INODE_FLAG_EXTENTS)) {
		int rc;
		ext4_fsblk_t current_fsblk;
		struct ext4_sblock *sb = &inode_ref->fs->sb;
		uint64_t inode_size = luca_inode_get_size(sb, inode_ref->inode);
		uint32_t block_size = ext4_sb_get_block_size(sb);
		*iblock = (uint32_t)((inode_size + block_size - 1) / block_size);

		rc = luca_extent_get_blocks(inode_ref, *iblock, 1,
						&current_fsblk, true, NULL);
		if (rc != EOK)
			return rc;

		if (fblock) {
			*fblock = current_fsblk;
			ext4_assert(*fblock);
		}

		luca_inode_set_size(inode_ref->inode, inode_size + block_size);
		inode_ref->dirty = true;


		return rc;
	}
#endif
	struct ext4_sblock *sb = &inode_ref->fs->sb;

	/* Compute next block index and allocate data block */
	uint64_t inode_size = luca_inode_get_size(sb, inode_ref->inode);
	uint32_t block_size = ext4_sb_get_block_size(sb);

	/* Align size i-node size */
	if ((inode_size % block_size) != 0)
		inode_size += block_size - (inode_size % block_size);

	/* Logical blocks are numbered from 0 */
	uint32_t new_block_idx = (uint32_t)(inode_size / block_size);

	/* Allocate new physical block */
	ext4_fsblk_t goal, phys_block;
	int rc = luca_fs_indirect_find_goal(inode_ref, &goal);
	if (rc != EOK)
		return rc;

	inode_ref->fs->block_alloc_lock();
	rc = luca_balloc_alloc_block(inode_ref, goal, &phys_block);
	inode_ref->fs->block_alloc_unlock();

	if (rc != EOK)
		return rc;

	/* Add physical block address to the i-node */
	rc = luca_fs_set_inode_data_block_index(inode_ref, new_block_idx,
						phys_block);
	if (rc != EOK) {
		// ext4_balloc_free_block(inode_ref, phys_block);
		inode_ref->fs->block_alloc_lock();
		int rc = luca_balloc_free_block(inode_ref, phys_block);
		inode_ref->fs->block_alloc_unlock();
		return rc;
	}

	/* Update i-node */
	luca_inode_set_size(inode_ref->inode, inode_size + block_size);
	inode_ref->dirty = true;

	if (fblock)
		*fblock = phys_block;
	*iblock = new_block_idx;

	return EOK;
}


void luca_fs_inode_links_count_inc(luca_inode_ref_t *inode_ref)
{
	uint16_t link;
	bool is_dx;
	// link = ext4_inode_get_links_cnt(inode_ref->inode);
	link = to_le16(inode_ref->inode->links_count);
	link++;
	// ext4_inode_set_links_cnt(inode_ref->inode, link);
	inode_ref->inode->links_count = to_le16(link);

	is_dx = ext4_sb_feature_com(&inode_ref->fs->sb, EXT4_FCOM_DIR_INDEX) &&
		/*ext4_inode_has_flag(inode_ref->inode, EXT4_INODE_FLAG_INDEX*/
		(to_le32(inode_ref->inode->flags) & EXT4_INODE_FLAG_INDEX);

	if (is_dx && link > 1) {
		if (link >= EXT4_LINK_MAX || link == 2) {
			// ext4_inode_set_links_cnt(inode_ref->inode, 1);
			inode_ref->inode->links_count = to_le16(1);

			uint32_t v;
			v = ext4_get32(&inode_ref->fs->sb, features_read_only);
			v |= EXT4_FRO_COM_DIR_NLINK;
			ext4_set32(&inode_ref->fs->sb, features_read_only, v);
		}
	}
}

void luca_fs_inode_links_count_dec(luca_inode_ref_t *inode_ref)
{
	// uint16_t links = ext4_inode_get_links_cnt(inode_ref->inode);
	uint16_t links = to_le16(inode_ref->inode->links_count);

	// if (!ext4_inode_is_type(&inode_ref->fs->sb, inode_ref->inode,
	// 			EXT4_INODE_MODE_DIRECTORY)) {
	// 	if (links > 0)
	// 		ext4_inode_set_links_cnt(inode_ref->inode, links - 1);
	// 	return;
	// }
	if((to_le16(inode_ref->inode->mode) & EXT4_INODE_MODE_TYPE_MASK) != EXT4_INODE_MODE_DIRECTORY)
	{
		if(links > 0)
			inode_ref->inode->links_count = to_le16(links - 1);
	}

	if (links > 2)
		inode_ref->inode->links_count = to_le16(links - 1);
		// ext4_inode_set_links_cnt(inode_ref->inode, links - 1);

}