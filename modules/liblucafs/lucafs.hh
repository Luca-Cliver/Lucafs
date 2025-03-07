#ifndef LUCAFS_HH
#define LUCAFS_HH

//#include <ext4_types.h>
#include "tree.h"
#include "queue.h"
#include <ext4_blockdev.h>
#include <ext4_debug.h>
#include <ext4_fs.h>
#include <ext4_super.h>
#include <ext4_crc32.h>
#include <ext4_block_group.h>
#include <ext4_balloc.h>
#include <ext4_bitmap.h>
#include <ext4_ialloc.h>
#include <ext4_types.h>
#include <ext4_hash.h>



struct luca_blockdev;
struct luca_block;
struct luca_buf;
struct luca_bcache;
struct luca_blockdev_iface;
struct luca_block_group_ref;
struct luca_inode_ref;
struct luca_inode;
struct luca_bgroup;
struct luca_fs;
struct luca_dir_iter;
struct luca_dir_search_result;
struct luca_dir_idx_block;

typedef struct luca_blockdev luca_blockdev_t;

typedef struct luca_bcache luca_bcache_t;

typedef struct luca_inode_ref luca_inode_ref_t;



/*************block cache 相关定义****************/
// typedef struct ext4_bcache luca_bcache_t;

struct luca_block {
	/*Logical block ID*/
	uint64_t lb_id;
	/*Buffer */
	struct luca_buf *buf;
	/*Data buffer.*/
	uint8_t *data;
};

/*Single block descriptor*/
struct luca_buf {
	char flags[BC_TMP + 1];

	/*Logical block address*/
	uint64_t lba;

	/*Data buffer.*/
	uint8_t *data;

	// /*LRU priority. (unused) */
	// uint32_t lru_prio;

	/*LRU id.*/
	uint32_t lru_id;

	/*Reference count table*/
	uint32_t refctr;

	/*The block cache this buffer belongs to. */
	luca_bcache_t *bc;

	bool on_dirty_list;

	/*LBA tree node*/
	RB_ENTRY(luca_buf) lba_node;

	/*LRU tree node*/
	RB_ENTRY(luca_buf) lru_node;

	/*Dirty list node*/
	SLIST_ENTRY(luca_buf) dirty_node;

	/**@brief   Callback routine after a disk-write operation.
	 * @param   bc block cache descriptor
	 * @param   buf buffer descriptor
	 * @param   standard error code returned by bdev->bwrite()
	 * @param   arg argument passed to this routine*/
	void (*end_write)(luca_bcache_t *bc,
			  struct luca_buf *buf,
			  int res,
			  void *arg);

	/*argument passed to end_write() callback.*/
	void *end_write_arg;
};

struct luca_buf_lba {								\
		struct luca_buf *rbh_root; /* root of the tree */			\
	} ;

struct luca_buf_lru { struct luca_buf *rbh_root; };

struct luca_bcache {

	/*Item count in block cache*/
	uint32_t cnt;

	/*Item size in block cache*/
	uint32_t itemsize;

	/*Last recently used counter*/
	uint32_t lru_ctr;

	/*Currently referenced datablocks*/
	uint32_t ref_blocks;

	/*Maximum referenced datablocks*/
	uint32_t max_ref_blocks;

	/*The blockdev binded to this block cache*/
	luca_blockdev_t *bdev;

	/*The cache should not be shaked */
	bool dont_shake;

	/*A tree holding all bufs*/
	// RB_HEAD(luca_buf_lba, luca_buf) lba_root;
	struct luca_buf_lba lba_root;

	/* A tree holding unreferenced bufs*/
	//RB_HEAD(luca_buf_lru, luca_buf) lru_root;
	struct luca_buf_lru lru_root;

	/*A singly-linked list holding dirty buffers*/
	SLIST_HEAD(luca_buf_dirty, luca_buf) dirty_list;
};

// typedef struct luca_bcache luca_bcache_t;

#define luca_bcache_set_flag(buf, b)    \
	(buf)->flags[b] = 1

#define luca_bcache_clear_flag(buf, b)    \
	(buf)->flags[b] = 0

#define luca_bcache_test_flag(buf, b)    \
	(((buf)->flags[b] == 1 ))

static inline void luca_bcache_set_dirty(struct luca_buf *buf) {
	luca_bcache_set_flag(buf, BC_UPTODATE);
	luca_bcache_set_flag(buf, BC_DIRTY);
}

static inline void luca_bcache_clear_dirty(struct luca_buf *buf) {
	luca_bcache_clear_flag(buf, BC_UPTODATE);
	luca_bcache_clear_flag(buf, BC_DIRTY);
}

/**@brief   Increment reference counter of buf by 1.*/
#define luca_bcache_inc_ref(buf) ((buf)->refctr++)

/**@brief   Decrement reference counter of buf by 1.*/
#define luca_bcache_dec_ref(buf) ((buf)->refctr--)

/**@brief   Insert buffer to dirty cache list
 * @param   bc block cache descriptor
 * @param   buf buffer descriptor */
static inline void
luca_bcache_insert_dirty_node(luca_bcache_t *bc, struct luca_buf *buf) {
	if (!buf->on_dirty_list) {
		SLIST_INSERT_HEAD(&bc->dirty_list, buf, dirty_node);
		buf->on_dirty_list = true;
	}
}

/**@brief   Remove buffer to dirty cache list
 * @param   bc block cache descriptor
 * @param   buf buffer descriptor */
static inline void
luca_bcache_remove_dirty_node(luca_bcache_t *bc, struct luca_buf *buf) {
	if (buf->on_dirty_list) {
		SLIST_REMOVE(&bc->dirty_list, buf, luca_buf, dirty_node);
		buf->on_dirty_list = false;
	}
}







/**************block dev相关定义**************/
struct luca_blockdev {
	struct luca_blockdev_iface *bdif; //块设备接口的指针，复用了lwext
	uint64_t part_offset; //该分区在块设备中的偏移量
	uint64_t part_size; //分区的大小
	luca_bcache_t *bc; //块缓存
	uint32_t lg_bsize; //逻辑块大小
	uint64_t lg_bcnt; //逻辑块数量
	uint32_t cache_write_back; //缓存写回模式的引用计数器
	struct luca_fs *fs; //所属的文件系统
	void *journal; //日志系统，暂未实现
};
//typedef struct luca_blockdev luca_blockdev_t;

struct luca_blockdev_iface {
	int (*open)(luca_blockdev_t *bdev);

	int (*bread)(luca_blockdev_t *bdev, void *buf, uint64_t blk_id,
		     uint32_t blk_cnt);

	int (*bwrite)(luca_blockdev_t *bdev, const void *buf,
		      uint64_t blk_id, uint32_t blk_cnt);

	int (*close)(luca_blockdev_t *bdev);

	int (*lock)(luca_blockdev_t *bdev);

	int (*unlock)(luca_blockdev_t *bdev);

	/*物理块size*/
	uint32_t ph_bsize;

	/*物理块count*/
	uint64_t ph_bcnt;

	/*Block size buffer: physical*/
	uint8_t *ph_bbuf;

	/*Reference counter to block device interface*/
	uint32_t ph_refctr;

	/*Physical read counter*/
	uint32_t bread_ctr;

	/*Physical write counter*/
	uint32_t bwrite_ctr;

	/*User data pointer*/
	void* p_user;
};



#define LUCA_MIN_BLOCK_GROUP_DESCRIPTOR_SIZE 32
#define LUCA_MAX_BLOCK_GROUP_DESCRIPTOR_SIZE 64

#define LUCA_MIN_BLOCK_SIZE 1024  /* 1 KiB */
#define LUCA_MAX_BLOCK_SIZE 65536 /* 64 KiB */
#define LUCA_REV0_INODE_SIZE 128





/*superblcok相关*/
typedef struct ext4_sblock luca_sblock_t;


#define LUCA_SUPERBLOCK_MAGIC 0xEF53
#define LUCA_SUPERBLOCK_SIZE 1024
#define LUCA_SUPERBLOCK_OFFSET 1024

#define LUCA_SUPERBLOCK_OS_LINUX 0
#define LUCA_SUPERBLOCK_OS_HURD 1

/*
 * Misc. filesystem flags
 */
#define LUCA_SUPERBLOCK_FLAGS_SIGNED_HASH 0x0001
#define LUCA_SUPERBLOCK_FLAGS_UNSIGNED_HASH 0x0002
#define LUCA_SUPERBLOCK_FLAGS_TEST_FILESYS 0x0004
/*
 * Filesystem states
 */
#define LUCA_SUPERBLOCK_STATE_VALID_FS 0x0001  /* Unmounted cleanly */
#define LUCA_SUPERBLOCK_STATE_ERROR_FS 0x0002  /* Errors detected */
#define LUCA_SUPERBLOCK_STATE_ORPHAN_FS 0x0004 /* Orphans being recovered */

/*
 * Behaviour when errors detected
 */
#define LUCA_SUPERBLOCK_ERRORS_CONTINUE 1 /* Continue execution */
#define LUCA_SUPERBLOCK_ERRORS_RO 2       /* Remount fs read-only */
#define LUCA_SUPERBLOCK_ERRORS_PANIC 3    /* Panic */
//#define LUCA_SUPERBLOCK_ERRORS_DEFAULT LUCA_ERRORS_CONTINUE

/*
 * Compatible features
 */
#define LUCA_FCOM_DIR_PREALLOC 0x0001
#define LUCA_FCOM_IMAGIC_INODES 0x0002
#define LUCA_FCOM_HAS_JOURNAL 0x0004
#define LUCA_FCOM_EXT_ATTR 0x0008
#define LUCA_FCOM_RESIZE_INODE 0x0010
#define LUCA_FCOM_DIR_INDEX 0x0020

/*
 * Read-only compatible features
 */
#define LUCA_FRO_COM_SPARSE_SUPER 0x0001
#define LUCA_FRO_COM_LARGE_FILE 0x0002
#define LUCA_FRO_COM_BTREE_DIR 0x0004
#define LUCA_FRO_COM_HUGE_FILE 0x0008
#define LUCA_FRO_COM_GDT_CSUM 0x0010
#define LUCA_FRO_COM_DIR_NLINK 0x0020
#define LUCA_FRO_COM_EXTRA_ISIZE 0x0040
#define LUCA_FRO_COM_QUOTA 0x0100
#define LUCA_FRO_COM_BIGALLOC 0x0200
#define LUCA_FRO_COM_METADATA_CSUM 0x0400

/*
 * Incompatible features
 */
#define LUCA_FINCOM_COMPRESSION 0x0001
#define LUCA_FINCOM_FILETYPE 0x0002
#define LUCA_FINCOM_RECOVER 0x0004     /* Needs recovery */
#define LUCA_FINCOM_JOURNAL_DEV 0x0008 /* Journal device */
#define LUCA_FINCOM_META_BG 0x0010
#define LUCA_FINCOM_EXTENTS 0x0040 /* extents support */
#define LUCA_FINCOM_64BIT 0x0080
#define LUCA_FINCOM_MMP 0x0100
#define LUCA_FINCOM_FLEX_BG 0x0200
#define LUCA_FINCOM_EA_INODE 0x0400	 /* EA in inode */
#define LUCA_FINCOM_DIRDATA 0x1000	  /* data in dirent */
#define LUCA_FINCOM_BG_USE_META_CSUM 0x2000 /* use crc32c for bg */
#define LUCA_FINCOM_LARGEDIR 0x4000	 /* >2GB or 3-lvl htree */
#define LUCA_FINCOM_INLINE_DATA 0x8000      /* data in inode */

int luca_sb_write(luca_blockdev_t *bdev, luca_sblock_t *s);







#define LUCA_MIN_BLOCK_GROUP_DESCRIPTOR_SIZE 32
#define LUCA_MAX_BLOCK_GROUP_DESCRIPTOR_SIZE 64

#define LUCA_MIN_BLOCK_SIZE 1024  /* 1 KiB */
#define LUCA_MAX_BLOCK_SIZE 65536 /* 64 KiB */
#define LUCA_REV0_INODE_SIZE 128








/*inode相关*/
//typedef struct ext4_inode_ref luca_inode_ref_t;

struct luca_inode {
	uint16_t mode;		    /* File mode */
	uint16_t uid;		    /* Low 16 bits of owner uid */
	uint32_t size_lo;	   /* Size in bytes */
	uint32_t access_time;       /* Access time */
	uint32_t change_inode_time; /* I-node change time */
	uint32_t modification_time; /* Modification time */
	uint32_t deletion_time;     /* Deletion time */
	uint16_t gid;		    /* Low 16 bits of group id */
	uint16_t links_count;       /* Links count */
	uint32_t blocks_count_lo;   /* Blocks count */
	uint32_t flags;		    /* File flags */
	uint32_t unused_osd1;       /* OS dependent - not used in HelenOS */
	uint32_t blocks[EXT4_INODE_BLOCKS]; /* Pointers to blocks */ 
	uint32_t generation;		    /* File version (for NFS) */
	uint32_t file_acl_lo;		    /* File ACL */
	uint32_t size_hi;
	uint32_t obso_faddr; /* Obsoleted fragment address */

	// union {
	// 	struct {
	// 		uint16_t blocks_high;
	// 		uint16_t file_acl_high;
	// 		uint16_t uid_high;
	// 		uint16_t gid_high;
	// 		uint16_t checksum_lo; /* crc32c(uuid+inum+inode) LE */
	// 		uint16_t reserved2;
	// 	} linux2;
	// 	struct {
	// 		uint16_t reserved1;
	// 		uint16_t mode_high;
	// 		uint16_t uid_high;
	// 		uint16_t gid_high;
	// 		uint32_t author;
	// 	} hurd2;
	// } osd2;

	uint16_t blocks_high;
	uint16_t file_acl_high;
	uint16_t uid_high;
	uint16_t gid_high;
	uint16_t checksum_lo; /* crc32c(uuid+inum+inode) LE */
	uint16_t reserved2;


	uint16_t extra_isize;
	uint16_t checksum_hi;	/* crc32c(uuid+inum+inode) BE */
	uint32_t ctime_extra; /* Extra change time (nsec << 2 | epoch) */
	uint32_t mtime_extra; /* Extra Modification time (nsec << 2 | epoch) */
	uint32_t atime_extra; /* Extra Access time (nsec << 2 | epoch) */
	uint32_t crtime;      /* File creation time */
	uint32_t
	    crtime_extra;    /* Extra file creation time (nsec << 2 | epoch) */
	uint32_t version_hi; /* High 32 bits for 64-bit version */
};

#define LUCA_INODE_BLOCK_SIZE 512

#define LUCA_INODE_DIRECT_BLOCK_COUNT 12
#define LUCA_INODE_INDIRECT_BLOCK LUCA_INODE_DIRECT_BLOCK_COUNT
#define LUCA_INODE_DOUBLE_INDIRECT_BLOCK (LUCA_INODE_INDIRECT_BLOCK + 1)
#define LUCA_INODE_TRIPPLE_INDIRECT_BLOCK (LUCA_INODE_DOUBLE_INDIRECT_BLOCK + 1)
#define LUCA_INODE_BLOCKS (LUCA_INODE_TRIPPLE_INDIRECT_BLOCK + 1)
#define LUCA_INODE_INDIRECT_BLOCK_COUNT                                        \
	(LUCA_INODE_BLOCKS - LUCA_INODE_DIRECT_BLOCK_COUNT)


#define LUCA_INODE_MODE_FIFO 0x1000
#define LUCA_INODE_MODE_CHARDEV 0x2000
#define LUCA_INODE_MODE_DIRECTORY 0x4000
#define LUCA_INODE_MODE_BLOCKDEV 0x6000
#define LUCA_INODE_MODE_FILE 0x8000
#define LUCA_INODE_MODE_SOFTLINK 0xA000
#define LUCA_INODE_MODE_SOCKET 0xC000
#define LUCA_INODE_MODE_TYPE_MASK 0xF000

enum { LUCA_DE_UNKNOWN = 0,
       LUCA_DE_REG_FILE,
       LUCA_DE_DIR,
       LUCA_DE_CHRDEV,
       LUCA_DE_BLKDEV,
       LUCA_DE_FIFO,
       LUCA_DE_SOCK,
       LUCA_DE_SYMLINK };





struct luca_dir_idx_block {
	struct luca_block b;
	struct ext4_dir_idx_entry *entries;
	struct ext4_dir_idx_entry *position;
};


struct luca_dir_iter{
	luca_inode_ref_t *inode_ref;
	struct luca_block curr_blk;
	uint64_t curr_off;
	struct ext4_dir_en *curr;
};

struct luca_dir_search_result {
	struct luca_block block;
	struct ext4_dir_en *dentry;
};






// typedef struct ext4_fs luca_fs_t;

struct luca_fs {
	bool read_only;

	struct luca_blockdev *bdev;
	struct ext4_sblock sb;

	uint64_t inode_block_limits[4];
	uint64_t inode_blocks_per_level[4];

	uint32_t last_inode_bg_id;

	// struct jbd_fs *jbd_fs;
	// struct jbd_journal *jbd_journal;
	// struct jbd_trans *curr_trans;

	void (*inode_alloc_lock)();
	void (*inode_alloc_unlock)();

	void (*block_alloc_lock)();
	void (*block_alloc_unlock)();

	void (*bcache_lock)();
	void (*bcache_unlock)();
};
typedef struct luca_fs luca_fs_t;

struct luca_block_group_ref {
	struct luca_block block;
	struct ext4_bgroup *block_group;
	luca_fs_t *fs;
	uint32_t index;
	bool dirty;
};
typedef struct luca_block_group_ref luca_block_group_ref_t;

struct luca_inode_ref {
	struct luca_block block;
	struct luca_inode *inode;
	luca_fs_t *fs;
	uint32_t index;
	bool dirty;
};
//typedef struct luca_inode_ref luca_inode_ref_t;

static int blockdev_bread(luca_blockdev_t *bdev, void *buf, uint64_t blk_id, uint32_t blk_cnt);

static int blockdev_bwrite(luca_blockdev_t *bdev, const void *buf,
                           uint64_t blk_id, uint32_t blk_cnt);

static inline uint32_t luca_sb_get_block_size(luca_sblock_t *s)
{
	return 1024 << to_le32(s->log_block_size);
}

/*blockdev相关*/
int luca_block_readbytes(luca_blockdev_t *bdev, uint64_t off, void *buf,
			 uint32_t len);

int luca_block_writebytes(luca_blockdev_t *bdev, uint64_t off,
			  const void *buf, uint32_t len);

int luca_blocks_get_direct(luca_blockdev_t *bdev, void *buf, uint64_t lba,
			   uint32_t cnt);

int luca_blocks_set_direct(luca_blockdev_t *bdev, const void *buf,
			   uint64_t lba, uint32_t cnt);

int luca_block_fini(luca_blockdev_t *bdev);

int luca_trans_block_get_noread(luca_blockdev_t *bdev,
			  struct luca_block *b,
			  uint64_t lba);

int luca_block_get_noread(luca_blockdev_t *bdev, struct luca_block *b,
			  uint64_t lba);

int luca_block_get(luca_blockdev_t *bdev, struct luca_block *b,
		   uint64_t lba);

int luca_block_set(luca_blockdev_t *bdev, struct luca_block *b);

int luca_block_cache_flush(luca_blockdev_t *bdev);

int luca_block_cache_write_back(luca_blockdev_t *bdev, uint8_t on_off);


/*bcache相关函数*/
int luca_bcache_init_dynamic(luca_bcache_t *bc, uint32_t cnt,
			     uint32_t itemsize);

int luca_bcache_fini_dynamic(luca_bcache_t *bc);

int luca_block_bind_bcache(luca_blockdev_t *bdev, luca_bcache_t *bc);

int luca_block_flush_buf(luca_blockdev_t*bdev, struct luca_buf *buf);

void luca_bcache_cleanup(luca_bcache_t *bc);

void luca_bcache_drop_buf(luca_bcache_t *bc, struct luca_buf *buf);

static void luca_buf_free(struct luca_buf *buf);

int luca_bcache_alloc(struct luca_bcache *bc, struct luca_block *b,
		      bool *is_new);

int luca_bcache_free(struct luca_bcache *bc, struct luca_block *b);

int luca_block_cache_shake(luca_blockdev_t *bdev);

struct luca_buf *
luca_bcache_find_get(struct luca_bcache *bc, struct luca_block *b,
		     uint64_t lba);

void luca_bcache_invalidate_lba(luca_bcache_t *bc,
				uint64_t from,
				uint32_t cnt);



/*bgroup相关函数*/
int luca_fs_get_block_group_ref(luca_fs_t *fs, uint32_t bgid,
				luca_block_group_ref_t *ref);

uint64_t luca_inode_get_size(luca_sblock_t *sb, struct luca_inode *inode);

/*inode相关函数*/
void luca_inode_clear_flag(struct luca_inode *inode, uint32_t f);

void luca_inode_set_size(struct luca_inode *inode, uint64_t size);

static uint32_t luca_inode_block_bits_count(uint32_t block_size);

uint32_t luca_inode_type(luca_sblock_t*sb, struct luca_inode *inode);

void luca_inode_set_flag(struct luca_inode *inode, uint32_t f);

uint64_t luca_inode_get_size(luca_sblock_t *sb, struct luca_inode *inode);

uint32_t luca_inode_get_csum(luca_sblock_t *sb, struct luca_inode *inode);

void luca_inode_set_csum(luca_sblock_t *sb, struct luca_inode *inode,
			uint32_t checksum);

static int luca_fs_get_inode_ref(luca_fs_t *fs, uint32_t index,
			luca_inode_ref_t *ref, bool initialized);

int luca_fs_get_inode_ref(luca_fs_t *fs, uint32_t index,
			  luca_inode_ref_t *ref);

int luca_fs_put_inode_ref(luca_inode_ref_t *ref);

uint64_t luca_inode_get_blocks_count(luca_sblock_t *sb,
				     struct luca_inode *inode);

int luca_inode_set_blocks_count(luca_sblock_t *sb,
				struct luca_inode *inode, uint64_t count);

/*balloc相关*/
static bool luca_balloc_verify_bitmap_csum(luca_sblock_t *sb,
			       struct ext4_bgroup *bg,
			       void *bitmap __unused);

int luca_balloc_alloc_block(luca_inode_ref_t *inode_ref,
			    uint64_t goal,
			    uint64_t *fblock);

int
luca_balloc_free_block(luca_inode_ref_t *inode_ref, ext4_fsblk_t baddr);

int
luca_balloc_free_blocks(luca_inode_ref_t *inode_ref,
			    uint64_t first, uint32_t count);


/*extent相关*/
int luca_extent_get_blocks(luca_inode_ref_t *inode_ref, uint32_t iblock,
			   uint32_t max_blocks, uint64_t *result,
			   bool create, uint32_t *blocks_count);

void luca_extent_tree_init(luca_inode_ref_t *inode_ref);

int luca_extent_remove_space(luca_inode_ref_t *inode_ref, ext4_lblk_t from,
			     ext4_lblk_t to);


/*dir相关*/
static struct ext4_dir_entry_tail *
luca_dir_get_tail(luca_inode_ref_t *inode_ref,
		struct ext4_dir_en *de);

static uint32_t luca_dir_csum(luca_inode_ref_t *inode_ref,
			      struct ext4_dir_en *dirent, int size);

bool luca_dir_csum_verify(luca_inode_ref_t *inode_ref,
			      struct ext4_dir_en *dirent);

int luca_dir_dx_init(luca_inode_ref_t *dir, luca_inode_ref_t *parent);

int luca_dir_dx_reset_parent_inode(luca_inode_ref_t *dir,
                                   uint32_t parent_inode);




void luca_dir_init_entry_tail(struct ext4_dir_entry_tail *t);


static int luca_dir_iterator_set(struct luca_dir_iter *it,
				 uint32_t block_size);

static int luca_dir_iterator_seek(struct luca_dir_iter *it, uint64_t pos);

int luca_dir_iterator_init(struct luca_dir_iter *it,
			   luca_inode_ref_t *inode_ref, uint64_t pos);

int luca_dir_iterator_next(struct luca_dir_iter *it);

int luca_dir_iterator_fini(struct luca_dir_iter *it);

void luca_dir_write_entry(luca_sblock_t*sb, struct ext4_dir_en *en,
			  uint16_t entry_len, luca_inode_ref_t *child,
			  const char *name, size_t name_len);

void luca_dir_set_csum(luca_inode_ref_t *inode_ref,
			   struct ext4_dir_en *dirent);

int luca_dir_add_entry(luca_inode_ref_t *parent, const char *name,
		       uint32_t name_len, luca_inode_ref_t *child);

int luca_dir_find_entry(struct luca_dir_search_result *result,
			luca_inode_ref_t *parent, const char *name,
			uint32_t name_len);

int luca_dir_remove_entry(luca_inode_ref_t *parent, const char *name,
			  uint32_t name_len);

int luca_dir_try_insert_entry(luca_sblock_t *sb,
			      luca_inode_ref_t *inode_ref,
			      struct luca_block *dst_blk,
			      luca_inode_ref_t *child, const char *name,
			      uint32_t name_len);

int luca_dir_find_in_block(struct luca_block *block, luca_sblock_t *sb,
			   size_t name_len, const char *name,
			   struct ext4_dir_en **res_entry);

int luca_dir_destroy_result(luca_inode_ref_t *parent,
			    struct luca_dir_search_result *result);











				

/*lucafs相关*/
static uint64_t luca_fs_get_descriptor_block(luca_sblock_t *s,
					     uint32_t bgid,
					     uint32_t dsc_per_block);

static void luca_fs_mark_bitmap_end(int start_bit, int end_bit, void *bitmap);

static int luca_fs_init_block_bitmap(luca_block_group_ref_t *bg_ref);
						
static int luca_fs_init_inode_bitmap(luca_block_group_ref_t *bg_ref);

static int luca_fs_init_inode_table(luca_block_group_ref_t *bg_ref);

int luca_fs_put_block_group_ref(luca_block_group_ref_t *ref);

static uint16_t luca_fs_bg_checksum(luca_sblock_t *sb, uint32_t bgid,
				    struct ext4_bgroup *bg);

static uint32_t luca_fs_inode_checksum(luca_inode_ref_t *inode_ref);

static void luca_fs_set_inode_checksum(luca_inode_ref_t *inode_ref);

static bool luca_fs_verify_bg_csum(luca_sblock_t*sb,
				   uint32_t bgid,
				   struct ext4_bgroup *bg);

static bool luca_fs_verify_inode_csum(luca_inode_ref_t *inode_ref);

void luca_fs_inode_blocks_init(luca_fs_t *fs,
			       luca_inode_ref_t *inode_ref);

int luca_fs_alloc_inode(luca_fs_t *fs, luca_inode_ref_t *inode_ref,
			int filetype);

int luca_fs_free_inode(luca_inode_ref_t *inode_ref);

static int luca_fs_release_inode_block(luca_inode_ref_t *inode_ref,
				ext4_lblk_t iblock);

int luca_fs_truncate_inode(luca_inode_ref_t *inode_ref, uint64_t new_size);

uint64_t luca_fs_inode_to_goal_block(luca_inode_ref_t *inode_ref);


int luca_fs_get_inode_dblk_idx_internal(luca_inode_ref_t *inode_ref,
				       uint32_t iblock, uint64_t *fblock,
				       bool extent_create,
				       bool support_unwritten __unused);

static int luca_fs_set_inode_data_block_index(luca_inode_ref_t *inode_ref,
				       ext4_lblk_t iblock, ext4_fsblk_t fblock);

int luca_fs_append_inode_dblk(luca_inode_ref_t *inode_ref,
			      ext4_fsblk_t *fblock, ext4_lblk_t *iblock);

int luca_fs_indirect_find_goal(luca_inode_ref_t *inode_ref,
			       ext4_fsblk_t *goal);

void luca_fs_inode_links_count_inc(luca_inode_ref_t *inode_ref);

void luca_fs_inode_links_count_dec(luca_inode_ref_t *inode_ref);
#endif // LUCAFS_HH