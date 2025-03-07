extern "C" {
#define USE_C_INTERFACE 1
#include <osv/device.h>
#include <osv/bio.h>
#include <osv/prex.h>
#include <osv/vnode.h>
#include <osv/mount.h>
#include <osv/debug.h>

void* alloc_contiguous_aligned(size_t size, size_t align);
void free_contiguous_aligned(void* p);
}

// #include <ext4_blockdev.h>
// #include <ext4_debug.h>
// #include <ext4_fs.h>
// #include <ext4_super.h>

#include <cstdlib>
#include <cstddef>
#include <cstdio>

#include "lucafs.hh"

//#define CONF_debug_ext 1
#if CONF_debug_ext
#define ext_debug(format,...) kprintf("[ext4] " format, ##__VA_ARGS__)
#else
#define ext_debug(...)
#endif

extern "C" bool is_linear_mapped(const void *addr);

int ext_init(void) { return 0;}

static int blockdev_open(luca_blockdev_t *bdev)
{
    return EOK;
}

int luca_block_init(luca_blockdev_t *bdev)
{
	int rc;
	ext4_assert(bdev);
	ext4_assert(bdev->bdif);
	ext4_assert(bdev->bdif->open &&
		   bdev->bdif->close &&
		   bdev->bdif->bread &&
		   bdev->bdif->bwrite);

	if (bdev->bdif->ph_refctr) {
		bdev->bdif->ph_refctr++;
		return EOK;
	}

	/*Low level block init*/
	rc = bdev->bdif->open(bdev);
	if (rc != EOK)
		return rc;

	bdev->bdif->ph_refctr = 1;
	return EOK;
}

int luca_fs_init(luca_fs_t *fs, luca_blockdev_t *bdev,
		 bool read_only)
{
	int r, i;
	uint16_t tmp;
	uint32_t bsize;

	ext4_assert(fs && bdev);

	fs->bdev = bdev;

	fs->read_only = read_only;

	//r = ext4_sb_read(fs->bdev, &fs->sb);
    /*读取超级块*/
    printf("fs init测试1\n");
    r = luca_block_readbytes(fs->bdev, LUCA_SUPERBLOCK_OFFSET, &fs->sb, LUCA_SUPERBLOCK_SIZE);
	if (r != EOK)
		return r;

	// if (!ext4_sb_check(&fs->sb))
	// 	return ENOTSUP;
    printf("fs init测试2\n");
    if(fs->sb.magic != LUCA_SUPERBLOCK_MAGIC)
        return ENOTSUP;


    printf("fs init测试3\n");
	bsize = ext4_sb_get_block_size(&fs->sb);
    //bsize = 1024 << fs->sb.log_block_size;
    printf("block size: %d\n", bsize);
	if (bsize > EXT4_MAX_BLOCK_SIZE)
		return ENXIO;

	// r = ext4_fs_check_features(fs, &read_only);
	// if (r != EOK)
	// 	return r;

	if (read_only)
		fs->read_only = read_only;

	/* Compute limits for indirect block levels */
	uint32_t blocks_id = bsize / sizeof(uint32_t);

    /*12个直接指针，柒雨每级1个*/
	fs->inode_block_limits[0] = LUCA_INODE_DIRECT_BLOCK_COUNT;
	fs->inode_blocks_per_level[0] = 1;

	for (i = 1; i < 4; i++) {
		fs->inode_blocks_per_level[i] =
		    fs->inode_blocks_per_level[i - 1] * blocks_id;
		fs->inode_block_limits[i] = fs->inode_block_limits[i - 1] +
					    fs->inode_blocks_per_level[i];
	}

	/*Validate FS*/
	//tmp = ext4_get16(&fs->sb, state);
    tmp = fs->sb.state;
	if (tmp & LUCA_SUPERBLOCK_STATE_ERROR_FS)
        kprintf("last umount error: superblock fs_error flag\n");
		// ext4_dbg(DEBUG_FS, DBG_WARN
		// 		"last umount error: superblock fs_error flag\n");


	if (!fs->read_only) {
		/* Mark system as mounted */
		ext4_set16(&fs->sb, state, EXT4_SUPERBLOCK_STATE_ERROR_FS);
        //fs->sb.state = LUCA_SUPERBLOCK_STATE_ERROR_FS;
		r = luca_sb_write(fs->bdev, &fs->sb);


		if (r != EOK)
			return r;

		/*Update mount count*/
		ext4_set16(&fs->sb, mount_count, ext4_get16(&fs->sb, mount_count) + 1);
	}

	return r;
}


static int blockdev_bread_or_write(luca_blockdev_t *bdev, void *buf, uint64_t blk_id, uint32_t blk_cnt, bool read)
{
    struct bio *bio = alloc_bio();
    if (!bio)
        return ENOMEM;

    bio->bio_cmd = read ? BIO_READ : BIO_WRITE;
    bio->bio_dev = (struct device*)bdev->bdif->p_user;
    bio->bio_offset = blk_id * bdev->bdif->ph_bsize;
    bio->bio_bcount = blk_cnt * bdev->bdif->ph_bsize;

    if (!is_linear_mapped(buf)) {
        bio->bio_data = alloc_contiguous_aligned(bio->bio_bcount, alignof(std::max_align_t));
        if (!read) {
            memcpy(bio->bio_data, buf, bio->bio_bcount);
        }
    } else {
        bio->bio_data = buf;
    }

    bio->bio_dev->driver->devops->strategy(bio);
    int error = bio_wait(bio);

    ext_debug("%s %ld bytes at offset %ld to %p with error:%d\n", read ? "Read" : "Wrote",
        bio->bio_bcount, bio->bio_offset, bio->bio_data, error);

    if (!is_linear_mapped(buf)) {
        if (read && !error) {
            memcpy(buf, bio->bio_data, bio->bio_bcount);
        }
        free_contiguous_aligned(bio->bio_data);
    }
    destroy_bio(bio);

    return error;
}

static int blockdev_bread(luca_blockdev_t *bdev, void *buf, uint64_t blk_id, uint32_t blk_cnt)
{
    return blockdev_bread_or_write(bdev, buf, blk_id, blk_cnt, true);
}

static int blockdev_bwrite(luca_blockdev_t *bdev, const void *buf,
                           uint64_t blk_id, uint32_t blk_cnt)
{
    return blockdev_bread_or_write(bdev, const_cast<void *>(buf), blk_id, blk_cnt, false);
}

static int blockdev_close(luca_blockdev_t *bdev)
{
    return EOK;
}

// LUCA_BLOCKDEV_STATIC_INSTANCE(luca_blockdev, 512, 0, blockdev_open,
//                               blockdev_bread, blockdev_bwrite, blockdev_close, 0, 0);

static uint8_t luca_blockdev_ph_bbuf[512]; // 定义一个静态缓冲区
static struct luca_blockdev_iface luca_blockdev_iface = { // 定义并初始化块设备接口
    .open = blockdev_open,
    .bread = blockdev_bread,
    .bwrite = blockdev_bwrite,
    .close = blockdev_close,
    .lock = 0,
    .unlock = 0,
    .ph_bsize = 512,
    .ph_bcnt = 0,
    .ph_bbuf = luca_blockdev_ph_bbuf,
};
static luca_blockdev_t luca_blockdev = { // 定义并初始化 luca_blockdev_t 类型的结构体
    .bdif = &luca_blockdev_iface,
    .part_offset = 0,
    .part_size = 0 * 512,
};

static luca_fs_t luca_fs;
static luca_bcache_t luca_block_cache;
extern struct vnops luca_vnops;

int luca_blockcache_init(luca_fs_t *fs, luca_blockdev_t *bdev, luca_bcache_t *bcache)
{
    uint32_t bsize = ext4_sb_get_block_size(&fs->sb);
    //ext4_block_set_lb_size(bdev, bsize);
    /*设置bdev中的块大小和数目*/
    ext4_assert(!(bsize % bdev->bdif->ph_bsize));
    bdev->lg_bsize = bsize;
	bdev->lg_bcnt = bdev->part_size / bsize;

    int r = luca_bcache_init_dynamic(bcache, CONFIG_BLOCK_DEV_CACHE_SIZE, bsize);
    if(r != EOK) {
        return r;
    }
    
    if(bsize != bcache->itemsize)
        return ENOTSUP;

    r = luca_block_bind_bcache(bdev, bcache);
    if(r != EOK) {
        luca_bcache_cleanup(bcache);
        luca_block_fini(bdev);
        luca_bcache_fini_dynamic(bcache);
        return r;
    }

    return EOK;
}


//inode, block和bcache的锁
static mutex_t luca_inode_alloc_mutex;
static void luca_inode_alloc_lock()
{
    mutex_lock(&luca_inode_alloc_mutex);
}

static void luca_inode_alloc_unlock()
{
    mutex_unlock(&luca_inode_alloc_mutex);
}


static mutex_t luca_block_alloc_mutex;
static void luca_block_alloc_lock()
{
    mutex_lock(&luca_block_alloc_mutex);
}

static void luca_block_alloc_unlock()
{
    mutex_unlock(&luca_block_alloc_mutex);
}


static mutex_t luca_bcache_mutex;
static void luca_bcache_lock()
{
    mutex_lock(&luca_bcache_mutex);
}

static void luca_bcache_unlock()
{
    mutex_unlock(&luca_bcache_mutex);
}


static int luca_mount(struct mount *mp, const char *dev, int flags, const void *data)
{
    struct device *device;

    printf("进入了luca_mount magic=%d\n", luca_fs.sb.magic);
    const char *dev_name = dev + 5;  //跳过前缀名 /dev/
    int error = device_open(dev_name, DO_RDWR, &device);
    if (error) {
        //先用的printf
        printf("[lucafs] Error opening device!\n");
        return error;
    }

    //初始化inode, block和bcache的锁
    mutex_init(&luca_inode_alloc_mutex);
    luca_fs.inode_alloc_lock = luca_inode_alloc_lock;
    luca_fs.inode_alloc_unlock = luca_inode_alloc_unlock;

    mutex_init(&luca_block_alloc_mutex);
    luca_fs.block_alloc_lock = luca_block_alloc_lock;
    luca_fs.block_alloc_unlock = luca_block_alloc_unlock;

    mutex_init(&luca_bcache_mutex);
    luca_fs.bcache_lock = luca_bcache_lock;
    luca_fs.bcache_unlock = luca_bcache_unlock;

    //ext4_dmask_set(DEBUG_ALL);

    //
    mp->m_dev = device;
    luca_blockdev.bdif->p_user = device;
    luca_blockdev.part_offset = 0;
    luca_blockdev.part_size = device->size;
    luca_blockdev.bdif->ph_bcnt = luca_blockdev.part_size / luca_blockdev.bdif->ph_bsize;

    error = luca_block_init(&luca_blockdev);
    if (error != EOK) {
        return error;
    }

    printf("进入fsinit\n");
    error = luca_fs_init(&luca_fs, &luca_blockdev, false);
    if (error != EOK) {
        return error;
    }
    printf("进入cacheinit\n");
    error = luca_blockcache_init(&luca_fs, &luca_blockdev, &luca_block_cache);
    if (error != EOK) {
        return error;
    }

    luca_blockdev.fs = &luca_fs;
    mp->m_data = &luca_fs;
    mp->m_root->d_vnode->v_ino = EXT4_INODE_ROOT_INDEX;

    printf("[lucafs] Mounted lucafs on device: [%s] with code:%d\n", dev_name, error);
    return error;
}


static int luca_unmount(struct mount *mp, int flags)
{
    int r = EOK;
    ext4_assert(luca_fs);

	/*Set superblock state*/
	ext4_set16(&luca_fs.sb, state, EXT4_SUPERBLOCK_STATE_VALID_FS);

	if (!luca_fs.read_only)
		r = luca_sb_write(luca_fs.bdev, &luca_fs.sb);

    if (r == EOK) {
        luca_bcache_cleanup(&luca_block_cache);
        luca_bcache_fini_dynamic(&luca_block_cache);
    }

    luca_block_fini(&luca_blockdev);
    r = device_close((struct device*)luca_blockdev.bdif->p_user);
    printf("[lucafs] Unmounted filesystem with: %d!\n", r);

    return r;
}

static int luca_sync(struct mount *mp)
{
    return EIO;
}


static int luca_statfs(struct mount *mp, struct statfs *statp)
{
    luca_fs_t *fs = (luca_fs_t *)mp->m_data;
    statp->f_bsize = ext4_sb_get_block_size(&fs->sb);
    statp->f_blocks = ext4_sb_get_blocks_cnt(&fs->sb);
    statp->f_bfree = ext4_sb_get_free_blocks_cnt(&fs->sb);
    statp->f_bavail = ext4_sb_get_free_blocks_cnt(&fs->sb);

    statp->f_ffree = ext4_get32(&fs->sb, free_inodes_count);
    statp->f_files = ext4_get32(&fs->sb, inodes_count);

    statp->f_namelen = EXT4_DIRECTORY_FILENAME_LEN;
    statp->f_type = LUCA_SUPERBLOCK_MAGIC;

    statp->f_fsid = mp->m_fsid; /*fs识别*/

    return EOK;
}


//内核里面定义过vfsops结构体，用这个来实现对接
extern struct vfsops luca_vfsops;

//加载这个文件系统的时候用真实的函数把空函数覆盖掉
void __attribute__((constructor)) initialize_vfsops()
{
    printf("进入了initialize_vfsops\n");
    luca_vfsops.vfs_mount = luca_mount;
    luca_vfsops.vfs_unmount = luca_unmount;
    luca_vfsops.vfs_sync = luca_sync;
    luca_vfsops.vfs_vget = ((vfsop_vget_t)vfs_nullop);
    luca_vfsops.vfs_statfs = luca_statfs;
    luca_vfsops.vfs_vnops = &luca_vnops;
}