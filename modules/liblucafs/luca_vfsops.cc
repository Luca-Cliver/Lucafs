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

EXT4_BLOCKDEV_STATIC_INSTANCE(luca_blockdev, 512, 0, blockdev_open,
                              blockdev_bread, blockdev_bwrite, blockdev_close, 0, 0);


static luca_fs_t luca_fs;
static luca_bcache_t luca_block_cache;
extern struct vnops luca_vnops;

int luca_blockcache_init(luca_fs_t *fs, luca_blockdev_t *bdev, luca_bcache_t *bcache)
{
    uint32_t bsize = ext4_sb_get_block_size(&fs->sb);
    ext4_block_set_lb_size(bdev, bsize);

    int r = ext4_bcache_init_dynamic(bcache, CONFIG_BLOCK_DEV_CACHE_SIZE, bsize);
    if(r != EOK) {
        return r;
    }
    
    if(bsize != bcache->itemsize)
        return ENOTSUP;

    r = ext4_block_bind_bcache(bdev, bcache);
    if(r != EOK) {
        ext4_bcache_cleanup(bcache);
        ext4_block_fini(bdev);
        ext4_bcache_fini_dynamic(bcache);
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

    printf("进入了luca_mount\n");
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

    error = ext4_block_init(&luca_blockdev);
    if (error != EOK) {
        return error;
    }

    error = ext4_fs_init(&luca_fs, &luca_blockdev, false);
    if (error != EOK) {
        return error;
    }

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
    int r = ext4_fs_fini(&luca_fs);
    if (r == EOK) {
        ext4_bcache_cleanup(&luca_block_cache);
        ext4_bcache_fini_dynamic(&luca_block_cache);
    }

    ext4_block_fini(&luca_blockdev);
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
    statp->f_type = EXT4_SUPERBLOCK_MAGIC;

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