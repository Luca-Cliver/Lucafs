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
#include "lucafs.hh"

//#define CONF_debug_ext 1
#if CONF_debug_ext
#define ext_debug(format,...) kprintf("[ext4] " format, ##__VA_ARGS__)
#else
#define ext_debug(...)
#endif

//Simple RAII struct to automate release of i-node reference
//when it goes out of scope.
struct auto_inode_ref {
    luca_inode_ref_t _ref;
    int _r;

    auto_inode_ref(luca_fs_t *fs, uint32_t inode_no) {
        _r = ext4_fs_get_inode_ref(fs, inode_no, &_ref);
    }
    ~auto_inode_ref() {
        if (_r == EOK) {
            ext4_fs_put_inode_ref(&_ref);
        }
    }
};

//Simple RAII struct to set boundaries around ext4 function calls
//with block cache write back enabled. Effectively, when the instance
//of this struct goes out of scope, the writes are flushed to disk
//and write back disabled.
struct auto_write_back {
    //struct ext4_fs *_fs;
    luca_fs_t *_fs;

    auto_write_back(struct ext4_fs *fs) {
        _fs = fs;
        ext4_block_cache_write_back(_fs->bdev, 1);
    }

    ~auto_write_back() {
        ext4_block_cache_write_back(_fs->bdev, 0);
    }
};

typedef	struct vnode vnode_t;
typedef	struct file file_t;
typedef struct uio uio_t;
typedef	off_t offset_t;
typedef	struct vattr vattr_t;


static int luca_open(struct file *fp)
{
    // vnode_t *vp = fp->f_dentry.get()->d_vnode;
    // if(file_flags(fp) & O_DIRECT)
    // {
    //     return EINVAL;
    // }

    kprintf("[lucafs] luca_open called for inode\n");
    return (EOK);
}


static int luca_close(struct vnode *vp, struct file *fp)
{
    kprintf("[lucafs] luca_close called\n");
    return (EOK);
}

static int luca_internal_read(luca_fs_t *fs, luca_inode_ref_t *ref, uint64_t offset, void *buffer, size_t size, size_t *rcnt)
{
    uint64_t fblock;
    uint64_t block_start = 0;

    uint8_t *u8_buf = (uint8_t *)buffer;
    int r, rr = EOK;

    if(!size)
        return EOK;

    luca_sblock_t *const sb = &fs->sb;

    if(rcnt)
        *rcnt = 0;

    uint64_t fsize = ext4_inode_get_size(sb, ref->inode);
    uint32_t block_size = ext4_sb_get_block_size(sb);

    size = ((uint64_t)size > (fsize-offset)) ? ((size_t)(fsize-offset)) : size;

    uint32_t block_index = (uint32_t)(offset / block_size);   //第一个块的索引
    uint32_t block_final = (uint32_t)((offset + size) / block_size);   //最后一个块的索引
    uint32_t unalg = (offset) % block_size;    //第一个块中开始的位置

    uint32_t block_count = 0;

    /*没对齐的部分*/
    if(unalg)
    {
        /*如果size小于第一个块剩余的部分，直接读取size，否则读出第一个块剩余的部分*/
        size_t len = size > (block_size - unalg) ? (block_size - unalg) : size;

        r = ext4_fs_get_inode_dblk_idx(ref, block_index, &fblock, true);
        if(r != EOK)
            return r;

        /*检查这里是不是没有写入的块*/
        if(fblock != 0)
        {   /*fblock不为零说明是写入的块*/
            uint64_t off = fblock * block_size + unalg;
            /*lwext中提供的和底层交互的接口*/
            r = ext4_block_readbytes(fs->bdev, off, u8_buf, len);
            if(r != EOK)
                return r;
        }
        else
        {   /*fblock为零说明是未写入的块,内容填充为0*/
            memset(u8_buf, 0, len);
        }

        u8_buf += len;
        size -= len;
        offset += len;

        if(rcnt)
            *rcnt += len;

        block_index++;
    }

    block_start = 0;
    while(size >= block_size)
    {/*读中间的完整块*/
        while(block_index < block_final)
        {/*连续的块一起处理一起读*/
            r = ext4_fs_get_inode_dblk_idx(ref, block_index, &fblock, true);

            if(r != EOK)
                return r;

            block_index++;

            if(!block_start)
                block_start = fblock;

            if((block_start + block_count) != fblock)
                break;

            block_count++;
        }
        
        kprintf("[luca_internal_read] block_start:%ld, block_count:%d\n", block_start, block_count);
        r = ext4_blocks_get_direct(fs->bdev, u8_buf, block_start, block_count);

        if(r != EOK)
            return r;

        size -= block_size * block_count;
        u8_buf += block_size * block_count;
        offset += block_size * block_count;

        if(rcnt)
            *rcnt += block_size * block_count;

        block_start = fblock;
        block_count = 1;

    }

    if(size)
    {/*最后一个块剩余的一部分*/
        r = ext4_fs_get_inode_dblk_idx(ref, block_index, &fblock, true);
        if(r != EOK)
            return r;

        uint64_t off = fblock * block_size;
        r = ext4_block_readbytes(fs->bdev, off, u8_buf, size);
        if(r != EOK)
            return r;

        offset += size;

        if(rcnt)
            *rcnt += size;
    }

    return r;

}

static int luca_read(struct vnode *vp, struct file *fp, struct uio *uio, int ioflag)
{
    kprintf("[lucafs] luca_read called\n");

    /*如果是目录返回错误*/
    if (vp->v_type == VDIR)
        return EISDIR;

    /*检查是否为常规文件*/
    if (vp->v_type != VREG)
        return EINVAL;

    /*读取前不能小于第一个字节*/
    if (uio->uio_offset < 0)
        return EINVAL;

    /*需要读取的字节数不能为0*/
    if (uio->uio_resid == 0)
        return 0;

    luca_fs_t *fs = (luca_fs_t *)vp->v_mount->m_data;
    auto_inode_ref inode_ref(fs, vp->v_ino);
    if (inode_ref._r != EOK) {
        return inode_ref._r;
    }

    uint64_t file_size = ext4_inode_get_size(&fs->sb, inode_ref._ref.inode);
    uint64_t read_size = (file_size - uio->uio_offset) > (uint64_t)uio->uio_resid ? (uint64_t)uio->uio_resid : (file_size - uio->uio_offset);
    void *buffer = alloc_contiguous_aligned(read_size, alignof(std::max_align_t));

    size_t read_count = 0;
    int ret = luca_internal_read(fs, &inode_ref._ref, uio->uio_offset, buffer, read_size, &read_count);
    
    if (ret) {
        kprintf("[luca_read] Error reading data\n");
        free(buffer);
        return ret;
    }

    ret = uiomove(buffer, read_count, uio);
    free_contiguous_aligned(buffer);

    return ret;
}

static int luca_internal_write(luca_fs_t *fs, luca_inode_ref_t *ref, uint64_t offset, void *buffer, size_t size, size_t *wcnt)
{
    kprintf("[luca_internal_write] offset:%ld, size:%ld\n", offset, size);
    
    uint64_t fblock;
    uint64_t block_start = 0;

    uint8_t *u8_buf = (uint8_t *)buffer;
    int r, rr = EOK;

    if(!size)
        return EOK;

    luca_sblock_t *const sb = &fs->sb;

    if(wcnt)
        *wcnt = 0;

    uint64_t fsize = ext4_inode_get_size(sb, ref->inode);
    uint32_t block_size = ext4_sb_get_block_size(sb);

    uint32_t block_index = (uint32_t)(offset / block_size);   //第一个块的索引
    uint32_t block_final = (uint32_t)((offset + size) / block_size);   //最后一个块的索引
    uint32_t file_blocks = 0;   //文件中的块数
    if(fsize % block_size)
        file_blocks = (uint32_t)(fsize / block_size) + 1;
    else
        file_blocks = (uint32_t)(fsize / block_size);

    uint32_t unalg = (offset) % block_size;    //第一个块中开始的位置

    uint32_t block_count = 0;

    if(unalg)
    {/*没有对齐的块肯定不是空缺的块*/
        size_t len = size > (block_size - unalg) ? (block_size - unalg) : size;
        uint64_t off;

        if(block_index <  file_blocks)
        {
            r = ext4_fs_init_inode_dblk_idx(ref, block_index, &fblock);
        }
        else
        {
            r = ext4_fs_append_inode_dblk(ref, &fblock, &block_index);
            kprintf("[luca_internal_write] Appended block=%d, phys:%ld\n", block_index, fblock);
            file_blocks++;
        }
        if(r != EOK)
            goto Finish;

        off = fblock * block_size + unalg;
        r = ext4_block_writebytes(fs->bdev, off, u8_buf, len);
        if(r != EOK)
            goto Finish;

        u8_buf += len;
        size -= len;
        offset += len;

        if(wcnt)
            *wcnt += len;

        block_index++;
    }

    /*开启写回cache*/
    r = ext4_block_cache_write_back(fs->bdev, 1);
    if(r != EOK)
        goto Finish;

    /*本文件系统并不支持稀疏文件，因此需要填补间隙*/
    while(file_blocks < block_index)
    {
        uint32_t block_index_;
        r = ext4_fs_append_inode_dblk(ref, nullptr, &block_index_);
        if(r != EOK)
        {
            offset = file_blocks * block_size;
            goto overflow;
        }
        kprintf("[luca_internal_write] Appended block=%d\n", block_index_);
        file_blocks++;
    }

    while(size >= block_size)
    {/*中间的完整块*/
        while(block_index < block_final)
        {  /*连续的快一起写*/
            if(block_index < block_final)
            {
                r = ext4_fs_init_inode_dblk_idx(ref, block_index, &fblock);
                if(r != EOK)
                    goto Finish;
            }
            else
            {
                rr = ext4_fs_append_inode_dblk(ref, &fblock, &block_index);
                kprintf("[luca_internal_write] Appended block=%d, phys:%ld\n", block_index, fblock);
                if(rr != EOK)
                    break;
            }

            block_index++;
            if(!block_start)
                block_start = fblock;

            /*不连续了就跳出*/
            if((block_start + block_count) != fblock)
                break;

            block_count++;
        }

        r = ext4_blocks_set_direct(fs->bdev, u8_buf, block_start, block_count);
        kprintf("[luca_internal_write] Wrote direct %d blocks at block %ld\n", block_count, block_start);
        if(r != EOK)
            break;

        size -= block_size * block_count;
        u8_buf += block_size * block_count;
        offset += block_size * block_count;

        if(wcnt)
            *wcnt += block_size * block_count;

        block_start = fblock;
        block_count = 1;

        if(rr != EOK)
        {
            r = rr;
            goto overflow;
        }
    }

    /*关闭写回cache*/
    ext4_block_cache_write_back(fs->bdev, 0);

    if(r != EOK)
        goto Finish;

    if(size)
    {/*剩余部分*/
        uint64_t off;
        if(block_index < block_final)
        {
            r = ext4_fs_init_inode_dblk_idx(ref, block_index, &fblock);
            if(r != EOK)
                goto Finish;
        }
        else
        {
            r = ext4_fs_append_inode_dblk(ref, &fblock, &block_index);
            kprintf("[luca_internal_write] Appended (4) block=%d, phys:%ld\n", block_index, fblock);
            if(r != EOK)
                goto overflow;
        }

        off = fblock * block_size;
        r = ext4_block_writebytes(fs->bdev, off, u8_buf, size);
        if(r != EOK)
            goto Finish;

        offset += size;

        if(wcnt)
            *wcnt += size;
    }


overflow:
    if(offset > fsize)
    {
        ext4_inode_set_size(ref->inode, offset);
        ref->dirty = true;
    }


Finish:
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ext4_inode_set_change_inode_time(ref->inode, ts.tv_sec);
    ext4_inode_set_modif_time(ref->inode, ts.tv_sec);
    ref->dirty = true;

    return r;


}

static int luca_wirte(vnode_t *vp, uio_t *uio, int ioflag)
{
    kprintf("Writing %ld bytes at offset:%ld to file i-node:%ld\n", uio->uio_resid, uio->uio_offset, vp->v_ino);

    /*目录不能写*/
    if(vp->v_type == VDIR)
        return EISDIR;

    /*只能写入常规文件*/
    if(vp->v_type != VREG)
        return EINVAL;

    /*不能在第一个字节之前开始写*/
    if(uio->uio_offset < 0)
        return EINVAL;

    /*需要写入的字节数不能为0*/
    if(uio->uio_resid == 0)
        return 0;

    luca_fs_t *fs = (luca_fs_t *)vp->v_mount->m_data;
    auto_inode_ref inode_ref(fs, vp->v_ino);
    if (inode_ref._r != EOK) {
        return inode_ref._r;
    }

    uio_t uio__ = *uio;
    if (ioflag & IO_APPEND) {
        uio__.uio_offset = ext4_inode_get_size(&fs->sb, inode_ref._ref.inode);
    }

    void *buffer = alloc_contiguous_aligned(uio->uio_resid, alignof(std::max_align_t));
    int ret = uiomove(buffer, uio->uio_resid, &uio__);

    if (ret) {
        kprintf("[luca_write] Error copying data\n");
        free(buffer);
        return ret;
    }

    size_t write_count = 0;
    ret = luca_internal_write(fs, &inode_ref._ref, uio->uio_offset, buffer, uio->uio_resid, &write_count);

    uio->uio_resid -= write_count;
    free_contiguous_aligned(buffer);

    return ret;


}

static int luca_ioctl(vnode_t *vp, file_t *fp, u_long com, void *data)
{
    kprintf("[lucafs] ioctl\n");
    return (EINVAL);
}

static int luca_fsync(vnode_t *vp, file_t *fp)
{
    kprintf("[lucafs] fsync\n");
    return (EOK);
}

static int luca_readdir(struct vnode *dvp, struct file *fp, struct dirent *dir)
{
    kprintf("[lucafs] readdir\n");
    luca_fs_t *fs = (luca_fs_t *)dvp->v_mount->m_data;
    luca_inode_ref_t inode_ref;

    if(file_offset(fp) == 1)
    {
        return ENOENT;
    }

    int r = ext4_fs_get_inode_ref(fs, dvp->v_ino, &inode_ref);
    if(r != EOK)
    {
        return r;
    }

    /*检查是否是目录*/
    if(ext4_inode_is_type(&fs->sb, inode_ref.inode, EXT4_INODE_MODE_DIRECTORY) == 0)
    {
        ext4_fs_put_inode_ref(&inode_ref);
        return ENOTDIR;
    }

    kprintf("[lucafs] readdir called for inode %ld\n", dvp->v_ino);
    /*目录迭代器*/
    struct ext4_dir_iter it;
    int rc = ext4_dir_iterator_init(&it, &inode_ref, file_offset(fp));
    if(rc != EOK)
    {
        kprintf("[lucafs] Reading directory with i-node:%ld at offset:%ld -> FAILED to init iterator\n", dvp->v_ino, file_offset(fp));
        ext4_fs_put_inode_ref(&inode_ref);
        return rc;
    }

    /*处理非空目录项*/
    if(it.curr != NULL)
    {
        if(ext4_dir_en_get_inode(it.curr) != 0)
        {
            memset(dir->d_name, 0, sizeof(dir->d_name));
            uint16_t name_length = ext4_dir_en_get_name_len(&fs->sb, it.curr);
            memcpy(dir->d_name, it.curr->name, name_length);
            kprintf("[lucafs] Reading directory with i-node:%ld at offset:%ld => entry name:%s\n", dvp->v_ino, file_offset(fp), dir->d_name);

            dir->d_ino = ext4_dir_en_get_inode(it.curr);

            uint8_t i_type = ext4_dir_en_get_inode_type(&fs->sb, it.curr);

            if(i_type == LUCA_DE_DIR)
                dir->d_type = DT_DIR;
            else if(i_type == LUCA_DE_REG_FILE)
                dir->d_type = DT_REG;
            else if(i_type == LUCA_DE_SYMLINK)
                dir->d_type = DT_LNK;

            ext4_dir_iterator_next(&it);

            off_t off = file_offset(fp);
            dir->d_fileno = off;
            dir->d_off = off + 1;
            file_setoffset(fp, it.curr ? it.curr_off : (uint64_t)-1);
        }
        else
        {
            kprintf("[lucafs] Reading directory with i-node:%ld at offset:%ld -> cos ni tak\n", dvp->v_ino, file_offset(fp));
        }
    }
    else
    {
        ext4_dir_iterator_fini(&it);
        ext4_fs_put_inode_ref(&inode_ref);
        kprintf("[lucafs] Reading directory with i-node:%ld at offset:%ld -> ENOENT\n", dvp->v_ino, file_offset(fp));
        return ENOENT;
    }

    rc = ext4_dir_iterator_fini(&it);
    ext4_fs_put_inode_ref(&inode_ref);
    if(rc != EOK)
        return rc;

    return (EOK);
}

static int luca_lookup(struct vnode *dvp, char *name, struct vnode **vpp)
{
    kprintf("[lucafs] lookup\n");

    luca_fs_t *fs = (luca_fs_t *)dvp->v_mount->m_data;

    auto_inode_ref inode_ref(fs, dvp->v_ino);
    if (inode_ref._r != EOK) {
        return inode_ref._r;
    }

    /*检查是不是目录*/
    if(ext4_inode_is_type(&fs->sb, inode_ref._ref.inode, EXT4_INODE_MODE_DIRECTORY) == 0)
    {
        return ENOTDIR;
    }

    struct ext4_dir_search_result result;
    int r = ext4_dir_find_entry(&result, &inode_ref._ref, name, strlen(name));
    if(r == EOK)
    {
        uint32_t inode_num = ext4_dir_en_get_inode(result.dentry);
        vget(dvp->v_mount, inode_num, vpp);

        auto_inode_ref inode_ref_(fs, inode_num);
        if (inode_ref_._r != EOK) {
            return inode_ref_._r;
        }

        uint32_t inode_type = ext4_inode_type(&fs->sb, inode_ref_._ref.inode);
        if (inode_type == LUCA_INODE_MODE_DIRECTORY) {
            (*vpp)->v_type = VDIR;
        } else if (inode_type == LUCA_INODE_MODE_FILE) {
            (*vpp)->v_type = VREG;
        } else if (inode_type == LUCA_INODE_MODE_SOFTLINK) {
            (*vpp)->v_type = VLNK;
        }

        (*vpp)->v_mode = ext4_inode_get_mode(&fs->sb, inode_ref_._ref.inode);
    }
    else
    {
        r = ENOENT;
    }

    ext4_dir_destroy_result(&inode_ref._ref, &result);

    return r;
}

static int luca_dir_initialize(luca_inode_ref_t *parent, luca_inode_ref_t *child, bool dir_index_on)
{
    kprintf("[lucafs] dir_initialize\n");
    int r;
#if CONFIG_DIR_INDEX_ENABLE
    if(dir_index_on)
    {
        r =ext4_dir_dx_init(parent, child);
        if(r != EOK)
            return r;

        ext4_inode_set_flag(child->inode, 0x00001000);
    }
    else
#endif
    {
        r = ext4_dir_add_entry(child, ".", 1, child);
        if(r != EOK)
            return r;

        r = ext4_dir_add_entry(child, "..", 2, parent);
        if(r != EOK)
        {
            ext4_dir_remove_entry(child, ".", 1);
            return r;
        }
    }

    /*新目录有两个链接：.和..*/
    ext4_inode_set_links_cnt(child->inode, 2);
    ext4_fs_inode_links_count_inc(parent);
    parent->dirty = true;
    child->dirty = true;

    return r;
}

static int luca_dir_link(struct vnode *dvp, char *name, int type, uint32_t *link_no, uint32_t *inode_no_created)
{
    kprintf("[lucafs] dir_link\n");
    luca_fs_t *fs = (luca_fs_t *)dvp->v_mount->m_data;
    auto_write_back write_back(fs);
    auto_inode_ref inode_ref(fs, dvp->v_ino);
    if (inode_ref._r != EOK) {
        return inode_ref._r;
    }

    /*检查是否是目录*/
    if(ext4_inode_is_type(&fs->sb, inode_ref._ref.inode, LUCA_INODE_MODE_DIRECTORY) == 0)
    {
        return ENOTDIR;
    }

    struct ext4_dir_search_result result;
    int r = ext4_dir_find_entry(&result, &inode_ref._ref, name, strlen(name));
    ext4_dir_destroy_result(&inode_ref._ref, &result);

    if(r == EOK)
    {
        return EEXIST;
    }

    luca_inode_ref_t child;
    if(link_no)
        r = ext4_fs_get_inode_ref(fs, *link_no, &child);
    else
        r = ext4_fs_alloc_inode(fs, &child, type);

    if(r != EOK)
        return r;

    if(!link_no)
        ext4_fs_inode_blocks_init(fs, &child);

    r = ext4_dir_add_entry(&inode_ref._ref, name, strlen(name), &child);
    if(r == EOK)
    {
        bool is_dir = ext4_inode_is_type(&fs->sb, child.inode, LUCA_INODE_MODE_DIRECTORY);

        if(is_dir && link_no)
        {
            r = EPERM;
        }
        else if(is_dir)
        {
#if CONFIG_DIR_INDEX_ENABLE
            bool dir_index_on = ext4_sb_feature_com(&fs->sb, EXT4_FCOM_DIR_INDEX);
#else
            bool dir_index_on = false;
#endif
            r = luca_dir_initialize(&inode_ref._ref, &child, dir_index_on);
            if(r != EOK)
            {
                ext4_dir_remove_entry(&inode_ref._ref, name, strlen(name));
            }
        }
        else
        {
            ext4_fs_inode_links_count_inc(&child);
        }
    }

    if(r == EOK)
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ext4_inode_set_change_inode_time(child.inode, ts.tv_sec);
        if(!link_no)
        {
            ext4_inode_set_access_time(child.inode, ts.tv_sec);
            ext4_inode_set_modif_time(child.inode, ts.tv_sec);
        }

        ext4_inode_set_change_inode_time(inode_ref._ref.inode, ts.tv_sec);
        ext4_inode_set_modif_time(inode_ref._ref.inode, ts.tv_sec);

        inode_ref._ref.dirty = true;
        child.dirty = true;

        if(inode_no_created)
            *inode_no_created = child.index;
        kprintf("[lucafs] created %s under i-node %li\n", name, dvp->v_ino);
    }
    else
    {
        if(!link_no)
            ext4_fs_free_inode(&child);
        
        child.dirty = false;
    }

    ext4_fs_put_inode_ref(&child);

    return r;

}

static int luca_create(struct vnode *dvp, char *name, mode_t mode)
{
    kprintf("[lucafs] create\n");

    if(strlen(name) > 255)
        return ENAMETOOLONG;

    if(!S_ISREG(mode))
        return EINVAL;

    return luca_dir_link(dvp, name, LUCA_DE_REG_FILE, nullptr, nullptr);
}


static int luca_trunc_inode(luca_fs_t *fs, uint32_t index, uint64_t new_size)
{
    kprintf("[lucafs] trunc_inode\n");
    luca_inode_ref_t inode_ref;
    int r = ext4_fs_get_inode_ref(fs, index, &inode_ref);
    if(r != EOK)
        return r;

    uint64_t inode_size = ext4_inode_get_size(&fs->sb, inode_ref.inode);
    ext4_fs_put_inode_ref(&inode_ref);

    if(inode_size > new_size)
    {
        while(inode_size > new_size + CONFIG_MAX_TRUNCATE_SIZE)
        {/*每次截断最大能截断的长度*/
            inode_size = inode_size - CONFIG_MAX_TRUNCATE_SIZE;

            r = ext4_fs_get_inode_ref(fs, index, &inode_ref);
            if(r != EOK)
                break;

            r = ext4_fs_truncate_inode(&inode_ref, inode_size);
            if(r != EOK)
            {
                ext4_fs_put_inode_ref(&inode_ref);
                goto Finish;
            }
            
            r = ext4_fs_put_inode_ref(&inode_ref);
            if(r != EOK)
                goto Finish; 
        }
        if(inode_size > new_size)
        {/*处理剩余的部分*/
            inode_size = new_size;

            r = ext4_fs_get_inode_ref(fs, index, &inode_ref);
            if(r != EOK)
                goto Finish;

            r = ext4_fs_truncate_inode(&inode_ref, inode_size);
            if(r != EOK)
                ext4_fs_put_inode_ref(&inode_ref);
            else
                r = ext4_fs_put_inode_ref(&inode_ref);
        }
    }

Finish:
    return r;
}


static int luca_dir_trunc(luca_fs_t *fs, luca_inode_ref_t *parent, luca_inode_ref_t *dir)
{
    kprintf("[lucafs] dir_trunc\n");
    int r = EOK;
    uint32_t block_size = ext4_sb_get_block_size(&fs->sb);

#if CONFIG_DIR_INDEX_ENABLE
    /*初始化目录索引*/
    if(ext4_sb_feature_com(&fs->sb, EXT4_FCOM_DIR_INDEX))
    {
        r = ext4_dir_dx_init(dir, parent);
        if(r != EOK)
            return r;

        r = luca_trunc_inode(fs, dir->index, EXT4_DIR_DX_INIT_BCNT*block_size);
        if(r != EOK)
            return r;
    }
    else
#endif
    {
        r = luca_trunc_inode(fs, dir->index, block_size);
        if(r != EOK)
            return r;
    }

    return ext4_fs_truncate_inode(dir, 0);


    return (EOK);
}


static int luca_dir_remove_entry(struct vnode *dvp, struct vnode *vp, char *name)
{
    kprintf("[lucafs] dir_remove_entry\n");
    return (EOK);
}


static int luca_remove(struct vnode *dvp, struct vnode *vp, char *name)
{
    kprintf("[lucafs] remove\n");
    luca_fs_t *fs = (luca_fs_t *)dvp->v_mount->m_data;
    auto_write_back write_back(fs);
    auto_inode_ref parent_ref(fs, dvp->v_ino);
    if (parent_ref._r != EOK) 
        return parent_ref._r;
    

    auto_inode_ref child_ref(fs, vp->v_ino);
    if (child_ref._r != EOK) 
        return child_ref._r;

    int r = EOK;
    uint32_t type = ext4_inode_type(&fs->sb, child_ref._ref.inode);
    if(type == LUCA_INODE_MODE_DIRECTORY)
    {
        r = luca_dir_trunc(fs, &parent_ref._ref, &child_ref._ref);
        if(r != EOK)
            return r;
    }
    else
    {
        if(ext4_inode_get_links_cnt(child_ref._ref.inode) == 1)
        {
            r = luca_trunc_inode(fs, child_ref._ref.index, 0);
            if(r != EOK)
                return r;
        }
        
    }

    /*在父目录中删除这个节点*/
    r = ext4_dir_remove_entry(&parent_ref._ref, name, strlen(name));
    if(r != EOK)
        return r;

    if(type == LUCA_INODE_MODE_DIRECTORY)
        ext4_fs_free_inode(&child_ref._ref);
    else
    {
        int links_count = ext4_inode_get_links_cnt(child_ref._ref.inode);
        if(links_count)
        {
            ext4_fs_inode_links_count_dec(&child_ref._ref);
            child_ref._ref.dirty = true;

            if(links_count == 1)
            {/*原本是1，现在就是0*/
                ext4_fs_free_inode(&child_ref._ref);
            }
        }
    }

    if(r == EOK)
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ext4_inode_set_change_inode_time(parent_ref._ref.inode, ts.tv_sec);
        ext4_inode_set_modif_time(parent_ref._ref.inode, ts.tv_sec);
        parent_ref._ref.dirty = true;
    }
    return r;
}

static int luca_rename(struct vnode *oldplace_vp, struct vnode *old_vp, char *old_name,
           struct vnode *newplace_vp, struct vnode *new_vp, char *new_name)
{
    kprintf("[lucafs] rename\n");
    luca_fs_t *fs = (luca_fs_t *)oldplace_vp->v_mount->m_data;
    auto_write_back write_back(fs);

    int r = EOK;

    if(new_vp)
    {/*新文件已经存在了，先删除这个文件*/
        auto_inode_ref target_dir(fs, oldplace_vp->v_ino);
        if(target_dir._r != EOK)
            return target_dir._r;

        //从目标目录中移除
        r = ext4_dir_remove_entry(&target_dir._ref, new_name, strlen(new_name));
        if(r != EOK)
            return r;
    }

    auto_inode_ref old_dir(fs, oldplace_vp->v_ino);
    if(old_dir._r != EOK)
        return old_dir._r;

    auto_inode_ref old_file(fs, old_vp->v_ino);
    if(old_file._r != EOK)
        return old_file._r;

    if(oldplace_vp == newplace_vp)
    {/*新旧位置是同一个*/
        //直接把在同样的目录下添加一个新的名字
        r = ext4_dir_add_entry(&old_dir._ref, new_name, strlen(new_name), &old_file._ref);
        if(r != EOK)
            return r;

    }    
    else
    {/*创建一个目标目录，在这里面添加*/
        auto_inode_ref new_dir(fs, newplace_vp->v_ino);
        if(new_dir._r != EOK)
            return new_dir._r;

        r = ext4_dir_add_entry(&new_dir._ref, new_name, strlen(new_name), &old_file._ref);
        if(r != EOK)
            return r;
    
    }

    /*改名的是目录，那也需要把父目录“..”重定位一下*/
    if(ext4_inode_is_type(&fs->sb, old_file._ref.inode, LUCA_INODE_MODE_DIRECTORY))
    {
        auto_inode_ref new_dir(fs, newplace_vp->v_ino);
        if(new_dir._r != EOK)
            return new_dir._r;

        struct ext4_dir_search_result result;
        if(ext4_inode_has_flag(old_file._ref.inode, 0x00001000))
        {
#if CONFIG_DIR_INDEX_ENABLE
        r = ext4_dir_dx_reset_parent_inode(&old_file._ref, new_dir._ref.index);
        if(r != EOK)
            return r;      
#endif
        }
        else
        {
            r = ext4_dir_find_entry(&result, &old_file._ref, "..", 2);
            if(r != EOK)
                return EIO;

            ext4_dir_en_set_inode(result.dentry, new_dir._ref.index);
            ext4_trans_set_block_dirty(result.block.buf);
            r = ext4_dir_destroy_result(&old_file._ref, &result);
            if(r != EOK)
                return r;
        }

        ext4_fs_inode_links_count_inc(&new_dir._ref);
    }

    /*从旧目录中移除源文件*/
    r = ext4_dir_remove_entry(&old_dir._ref, old_name, strlen(old_name));
    if(r != EOK)
        return r;

    
    return r;
}


static int luca_mkdir(struct vnode *dvp, char *dirname, mode_t mode)
{
    kprintf("[lucafs] mkdir\n");
    uint32_t length = strlen(dirname);
    if(length > 255)
        return ENAMETOOLONG;

    if(!S_ISDIR(mode))
        return EINVAL;

    return luca_dir_link(dvp, dirname, LUCA_DE_DIR, nullptr, nullptr);
}


static int luca_rmdir(vnode_t *dvp, vnode_t *vp, char *name)
{
    kprintf("[lucafs] rmdir\n");
    return luca_remove(dvp, vp, name);
}


static int luca_getattr(vnode_t *vp, vattr_t *vap)
{
    kprintf("[lucafs] getattr\n");
    luca_fs_t *fs = (luca_fs_t *)vp->v_mount->m_data;

    auto_inode_ref inode_ref(fs, vp->v_ino);
    if (inode_ref._r != EOK) {
        return inode_ref._r;
    }

    vap->va_mode = ext4_inode_get_mode(&fs->sb, inode_ref._ref.inode);
    uint32_t type = ext4_inode_type(&fs->sb, inode_ref._ref.inode);
    if (type == LUCA_INODE_MODE_DIRECTORY) {
        vap->va_type = VDIR;
    } else if (type == LUCA_INODE_MODE_FILE) {
        vap->va_type = VREG;
    } else if (type == LUCA_INODE_MODE_SOFTLINK) {
        vap->va_type = VLNK;
    }

    vap->va_nodeid = vp->v_ino;
    vap->va_size = ext4_inode_get_size(&fs->sb, inode_ref._ref.inode);

    vap->va_atime.tv_sec = ext4_inode_get_access_time(inode_ref._ref.inode);
    vap->va_mtime.tv_sec = ext4_inode_get_modif_time(inode_ref._ref.inode);
    vap->va_ctime.tv_sec = ext4_inode_get_change_inode_time(inode_ref._ref.inode);

    return (EOK);
}


static int luca_setattr(vnode_t *vp, vattr_t *vap)
{
    kprintf("[lucafs] setattr\n");
    luca_fs_t *fs = (luca_fs_t *)vp->v_mount->m_data;

    auto_write_back wb(fs);
    auto_inode_ref inode_ref(fs, vp->v_ino);
    if (inode_ref._r != EOK) {
        return inode_ref._r;
    }

    if(vap->va_mask & AT_ATIME)
    {
        ext4_inode_set_access_time(inode_ref._ref.inode, vap->va_atime.tv_sec);
        inode_ref._ref.dirty = true;
    }

    if(vap->va_mask & AT_CTIME)
    {
        ext4_inode_set_change_inode_time(inode_ref._ref.inode, vap->va_ctime.tv_sec);
        inode_ref._ref.dirty = true;
    }

    if(vap->va_mask & AT_MTIME)
    {
        ext4_inode_set_modif_time(inode_ref._ref.inode, vap->va_mtime.tv_sec);
        inode_ref._ref.dirty = true;
    }

    if(vap->va_mask & AT_MODE)
    {
        ext4_inode_set_mode(&fs->sb, inode_ref._ref.inode, vap->va_mode);
        inode_ref._ref.dirty = true;
    }
    return (EOK);
}


static int luca_truncate(struct vnode *vp, off_t new_size)
{
    kprintf("[lucafs] truncate\n");
    luca_fs_t *fs = (luca_fs_t *)vp->v_mount->m_data;
    auto_write_back wb(fs);
    return luca_trunc_inode(fs, vp->v_ino, new_size);
    return (EOK);
}


static int luca_link(vnode_t *tdvp, vnode_t *svp, char *name)
{
    kprintf("[lucafs] link\n");
    uint32_t len = strlen(name);
    if(len > 255)
        return ENAMETOOLONG;

    uint32_t link_no = svp->v_ino;
    return luca_dir_link(tdvp, name, LUCA_DE_REG_FILE, &link_no, nullptr);
}


static int luca_arc(vnode_t *vp, struct file* fp, uio_t *uio)
{
    kprintf("[lucafs] arc\n");
    return (EOK);
}


static int luca_fallocate(vnode_t *vp, int mode, off_t offset, off_t len)
{
    kprintf("[lucafs] fallocate\n");
    return (EOK);
}


static int luca_readlink(vnode_t *vp, uio_t *uio)
{
    kprintf("[lucafs] readlink\n");
    if(vp->v_type != VLNK)
        return EINVAL;

    if(uio->uio_offset < 0)
        return EINVAL;

    if(uio->uio_resid == 0)
        return 0;

    luca_fs_t *fs = (luca_fs_t *)vp->v_mount->m_data;
    auto_inode_ref inode_ref(fs, vp->v_ino);
    if (inode_ref._r != EOK) {
        return inode_ref._r;
    }

    uint64_t size = ext4_inode_get_size(&fs->sb, inode_ref._ref.inode);
    if(size < (uint64_t)inode_ref._ref.inode->blocks && 
       !ext4_inode_get_blocks_count(&fs->sb, inode_ref._ref.inode))
    {
        char *content = (char *)inode_ref._ref.inode->blocks;
        return uiomove(content, size, uio);
    }    
    else
    {
        uint32_t block_size = ext4_sb_get_block_size(&fs->sb);
        void *buffer = malloc(block_size);
        size_t read_count = 0;
        int ret = luca_internal_read(fs, &inode_ref._ref, uio->uio_offset, buffer, size, &read_count);
        if(ret)
        {
            kprintf("[luca_readlink] Error reading data\n");
            free(buffer);
            return ret;
        }
        ret = uiomove(buffer, read_count, uio);
        free(buffer);
        return ret;
    }
    return (EOK);
}


static int luca_symlink(vnode_t *dvp, char *name, char *link)
{
    kprintf("[lucafs] symlink\n");
    luca_fs_t *fs = (luca_fs_t *)dvp->v_mount->m_data;
    auto_write_back write_back(fs);
    uint32_t inode_no;
    int r = luca_dir_link(dvp, name, LUCA_DE_SYMLINK, nullptr, &inode_no);
    if(r == EOK)
    {
        void *buffer = link;
        uint32_t size = strlen(link);
        uint32_t block_size = ext4_sb_get_block_size(&fs->sb);

        if(size > block_size)
            return EINVAL;
        
        auto_inode_ref inode_ref(fs, inode_no);
        if(inode_ref._r != EOK)
            return inode_ref._r;

        //如果size小于60字节
        if(size < sizeof(inode_ref._ref.inode->blocks))
        {/*内容比较少，就不再单独分配block了，直接存在inode的数组里面*/
            memset(inode_ref._ref.inode->blocks, 0, sizeof(inode_ref._ref.inode->blocks));
            memcpy(inode_ref._ref.inode->blocks, buffer, size);
            ext4_inode_clear_flag(inode_ref._ref.inode, 0x00080000);
        }
        else
        {/*内容比较多就再分一个块出来*/
        ext4_fs_inode_blocks_init(fs, &inode_ref._ref);

        uint32_t block_no;
        ext4_fsblk_t fblock;
        int r = ext4_fs_append_inode_dblk(&inode_ref._ref, &fblock, &block_no);
        if(r != EOK)
            return r;

        uint64_t offset = fblock * block_size;

        r = ext4_block_writebytes(fs->bdev, offset, buffer, size);
        if(r != EOK)
            return r;

        }
        ext4_inode_set_size(inode_ref._ref.inode, size);
        inode_ref._ref.dirty = true;
        return EOK;

    }
    return r;
}


static int
ext_getattr(vnode_t *vp, vattr_t *vap)
{
    kprintf("Getting attributes at i-node:%ld\n", vp->v_ino);
    struct ext4_fs *fs = (struct ext4_fs *)vp->v_mount->m_data;

    auto_inode_ref inode_ref(fs, vp->v_ino);
    if (inode_ref._r != EOK) {
        return inode_ref._r;
    }

    vap->va_mode = ext4_inode_get_mode(&fs->sb, inode_ref._ref.inode);

    uint32_t i_type = ext4_inode_type(&fs->sb, inode_ref._ref.inode);
    if (i_type == EXT4_INODE_MODE_DIRECTORY) {
       vap->va_type = VDIR;
    } else if (i_type == EXT4_INODE_MODE_FILE) {
        vap->va_type = VREG;
    } else if (i_type == EXT4_INODE_MODE_SOFTLINK) {
        vap->va_type = VLNK;
    }

    vap->va_nodeid = vp->v_ino;
    vap->va_size = ext4_inode_get_size(&fs->sb, inode_ref._ref.inode);
    ext_debug("getattr: va_size:%ld\n", vap->va_size);

    vap->va_atime.tv_sec = ext4_inode_get_access_time(inode_ref._ref.inode);
    vap->va_mtime.tv_sec = ext4_inode_get_modif_time(inode_ref._ref.inode);
    vap->va_ctime.tv_sec = ext4_inode_get_change_inode_time(inode_ref._ref.inode);

    //auto *fsid = &vnode->v_mount->m_fsid; //TODO
    //attr->va_fsid = ((uint32_t)fsid->__val[0]) | ((dev_t) ((uint32_t)fsid->__val[1]) << 32);

    return (EOK);
}

static int
ext_setattr(vnode_t *vp, vattr_t *vap)
{
    ext_debug("setattr\n");
    struct ext4_fs *fs = (struct ext4_fs *)vp->v_mount->m_data;

    auto_write_back wb(fs);
    auto_inode_ref inode_ref(fs, vp->v_ino);
    if (inode_ref._r != EOK) {
        return inode_ref._r;
    }

    if (vap->va_mask & AT_ATIME) {
        ext4_inode_set_access_time(inode_ref._ref.inode, vap->va_atime.tv_sec);
        inode_ref._ref.dirty = true;
    }

    if (vap->va_mask & AT_CTIME) {
        ext4_inode_set_change_inode_time(inode_ref._ref.inode, vap->va_ctime.tv_sec);
        inode_ref._ref.dirty = true;
    }

    if (vap->va_mask & AT_MTIME) {
        ext4_inode_set_modif_time(inode_ref._ref.inode, vap->va_mtime.tv_sec);
        inode_ref._ref.dirty = true;
    }

    if (vap->va_mask & AT_MODE) {
        ext4_inode_set_mode(&fs->sb, inode_ref._ref.inode, vap->va_mode);
        inode_ref._ref.dirty = true;
    }

    return (EOK);
}

static int
ext_truncate(struct vnode *vp, off_t new_size)
{
    ext_debug("truncate\n");
    struct ext4_fs *fs = (struct ext4_fs *)vp->v_mount->m_data;
    auto_write_back wb(fs);
    return luca_trunc_inode(fs, vp->v_ino, new_size);
}

static int
ext_link(vnode_t *tdvp, vnode_t *svp, char *name)
{
    ext_debug("link\n");
    uint32_t len = strlen(name);
    if (len > NAME_MAX || len > EXT4_DIRECTORY_FILENAME_LEN) {
        return ENAMETOOLONG;
    }

    uint32_t source_link_no = svp->v_ino;
    return luca_dir_link(tdvp, name, EXT4_DE_REG_FILE, &source_link_no, nullptr);
}

static int
ext_arc(vnode_t *vp, struct file* fp, uio_t *uio)
{
    kprintf("[ext4] arc\n");
    return (EINVAL);
}

static int
ext_fallocate(vnode_t *vp, int mode, loff_t offset, loff_t len)
{
    kprintf("[ext4] fallocate\n");
    return (EINVAL);
}

static int
ext_readlink(vnode_t *vp, uio_t *uio)
{
    ext_debug("readlink\n");
    if (vp->v_type != VLNK) {
        return EINVAL;
    }
    if (uio->uio_offset < 0) {
        return EINVAL;
    }
    if (uio->uio_resid == 0) {
        return 0;
    }

    struct ext4_fs *fs = (struct ext4_fs *)vp->v_mount->m_data;

    auto_inode_ref inode_ref(fs, vp->v_ino);
    if (inode_ref._r != EOK) {
        return inode_ref._r;
    }

    uint64_t fsize = ext4_inode_get_size(&fs->sb, inode_ref._ref.inode);
    if (fsize < sizeof(inode_ref._ref.inode->blocks)
             && !ext4_inode_get_blocks_count(&fs->sb, inode_ref._ref.inode)) {

        char *content = (char *)inode_ref._ref.inode->blocks;
        return uiomove(content, fsize, uio);
    } else {
        uint32_t block_size = ext4_sb_get_block_size(&fs->sb);
        void *buf = malloc(block_size);
        size_t read_count = 0;
        int ret = luca_internal_read(fs, &inode_ref._ref, uio->uio_offset, buf, fsize, &read_count);
        if (ret) {
            kprintf("[ext_readlink] Error reading data\n");
            free(buf);
            return ret;
        }

        ret = uiomove(buf, read_count, uio);
        free(buf);
        return ret;
    }
}

static int
ext_fsymlink_set(struct ext4_fs *fs, uint32_t inode_no, const void *buf, uint32_t size)
{
    uint32_t block_size = ext4_sb_get_block_size(&fs->sb);
    if (size > block_size) {
        return EINVAL;
    }

    auto_inode_ref inode_ref(fs, inode_no);
    if (inode_ref._r != EOK) {
        return inode_ref._r;
    }

    /*If the size of symlink is smaller than 60 bytes*/
    if (size < sizeof(inode_ref._ref.inode->blocks)) {
        memset(inode_ref._ref.inode->blocks, 0, sizeof(inode_ref._ref.inode->blocks));
        memcpy(inode_ref._ref.inode->blocks, buf, size);
        ext4_inode_clear_flag(inode_ref._ref.inode, EXT4_INODE_FLAG_EXTENTS);
    } else {
        ext4_fs_inode_blocks_init(fs, &inode_ref._ref);

        uint32_t sblock;
        ext4_fsblk_t fblock;
        int r = ext4_fs_append_inode_dblk(&inode_ref._ref, &fblock, &sblock);
        if (r != EOK)
            return r;

        uint64_t off = fblock * block_size;
        r = ext4_block_writebytes(fs->bdev, off, buf, size);
        if (r != EOK)
            return r;
    }

    ext4_inode_set_size(inode_ref._ref.inode, size);
    inode_ref._ref.dirty = true;

    return EOK;
}

static int
ext_symlink(vnode_t *dvp, char *name, char *link)
{
    ext_debug("symlink\n");
    struct ext4_fs *fs = (struct ext4_fs *)dvp->v_mount->m_data;
    auto_write_back wb(fs);
    uint32_t inode_no_created;
    int r = luca_dir_link(dvp, name, EXT4_DE_SYMLINK, nullptr, &inode_no_created);
    if (r == EOK ) {
       return ext_fsymlink_set(fs, inode_no_created, link, strlen(link));
    }
    return r;
}

#define luca_seek        ((vnop_seek_t)vop_nullop)
#define luca_inactive    ((vnop_inactive_t)vop_nullop)


struct vnops luca_vnops = {
    luca_open,       /* open */
    luca_close,      /* close */
    luca_read,       /* read */
    luca_wirte,      /* write */
    luca_seek,       /* seek */
    luca_ioctl,      /* ioctl */
    luca_fsync,      /* fsync */
    luca_readdir,    /* readdir */
    luca_lookup,     /* lookup */
    luca_create,     /* create */
    luca_remove,     /* remove */
    luca_rename,     /* rename */
    luca_mkdir,      /* mkdir */
    luca_rmdir,      /* rmdir */
    ext_getattr,    /* getattr */
    ext_setattr,    /* setattr */
    luca_inactive,   /* inactive */
    luca_truncate,   /* truncate */
    luca_link,       /* link */
    luca_arc,        /* arc */
    luca_fallocate,  /* fallocate */
    luca_readlink,   /* read link */
    luca_symlink,    /* symbolic link */
};


