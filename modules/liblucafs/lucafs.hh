#ifndef LUCAFS_HH
#define LUCAFS_HH


#include <ext4_blockdev.h>
#include <ext4_debug.h>
#include <ext4_fs.h>
#include <ext4_super.h>

typedef struct ext4_fs luca_fs_t;

typedef struct ext4_bcache luca_bcache_t;

typedef struct ext4_blockdev luca_blockdev_t;

typedef struct ext4_inode_ref luca_inode_ref_t;

typedef struct ext4_sblock luca_sblock_t;


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

#endif // LUCAFS_HH